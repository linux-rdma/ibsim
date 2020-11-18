/*
 * Copyright (c) 2004-2008 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2009 HNR Consulting. All rights reserved.
 * Copyright (c) 2011 Mellanox Technologies LTD. All rights reserved.
 *
 * This file is part of ibsim.
 *
 * ibsim is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <limits.h>

#include <ibsim.h>
#include "sim.h"

#undef DEBUG
#define DEBUG	if (simverb > 1 || ibdebug) IBWARN
#define VERB	if (simverb || ibdebug) IBWARN

#define ERR_METHOD_UNSUPPORTED	(2 << 2)
#define ERR_ATTR_UNSUPPORTED	(3 << 2)
#define ERR_BAD_PARAM		(7 << 2)

typedef int (Smpfn) (Port * port, unsigned op, uint32_t mod, uint8_t * data);
typedef int (EncodeTrapfn) (Port * port, char *data);

static Smpfn do_nodeinfo, do_nodedesc, do_switchinfo, do_portinfo,
    do_linearforwtbl, do_multicastforwtbl, do_portcounters, do_extcounters,
    do_rcv_error_details, do_xmit_discard_details, do_op_rcv_counters,
    do_flow_ctl_counters, do_vl_op_packets, do_vl_op_data,
    do_vl_xmit_flow_ctl_update_errors, do_vl_xmit_wait_counters, do_pkeytbl,
    do_sl2vl, do_vlarb, do_guidinfo, do_cpi, do_extportinfo;

static EncodeTrapfn encode_trap128;
static EncodeTrapfn encode_trap144;


#define ATTRIBUTES_NUMBER 20

typedef struct {
	unsigned attr_id;
	Smpfn * handler;
} attr_handler;

typedef struct {
	unsigned class_id;
	attr_handler handlers[ATTRIBUTES_NUMBER];
} class_handler;

static class_handler smp_handlers_array[] = {
	{IB_SMI_CLASS, {
		{IB_ATTR_NODE_DESC, do_nodedesc},
		{IB_ATTR_NODE_INFO, do_nodeinfo},
		{IB_ATTR_SWITCH_INFO, do_switchinfo},
		{IB_ATTR_PORT_INFO, do_portinfo},
		{IB_ATTR_LINEARFORWTBL, do_linearforwtbl},
		{IB_ATTR_MULTICASTFORWTBL, do_multicastforwtbl},
		{IB_ATTR_PKEY_TBL, do_pkeytbl},
		{IB_ATTR_SLVL_TABLE, do_sl2vl},
		{IB_ATTR_VL_ARBITRATION, do_vlarb},
		{IB_ATTR_GUID_INFO, do_guidinfo},
		{IB_ATTR_SMINFO, NULL},
		{IB_ATTR_MLNX_EXT_PORT_INFO, do_extportinfo},
		{UINT_MAX, NULL}
		}
	},
	{IB_SMI_DIRECT_CLASS, {
		{IB_ATTR_NODE_DESC, do_nodedesc},
		{IB_ATTR_NODE_INFO, do_nodeinfo},
		{IB_ATTR_SWITCH_INFO, do_switchinfo},
		{IB_ATTR_PORT_INFO, do_portinfo},
		{IB_ATTR_LINEARFORWTBL, do_linearforwtbl},
		{IB_ATTR_MULTICASTFORWTBL, do_multicastforwtbl},
		{IB_ATTR_PKEY_TBL, do_pkeytbl},
		{IB_ATTR_SLVL_TABLE, do_sl2vl},
		{IB_ATTR_VL_ARBITRATION, do_vlarb},
		{IB_ATTR_GUID_INFO, do_guidinfo},
		{IB_ATTR_SMINFO, NULL},
		{IB_ATTR_MLNX_EXT_PORT_INFO, do_extportinfo},
		{UINT_MAX, NULL}
		}
	},
	{IB_PERFORMANCE_CLASS, {
		{CLASS_PORT_INFO, do_cpi},
		{IB_GSI_PORT_SAMPLES_CONTROL, NULL},
		{IB_GSI_PORT_SAMPLES_RESULT, NULL},
		{IB_GSI_PORT_COUNTERS, do_portcounters},
		{IB_GSI_PORT_COUNTERS_EXT, do_extcounters},
		{IB_GSI_PORT_RCV_ERROR_DETAILS, do_rcv_error_details},
		{IB_GSI_PORT_XMIT_DISCARD_DETAILS, do_xmit_discard_details},
		{IB_GSI_PORT_PORT_OP_RCV_COUNTERS, do_op_rcv_counters},
		{IB_GSI_PORT_PORT_FLOW_CTL_COUNTERS, do_flow_ctl_counters},
		{IB_GSI_PORT_PORT_VL_OP_PACKETS, do_vl_op_packets},
		{IB_GSI_PORT_PORT_VL_OP_DATA, do_vl_op_data},
		{IB_GSI_PORT_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS, do_vl_xmit_flow_ctl_update_errors},
		{IB_GSI_PORT_PORT_VL_XMIT_WAIT_COUNTERS, do_vl_xmit_wait_counters},
		{UINT_MAX, NULL}
		}
	}
	,
	{UINT_MAX, {}}
};

static Smpfn * get_smp_handler(unsigned class_id, unsigned attr_id)
{
	int i, j;

	for (i = 0; smp_handlers_array[i].class_id != UINT_MAX; i++ ) {

		if (smp_handlers_array[i].class_id != class_id)
			continue;

		for (j = 0; smp_handlers_array[i].handlers[j].attr_id != UINT_MAX; j++) {
			if (smp_handlers_array[i].handlers[j].attr_id != attr_id)
				continue;

			return smp_handlers_array[i].handlers[j].handler;
		}

	}
	return NULL;
}

static EncodeTrapfn *encodetrap[] = {
	[TRAP_128] = encode_trap128,
	[TRAP_144] = encode_trap144,

	[TRAP_NUM_LAST] = NULL,
};

extern Node *nodes;
extern Switch *switchs;
extern Port *ports;
extern Port **lids;
extern int netnodes, netports, netswitches;
extern int maxlinearcap;

typedef void (*pc_reset_function)(Portcounters * pc, unsigned mask);
typedef void (*pc_get_function)(Portcounters * pc, uint8_t * data);
typedef void (*pc_sum_function)(Portcounters * totals, Portcounters * pc);

static uint64_t update_trid(uint8_t *mad, unsigned response, Client *cl)
{
	uint64_t trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
	if (!response) {
		trid = (trid&0xffffffffffffULL)|(((uint64_t)cl->id)<<48);
		mad_set_field64(mad, 0, IB_MAD_TRID_F, trid);
	}
	return trid;
}

static int decode_sim_MAD(Client * cl, struct sim_request * r, ib_rpc_t * rpc,
			  ib_dr_path_t * path, void *data)
{
	void *buf = r->mad;
	int response;

	// first word
	response = mad_get_field(buf, 0, IB_MAD_RESPONSE_F);
	if (mad_get_field(buf, 0, IB_MAD_CLASSVER_F) > 2 ||	// sma ver is 1, sa is 2
	    mad_get_field(buf, 0, IB_MAD_BASEVER_F) != 1) {
		IBWARN("bad smp headers (1st word)");
		return -1;
	}
	rpc->method = mad_get_field(buf, 0, IB_MAD_METHOD_F);
	rpc->mgtclass = mad_get_field(buf, 0, IB_MAD_MGMTCLASS_F);

	// second word:
	if (rpc->mgtclass == 0x81) {	// direct route
		if (mad_get_field(buf, 0, IB_DRSMP_HOPPTR_F) != 0x0 ||
		    mad_get_field(buf, 0, IB_DRSMP_DIRECTION_F) != response) {
			IBWARN("bad direct smp headers (2nd word)");
			return -1;
		}
		path->cnt = mad_get_field(buf, 0, IB_DRSMP_HOPCNT_F);
	} else if (r->slid == 0)
		r->slid = htons(cl->port->lid);

	// words 3,4,5,6
	rpc->trid = update_trid(buf, response, cl);

	rpc->attr.id = mad_get_field(buf, 0, IB_MAD_ATTRID_F);
	rpc->attr.mod = mad_get_field(buf, 0, IB_MAD_ATTRMOD_F);

	// words 7,8
//      mad_get_field(buf, 0, SMP_MKEY, rpc->mkey >> 32);
//      mad_get_field(buf, 4, SMP_MKEY, rpc->mkey & 0xffffffff);

	if (rpc->mgtclass == 0x81) {	// direct route
		// word 9
		if (mad_get_field(buf, 0, IB_DRSMP_DRDLID_F) != 0xffff ||
		    mad_get_field(buf, 0, IB_DRSMP_DRSLID_F) != 0xffff) {
			IBWARN("dr[ds]lids are used (not supported)");
			return -1;
		}
		// bytes 128 - 256
		if (!response)
			mad_get_array(buf, 0, IB_DRSMP_PATH_F, path->p);
		else
			mad_get_array(buf, 0, IB_DRSMP_RPATH_F, path->p);
	}

	if (rpc->mgtclass == 0x4 || rpc->mgtclass == 0x1
	    || rpc->mgtclass == 0x81) {
		rpc->dataoffs = 64;
		rpc->datasz = 64;
	}
	if (data)
		memcpy(data, (char *)buf + rpc->dataoffs, rpc->datasz);

	return response;
}

static int forward_MAD(void *buf, ib_rpc_t * rpc, ib_dr_path_t * path)
{
	if (rpc->mgtclass == 0x81) {	// direct route
		// word 9

		// bytes 128 - 256
		mad_set_array(buf, 0, IB_DRSMP_RPATH_F, path->p);
	}
	return 0;
}

static int reply_MAD(void *buf, ib_rpc_t * rpc, ib_dr_path_t * path,
		     int status, void *data)
{
	// first word
	mad_set_field(buf, 0, IB_MAD_RESPONSE_F, 1);
	mad_set_field(buf, 0, IB_MAD_METHOD_F, 0x81);	// SUBN_GETRESP

	// second word:
	if (rpc->mgtclass == 0x81) {	// direct route
		mad_set_field(buf, 0, IB_DRSMP_STATUS_F, status);
		mad_set_field(buf, 0, IB_DRSMP_DIRECTION_F, 1);
	} else
		mad_set_field(buf, 0, IB_MAD_STATUS_F, status);

	// words 3,4,5,6

	// words 7,8

	if (rpc->mgtclass == 0x81) {	// direct route
		// word 9

		// bytes 128 - 256
		mad_set_array(buf, 0, IB_DRSMP_RPATH_F, path->p);
//              memcpy(buf+128+64, buf+128, 64);        // copy dest path -> return path
	}

	if (data)
		memcpy((char *)buf + rpc->dataoffs, data, rpc->datasz);

	return 0;
}

static int do_cpi(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	Node *node = port->node;
	int status = 0;

	if (op != IB_MAD_METHOD_GET)
		status = ERR_METHOD_UNSUPPORTED;
	memset(data, 0, IB_SMP_DATA_SIZE);
	mad_set_field(data, 0, IB_CPI_BASEVER_F, 1);
	mad_set_field(data, 0, IB_CPI_CLASSVER_F, 1);
	if (node->type != SWITCH_NODE)
		mad_set_field(data, 0, IB_CPI_CAPMASK_F, IB_PM_EXT_WIDTH_SUPPORTED|IB_PM_PC_XMIT_WAIT_SUP);
	else
		mad_set_field(data, 0, IB_CPI_CAPMASK_F, IB_PM_ALL_PORT_SELECT|IB_PM_EXT_WIDTH_SUPPORTED|IB_PM_PC_XMIT_WAIT_SUP);

	mad_set_field(data, 0, IB_CPI_RESP_TIME_VALUE_F, 0x12);
	return status;
}

static int do_nodedesc(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	int status = 0;

	if (op != IB_MAD_METHOD_GET)
		status = ERR_METHOD_UNSUPPORTED;
	memcpy(data, port->node->nodedesc, IB_SMP_DATA_SIZE);

	return status;
}

static int do_nodeinfo(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	Node *node = port->node;
	int status = 0;
	uint64_t portguid = node->nodeguid + port->portnum;

	if (op != IB_MAD_METHOD_GET)
		status = ERR_METHOD_UNSUPPORTED;
	memcpy(data, node->nodeinfo, IB_SMP_DATA_SIZE);

	mad_set_field(data, 0, IB_NODE_LOCAL_PORT_F, port->portnum);
	if (node->type == SWITCH_NODE)
		mad_encode_field(data, IB_NODE_PORT_GUID_F, &node->nodeguid);
	else
		mad_encode_field(data, IB_NODE_PORT_GUID_F, &portguid);

	return status;
}

static int do_switchinfo(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	Switch *sw = port->node->sw;

	if (!sw)		// not a Switch?
		return ERR_ATTR_UNSUPPORTED;

	if (op == IB_MAD_METHOD_SET) {
		if (mad_get_field(data, 0, IB_SW_STATE_CHANGE_F))
			sw->portchange = 0;
		sw->linearFDBtop =
		    mad_get_field(data, 0, IB_SW_LINEAR_FDB_TOP_F);
		sw->lifetime = mad_get_field(data, 0, IB_SW_LIFE_TIME_F);
	}

	memcpy(data, sw->switchinfo, IB_SMP_DATA_SIZE);

	mad_set_field(data, 0, IB_SW_STATE_CHANGE_F, sw->portchange);
	mad_set_field(data, 0, IB_SW_LINEAR_FDB_TOP_F, sw->linearFDBtop);
	mad_set_field(data, 0, IB_SW_LIFE_TIME_F, sw->lifetime);

	return 0;
}

static int do_pkeytbl(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	unsigned block = mod & 0xffff;
	unsigned port_num = mod >> 16;
	unsigned pkey_size, size;
	uint16_t *pkeys;

	if (port->node->sw && !(port = node_get_port(port->node, port_num)))
		return ERR_BAD_PARAM;

	pkey_size = (port->node->sw && port_num) ?
	    mad_get_field(port->node->sw->switchinfo, 0,
			  IB_SW_PARTITION_ENFORCE_CAP_F) :
	    mad_get_field(port->node->nodeinfo, 0, IB_NODE_PARTITION_CAP_F);

	if (block * 32 >= pkey_size)
		return ERR_BAD_PARAM;

	pkeys = port->pkey_tbl + block * 32;
	size = pkey_size - block * 32;
	if (size > 32)
		size = 32;

	if (op == IB_MAD_METHOD_SET) {
		memcpy(pkeys, data, size * sizeof(uint16_t));
	} else {
		memset(data, 0, 32 * sizeof(uint16_t));
		memcpy(data, pkeys, size * sizeof(uint16_t));
	}

	return 0;
}

static int do_sl2vl(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	uint8_t *sl2vl;
	unsigned n;

	if (port->node->sw) {
		n = (mod >> 8) & 0xff;
		port = node_get_port(port->node, n);
		n = mod & 0xff;
		if (!port || !node_get_port(port->node, n))
			return ERR_BAD_PARAM;
	} else
		n = 0;

	sl2vl = port->sl2vl + 8 * n;

	if (op == IB_MAD_METHOD_SET)
		memcpy(sl2vl, data, 8);
	else
		memcpy(data, sl2vl, 8);

	return 0;
}

static int do_vlarb(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	struct vlarb *vlarb;
	unsigned size, n;

	if (port->node->sw) {
		n = mod & 0xffff;
		port = node_get_port(port->node, n);
		if (!port)
			return ERR_BAD_PARAM;
	}

	n = (mod >> 16) - 1;
	if (n > 3)
		return ERR_BAD_PARAM;

	size = mad_get_field(port->portinfo, 0,
			     (n / 2) ? IB_PORT_VL_ARBITRATION_HIGH_CAP_F :
			     IB_PORT_VL_ARBITRATION_LOW_CAP_F);
	if (!size || n % 2 > size / 32)
		return ERR_BAD_PARAM;

	vlarb = (n / 2) ? port->vlarb_high : port->vlarb_low;
	vlarb += (n % 2) * 32;

	if (size > 32 && n % 2)
		size %= 32;

	size *= sizeof(*vlarb);

	if (op == IB_MAD_METHOD_SET)
		memcpy(vlarb, data, size);
	else {
		memset(data, 0, IB_SMP_DATA_SIZE);
		memcpy(data, vlarb, size);
	}

	return 0;
}

static int do_guidinfo(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	Node *node = port->node;
	int status = 0;
	uint64_t portguid = node->nodeguid + port->portnum;

	if (op != IB_MAD_METHOD_GET)    // only get currently supported (non compliant)
		status = ERR_METHOD_UNSUPPORTED;

	memset(data, 0, IB_SMP_DATA_SIZE);
	if (mod == 0) {
		if (node->type == SWITCH_NODE)
			mad_encode_field(data, IB_GUID_GUID0_F, &node->nodeguid);
		else
			mad_encode_field(data, IB_GUID_GUID0_F, &portguid);
	}

	return status;
}

static int
do_portinfo(Port * port, unsigned op, uint32_t portnum, uint8_t * data)
{
	Node *node = port->node;
	Port *p, *rp = NULL;
	int r, newlid;
	int speed, espeed, width;

	portnum &= 0x7fffffff;
	if (portnum > node->numports)
		return ERR_BAD_PARAM;

	if (portnum == 0 && node->type != SWITCH_NODE)	//according to ibspec 14.2.5.6
		portnum = port->portnum;

	p = node_get_port(node, portnum);
	DEBUG("in node %" PRIx64 " port %" PRIx64 ": port %" PRIx64 " (%d(%d))",
	      node->nodeguid, port->portguid, p->portguid, p->portnum, portnum);

	if (op == IB_MAD_METHOD_SET) {
		unsigned val;
		if (node->type != SWITCH_NODE && port->portnum != p->portnum)
			return ERR_BAD_PARAM;	// on HCA or rtr can't "set" on other port
		newlid = mad_get_field(data, 0, IB_PORT_LID_F);
		if (newlid != p->lid) {
			if (p->lid > 0 && p->lid < maxlinearcap
			    && lids[p->lid] == p)
				lids[p->lid] = NULL;
		}
		p->lid = newlid;
		p->smlid = mad_get_field(data, 0, IB_PORT_SMLID_F);
              //p->linkwidth = mad_get_field(data, 0, IB_PORT_LINK_WIDTH_ENABLED_F); // ignored
		p->lmc = mad_get_field(data, 0, IB_PORT_LMC_F);
		p->hoqlife = mad_get_field(data, 0, IB_PORT_HOQ_LIFE_F);
		if ((r = mad_get_field(data, 0, IB_PORT_PHYS_STATE_F)))
			p->physstate = r;
		r = mad_get_field(data, 0, IB_PORT_STATE_F);
		if (r > 0 && p->remotenode &&
		    (rp = node_get_port(p->remotenode, p->remoteport))) {
			if (r == 1) {	/* DOWN */
				p->state = 2;	/* set to INIT */
				/*
				 * If the state is changed to initialize (from down or not)
				 * we should force remote state to same state.
				 * We also should set portchange on remote node.
				 * Note that the local portchange (if switch) is not changed
				 * according to the spec (p. 731) - no portchange on subnset.
				 */
				rp->state = 2;
				if (p->remotenode->type == SWITCH_NODE)
					p->remotenode->sw->portchange = 1;
			} else if (r > 2) {
				if (abs(rp->state - r) <= 1
				    && abs(p->state - r) == 1)
					p->state = r;	/* set to new state */
				else
					return ERR_BAD_PARAM;
			}
		} else if (r > 1)
			return ERR_BAD_PARAM;	/* trying to change the state of DOWN port */

		if (p->state == 4) {
			if (p->lid > 0 && p->lid < maxlinearcap
			    && lids[p->lid] != p && lids[p->lid])
				IBWARN
				    ("Port %s:%d overwrite lid table entry for lid %u (was %s:%d)",
				     node->nodeid, p->portnum, p->lid,
				     lids[p->lid]->node->nodeid,
				     lids[p->lid]->portnum);
			lids[p->lid] = p;
		}
		val = mad_get_field(data, 0, IB_PORT_OPER_VLS_F);
		if (val > mad_get_field(data, 0, IB_PORT_VL_CAP_F))
			return ERR_BAD_PARAM;
		p->op_vls = val;
		p->subnet_prefix = mad_get_field64(data, 0, IB_PORT_GID_PREFIX_F);

		if (!rp && p->remotenode)
			rp = node_get_port(p->remotenode, p->remoteport);
		else
			goto update_port;

		speed = mad_get_field(data, 0, IB_PORT_LINK_SPEED_ENABLED_F);
		switch (speed) {
		case LINKSPEED_SDR:
			p->linkspeed = LINKSPEED_SDR;
			rp->linkspeed = LINKSPEED_SDR;
			break;
		case LINKSPEED_SDR_DDR:
			p->linkspeed = LINKSPEED_DDR;
			rp->linkspeed = LINKSPEED_DDR;
			break;
		case LINKSPEED_SDR_QDR:
		case LINKSPEED_SDR_DDR_QDR:
			p->linkspeed = LINKSPEED_QDR;
			rp->linkspeed = LINKSPEED_QDR;
			break;
		default:
			speed = 0;
		}

		if (speed && speed != p->linkspeedena)
			p->linkspeedena = speed;
		else
			speed = 0;

		espeed = mad_get_field(data, 0, IB_PORT_LINK_SPEED_EXT_ENABLED_F);
		switch (espeed) {
		case LINKSPEEDEXT_FDR:
			p->linkspeedext = LINKSPEEDEXT_FDR;
			rp->linkspeedext = LINKSPEEDEXT_FDR;
			break;
		case LINKSPEEDEXT_EDR:
		case LINKSPEEDEXT_FDR_EDR:
			p->linkspeedext = LINKSPEEDEXT_EDR;
			rp->linkspeedext = LINKSPEEDEXT_EDR;
			break;
		case LINKSPEEDEXT_HDR:
		case LINKSPEEDEXT_HDR_FDR:
		case LINKSPEEDEXT_HDR_EDR:
		case LINKSPEEDEXT_HDR_EDR_FDR:
			p->linkspeedext = LINKSPEEDEXT_HDR;
			rp->linkspeedext = LINKSPEEDEXT_HDR;
			break;

		case LINKSPEEDEXT_NDR:
		case LINKSPEEDEXT_NDR_FDR:
		case LINKSPEEDEXT_NDR_EDR:
		case LINKSPEEDEXT_NDR_FDR_EDR:
		case LINKSPEEDEXT_NDR_HDR:
		case LINKSPEEDEXT_NDR_HDR_FDR:
		case LINKSPEEDEXT_NDR_HDR_EDR:
		case LINKSPEEDEXT_NDR_HDR_EDR_FDR:
			p->linkspeedext = LINKSPEEDEXT_NDR;
			rp->linkspeedext = LINKSPEEDEXT_NDR;
			break;

		default:
			espeed = 0;
		}

		if (espeed && espeed != p->linkspeedextena)
			p->linkspeedextena = espeed;
		else
			espeed = 0;

		width = mad_get_field(data, 0, IB_PORT_LINK_WIDTH_ENABLED_F);
		switch (width) {
		case LINKWIDTH_1x:
			p->linkwidth = LINKWIDTH_1x;
			rp->linkwidth = LINKWIDTH_1x;
			break;
		case LINKWIDTH_4x:
		case LINKWIDTH_1x_4x:
		case LINKWIDTH_2x_4x:
		case LINKWIDTH_1x_2x_4x:
			p->linkwidth = LINKWIDTH_4x;
			rp->linkwidth = LINKWIDTH_4x;
			break;
		case LINKWIDTH_8x:
		case LINKWIDTH_1x_8x:
		case LINKWIDTH_4x_8x:
		case LINKWIDTH_1x_4x_8x:
		case LINKWIDTH_2x_8x:
		case LINKWIDTH_1x_2x_8x:
		case LINKWIDTH_2x_4x_8x:
		case LINKWIDTH_1x_2x_4x_8x:
			p->linkwidth = LINKWIDTH_8x;
			rp->linkwidth = LINKWIDTH_8x;
			break;
		case LINKWIDTH_12x:
		case LINKWIDTH_1x_12x:
		case LINKWIDTH_4x_12x:
		case LINKWIDTH_1x_4x_12x:
		case LINKWIDTH_8x_12x:
		case LINKWIDTH_1x_8x_12x:
		case LINKWIDTH_4x_8x_12x:
		case LINKWIDTH_1x_4x_8x_12x:
		case LINKWIDTH_2x_12x:
		case LINKWIDTH_1x_2x_12x:
		case LINKWIDTH_2x_4x_12x:
		case LINKWIDTH_1x_2x_4x_12x:
		case LINKWIDTH_2x_8x_12x:
		case LINKWIDTH_1x_2x_8x_12x:
		case LINKWIDTH_2x_4x_8x_12x:
		case LINKWIDTH_1x_2x_4x_8x_12x:
			p->linkwidth = LINKWIDTH_12x;
			rp->linkwidth = LINKWIDTH_12x;
			break;
		case LINKWIDTH_2x:
		case LINKWIDTH_1x_2x:
			p->linkwidth = LINKWIDTH_2x;
			rp->linkwidth = LINKWIDTH_2x;
			break;
		default:
			width = 0;
		}

		if (width && width != p->linkwidthena)
			p->linkwidthena = width;
		else
			width = 0;

		if (speed || espeed || width)
			send_trap(port, TRAP_144);
	}

update_port:
	update_portinfo(p);
	memcpy(data, p->portinfo, IB_SMP_DATA_SIZE);
	mad_set_field(data, 0, IB_PORT_LOCAL_PORT_F, port->portnum);

	return 0;
}

static int
do_extportinfo(Port * port, unsigned op, uint32_t portnum, uint8_t * data)
{
	Node *node = port->node;
	Port *p;

	if (portnum > node->numports)
		return ERR_BAD_PARAM;

	if (portnum == 0 && node->type != SWITCH_NODE)  //according to ibspec 14.2.5.6
		portnum = port->portnum;

	p = node_get_port(node, portnum);
	DEBUG("in node %" PRIx64 " port %" PRIx64 ": port %" PRIx64 " (%d(%d))",
	      node->nodeguid, port->portguid, p->portguid, p->portnum, portnum);

	if (op == IB_MAD_METHOD_SET) {
		memcpy(p->extportinfo, data, IB_SMP_DATA_SIZE);
	} else
		memcpy(data, p->extportinfo, IB_SMP_DATA_SIZE);

	return 0;
}
static int do_linearforwtbl(Port * port, unsigned op, uint32_t mod,
			    uint8_t * data)
{
	Switch *sw = port->node->sw;

	if (!sw)		// not a Switch?
		return ERR_ATTR_UNSUPPORTED;

	if (mod > 767)
		return ERR_BAD_PARAM;

	if (op == IB_MAD_METHOD_SET)
		mad_get_array(data, 0, IB_LINEAR_FORW_TBL_F,
			      sw->fdb + mod * 64);

	mad_set_array(data, 0, IB_LINEAR_FORW_TBL_F, sw->fdb + mod * 64);

	return 0;
}

static int do_multicastforwtbl(Port * port, unsigned op, uint32_t mod,
			       uint8_t * data)
{
	int numPortMsk = mod >> 28;	// high order 4 bits
	int numBlock32 = mod & 0x1ff;	// low order 9 bits
	int blockposition;

	Switch *sw = port->node->sw;
	if (!sw)		// not a Switch?
		return ERR_ATTR_UNSUPPORTED;

	VERB("requested : Block32 %d PortMask %d", numBlock32, numPortMsk);
	if (numBlock32 > LASTBLOCK32 || numPortMsk >= sw->numportmask) {
		int8_t zeroblock[64] = { 0 };
		mad_set_array(data, 0, IB_MULTICAST_FORW_TBL_F, zeroblock);
		return 0;
	}

	blockposition = (numBlock32 * sw->numportmask + numPortMsk) * 64;
	if (op == IB_MAD_METHOD_SET)
		mad_get_array(data, 0, IB_MULTICAST_FORW_TBL_F,
			      sw->mfdb + blockposition);
	mad_set_array(data, 0, IB_MULTICAST_FORW_TBL_F,
		      sw->mfdb + blockposition);
	return 0;
}

static void pc_reset(Portcounters * pc, unsigned mask)
{
	if (mask & GS_PERF_ERR_SYM_MASK)
		pc->errs_sym = 0;
	if (mask & GS_PERF_LINK_RECOVERS_MASK)
		pc->linkrecovers = 0;
	if (mask & GS_PERF_LINK_DOWNED_MASK)
		pc->linkdowned = 0;
	if (mask & GS_PERF_ERR_RCV_MASK)
		pc->errs_rcv = 0;
	if (mask & GS_PERF_ERR_PHYSRCV_MASK)
		pc->errs_remphysrcv = 0;
	if (mask & GS_PERF_ERR_SWITCH_REL_MASK)
		pc->errs_rcvswitchrelay = 0;
	if (mask & GS_PERF_XMT_DISCARDS_MASK)
		pc->xmitdiscards = 0;
	if (mask & GS_PERF_ERR_XMTCONSTR_MASK)
		pc->errs_xmtconstraint = 0;
	if (mask & GS_PERF_ERR_RCVCONSTR_MASK)
		pc->errs_rcvconstraint = 0;
	if (mask & GS_PERF_ERR_LOCALINTEG_MASK)
		pc->errs_localinteg = 0;
	if (mask & GS_PERF_ERR_EXCESS_OVR_MASK)
		pc->errs_excessbufovrrun = 0;
	if (mask & GS_PERF_VL15_DROPPED_MASK)
		pc->vl15dropped = 0;
	if (mask & GS_PERF_XMT_BYTES_MASK)
		pc->flow_xmt_bytes = 0;
	if (mask & GS_PERF_RCV_BYTES_MASK)
		pc->flow_rcv_bytes = 0;
	if (mask & GS_PERF_XMT_PKTS_MASK)
		pc->flow_xmt_pkts = 0;
	if (mask & GS_PERF_RCV_PKTS_MASK)
		pc->flow_rcv_pkts = 0;
	if (mask & GS_PERF_XMT_WAIT_MASK)
		pc->xmt_wait = 0;
}

static inline uint32_t addval(uint32_t val, uint32_t delta, uint32_t max)
{
	uint32_t newval = val + delta;

	return (newval > max || newval < val) ? max : newval;
}

#define ADDVAL64(val, add) { uint64_t new = val + add; \
		val = new < val ? 0xffffffffffffffffULL : new ; }

static void pc_add_error_xmitdiscards(Port * port)
{
	Portcounters *pc = &(port->portcounters);

	pc->xmitdiscards =
	    addval(pc->xmitdiscards, 1, GS_PERF_XMT_DISCARDS_LIMIT);
}

static void pc_add_error_rcvswitchrelay(Port * port)
{
	Portcounters *pc = &(port->portcounters);

	pc->errs_rcvswitchrelay =
	    addval(pc->errs_rcvswitchrelay, 1, GS_PERF_ERR_SWITCH_REL_LIMIT);
}

static void pc_add_error_errs_rcv(Port * port)
{
	Portcounters *pc = &(port->portcounters);

	pc->errs_rcv = addval(pc->errs_rcv, 1, GS_PERF_ERR_RCV_LIMIT);
}

static int pc_updated(Port ** srcport, Port * destport)
{
	Portcounters *srcpc = &((*srcport)->portcounters);
	Portcounters *destpc = &(destport->portcounters);
	uint32_t madsize_div_4 = 72;	//real data divided by 4

	if (*srcport != destport) {
		//PKT got out of port ..
		srcpc->flow_xmt_pkts =
		    addval(srcpc->flow_xmt_pkts, 1, GS_PERF_XMT_PKTS_LIMIT);
		srcpc->flow_xmt_bytes =
		    addval(srcpc->flow_xmt_bytes, madsize_div_4,
			   GS_PERF_XMT_BYTES_LIMIT);
		ADDVAL64(srcpc->ext_xmit_data, madsize_div_4);
		ADDVAL64(srcpc->ext_xmit_pkts, 1);

		if (destport->errrate &&
		    !destport->errattr &&
		    (random() % 100) < destport->errrate) {
			pc_add_error_errs_rcv(destport);
			VERB("drop pkt due error rate %d", destport->errrate);
			return 0;
		}
		//PKT got into the port ..
		destpc->flow_rcv_pkts =
		    addval(destpc->flow_rcv_pkts, 1, GS_PERF_RCV_PKTS_LIMIT);
		destpc->flow_rcv_bytes =
		    addval(destpc->flow_rcv_bytes, madsize_div_4,
			   GS_PERF_RCV_BYTES_LIMIT);
		ADDVAL64(destpc->ext_recv_data, madsize_div_4);
		ADDVAL64(destpc->ext_recv_pkts, 1);

		*srcport = destport;
	}
	return 1;
}

static void pc_sum(Portcounters * totals, Portcounters * pc)
{
	totals->xmt_wait =
	    addval(totals->xmt_wait, pc->xmt_wait,
		   GS_PERF_XMT_WAIT_LIMIT);
	totals->flow_xmt_pkts =
	    addval(totals->flow_xmt_pkts, pc->flow_xmt_pkts,
		   GS_PERF_XMT_PKTS_LIMIT);
	totals->flow_xmt_bytes =
	    addval(totals->flow_xmt_bytes, pc->flow_xmt_bytes,
		   GS_PERF_XMT_BYTES_LIMIT);
	totals->flow_rcv_pkts =
	    addval(totals->flow_rcv_pkts, pc->flow_rcv_pkts,
		   GS_PERF_RCV_PKTS_LIMIT);
	totals->flow_rcv_bytes =
	    addval(totals->flow_rcv_bytes, pc->flow_rcv_bytes,
		   GS_PERF_RCV_BYTES_LIMIT);
	totals->xmitdiscards =
	    addval(totals->xmitdiscards, pc->xmitdiscards,
		   GS_PERF_ERR_XMTCONSTR_LIMIT);
	totals->vl15dropped =
	    addval(totals->vl15dropped, pc->vl15dropped,
		   GS_PERF_VL15_DROPPED_LIMIT);
	totals->linkrecovers =
	    addval(totals->linkrecovers, pc->linkrecovers,
		   GS_PERF_LINK_RECOVERS_LIMIT);
	totals->linkdowned =
	    addval(totals->linkdowned, pc->linkdowned,
		   GS_PERF_LINK_DOWNED_LIMIT);
	totals->errs_rcv =
	    addval(totals->errs_rcv, pc->errs_rcv, GS_PERF_ERR_RCV_LIMIT);
	totals->errs_sym =
	    addval(totals->errs_sym, pc->errs_sym, GS_PERF_ERR_SYM_LIMIT);
	totals->errs_localinteg =
	    addval(totals->errs_localinteg, pc->errs_localinteg,
		   GS_PERF_ERR_LOCALINTEG_LIMIT);
	totals->errs_remphysrcv =
	    addval(totals->errs_remphysrcv, pc->errs_remphysrcv,
		   GS_PERF_ERR_PHYSRCV_LIMIT);
	totals->errs_xmtconstraint =
	    addval(totals->errs_xmtconstraint, pc->errs_xmtconstraint,
		   GS_PERF_ERR_XMTCONSTR_LIMIT);
	totals->errs_rcvconstraint =
	    addval(totals->errs_rcvconstraint, pc->errs_rcvconstraint,
		   GS_PERF_ERR_RCVCONSTR_LIMIT);
	totals->errs_rcvswitchrelay =
	    addval(totals->errs_rcvswitchrelay, pc->errs_rcvswitchrelay,
		   GS_PERF_ERR_SWITCH_REL_LIMIT);
	totals->errs_excessbufovrrun =
	    addval(totals->errs_excessbufovrrun, pc->errs_excessbufovrrun,
		   GS_PERF_ERR_EXCESS_OVR_LIMIT);
}

static void pc_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_XMT_WAIT_F, pc->xmt_wait);
	mad_set_field(data, 0, IB_PC_XMT_PKTS_F, pc->flow_xmt_pkts);
	mad_set_field(data, 0, IB_PC_XMT_BYTES_F, pc->flow_xmt_bytes);
	mad_set_field(data, 0, IB_PC_RCV_PKTS_F, pc->flow_rcv_pkts);
	mad_set_field(data, 0, IB_PC_RCV_BYTES_F, pc->flow_rcv_bytes);
	mad_set_field(data, 0, IB_PC_XMT_DISCARDS_F, pc->xmitdiscards);
	mad_set_field(data, 0, IB_PC_VL15_DROPPED_F, pc->vl15dropped);
	mad_set_field(data, 0, IB_PC_LINK_RECOVERS_F, pc->linkrecovers);
	mad_set_field(data, 0, IB_PC_LINK_DOWNED_F, pc->linkdowned);
	mad_set_field(data, 0, IB_PC_ERR_RCV_F, pc->errs_rcv);
	mad_set_field(data, 0, IB_PC_ERR_SYM_F, pc->errs_sym);
	mad_set_field(data, 0, IB_PC_ERR_LOCALINTEG_F, pc->errs_localinteg);
	mad_set_field(data, 0, IB_PC_ERR_PHYSRCV_F, pc->errs_remphysrcv);
	mad_set_field(data, 0, IB_PC_ERR_XMTCONSTR_F, pc->errs_xmtconstraint);
	mad_set_field(data, 0, IB_PC_ERR_RCVCONSTR_F, pc->errs_rcvconstraint);
	mad_set_field(data, 0, IB_PC_ERR_SWITCH_REL_F, pc->errs_rcvswitchrelay);
	mad_set_field(data, 0, IB_PC_ERR_EXCESS_OVR_F,
		      pc->errs_excessbufovrrun);
}

static int do_portcounters(Port * port, unsigned op, uint32_t unused,
			   uint8_t * data)
{
	Node *node = port->node;
	int portnum = mad_get_field(data, 0, IB_PC_PORT_SELECT_F);
	Portcounters totals;
	unsigned mask, mask2;
	Port *p;
	int i;

	if (node->type != SWITCH_NODE && portnum != port->portnum)
		return ERR_BAD_PARAM;	//undef_behav.

	if (node->type == SWITCH_NODE && portnum > node->numports
	    && portnum != 0xff)
		return ERR_BAD_PARAM;

	DEBUG("in node %" PRIx64 " port %" PRIx64 " portnum %d",
	      node->nodeguid, port->portguid, portnum);

	mask = mad_get_field(data, 0, IB_PC_COUNTER_SELECT_F);
	mask2 = mad_get_field(data, 0, IB_PC_COUNTER_SELECT2_F);
	if (mask2)
		mask |= GS_PERF_XMT_WAIT_MASK;

	if (portnum != 0xff) {
		if (!(p = node_get_port(node, portnum)))
			return ERR_BAD_PARAM;

		if (op == IB_MAD_METHOD_SET)
			pc_reset(&p->portcounters, mask);

		pc_get(&p->portcounters, data);
		return 0;
	}

	memset(&totals, 0, sizeof totals);

	for (i = 0; i <= node->numports; i++) {
		if (!(p = node_get_port(node, i)))
			return ERR_BAD_PARAM;
		if (op == IB_MAD_METHOD_SET)
			pc_reset(&p->portcounters, mask);
		pc_sum(&totals, &p->portcounters);
	}

	pc_get(&totals, data);
	return 0;
}

static void pc_ext_sum(Portcounters * total, Portcounters * pc)
{
	ADDVAL64(total->ext_xmit_data, pc->ext_xmit_data);
	ADDVAL64(total->ext_recv_data, pc->ext_recv_data);
	ADDVAL64(total->ext_xmit_pkts, pc->ext_xmit_pkts);
	ADDVAL64(total->ext_recv_pkts, pc->ext_recv_pkts);
	ADDVAL64(total->ext_ucast_xmit, pc->ext_ucast_xmit);
	ADDVAL64(total->ext_ucast_recv, pc->ext_ucast_recv);
	ADDVAL64(total->ext_mcast_xmit, pc->ext_mcast_xmit);
	ADDVAL64(total->ext_mcast_recv, pc->ext_mcast_recv);
}

static void pc_ext_reset(Portcounters * pc, unsigned mask)
{
	if (mask & GS_PC_EXT_XMIT_DATA)
		pc->ext_xmit_data = 0;
	if (mask & GS_PC_EXT_RECV_DATA)
		pc->ext_recv_data = 0;
	if (mask & GS_PC_EXT_XMIT_PKTS)
		pc->ext_xmit_pkts = 0;
	if (mask & GS_PC_EXT_RECV_PKTS)
		pc->ext_xmit_pkts = 0;
	if (mask & GS_PC_EXT_UCAST_XMIT)
		pc->ext_ucast_xmit = 0;
	if (mask & GS_PC_EXT_UCAST_RECV)
		pc->ext_ucast_recv = 0;
	if (mask & GS_PC_EXT_MCAST_XMIT)
		pc->ext_mcast_xmit = 0;
	if (mask & GS_PC_EXT_MCAST_RECV)
		pc->ext_mcast_recv = 0;
}

static void pc_ext_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field64(data, 0, IB_PC_EXT_XMT_BYTES_F, pc->ext_xmit_data);
	mad_set_field64(data, 0, IB_PC_EXT_RCV_BYTES_F, pc->ext_recv_data);
	mad_set_field64(data, 0, IB_PC_EXT_XMT_PKTS_F, pc->ext_xmit_pkts);
	mad_set_field64(data, 0, IB_PC_EXT_RCV_PKTS_F, pc->ext_recv_pkts);
	mad_set_field64(data, 0, IB_PC_EXT_XMT_UPKTS_F, pc->ext_ucast_xmit);
	mad_set_field64(data, 0, IB_PC_EXT_RCV_UPKTS_F, pc->ext_ucast_recv);
	mad_set_field64(data, 0, IB_PC_EXT_XMT_MPKTS_F, pc->ext_mcast_xmit);
	mad_set_field64(data, 0, IB_PC_EXT_RCV_MPKTS_F, pc->ext_mcast_recv);
}

static int
do_extcounters(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	Node *node = port->node;
	unsigned portnum;
	Portcounters totals;
	unsigned mask;
	Port *p;
	int i;

	portnum = mad_get_field(data, 0, IB_PC_EXT_PORT_SELECT_F);
	if (node->type != SWITCH_NODE && portnum != port->portnum)
		return ERR_BAD_PARAM;	//undef_behav.

	if (node->type == SWITCH_NODE && portnum > node->numports
	    && portnum != 0xff)
		return ERR_BAD_PARAM;

	DEBUG("in node %" PRIx64 " port %" PRIx64 " portnum %u",
	      node->nodeguid, port->portguid, portnum);

	mask = mad_get_field(data, 0, IB_PC_EXT_COUNTER_SELECT_F);

	if (portnum != 0xff) {
		if (!(p = node_get_port(node, portnum)))
			return ERR_BAD_PARAM;
		if (op == IB_MAD_METHOD_SET)
			pc_ext_reset(&p->portcounters, mask);
		pc_ext_get(&p->portcounters, data);
		return 0;
	}

	memset(&totals, 0, sizeof totals);

	for (i = 0; i <= node->numports; i++) {
		if (!(p = node_get_port(node, i)))
			return ERR_BAD_PARAM;
		if (op == IB_MAD_METHOD_SET)
			pc_ext_reset(&p->portcounters, mask);
		pc_ext_sum(&totals, &p->portcounters);
	}

	pc_ext_get(&totals, data);
	return 0;
}

static int do_portcounters_common(Port * port, unsigned op, uint32_t unused,
				   uint8_t * data,
				   pc_reset_function pc_reset_ptr,
				   pc_get_function pc_get_ptr,
				   pc_sum_function pc_sum_ptr)
{
	Node *node = port->node;
	unsigned portnum;
	Portcounters totals;
	unsigned mask;
	Port *p;
	int i;

	portnum = mad_get_field(data, 0, IB_PC_PORT_SELECT_F);
	if (node->type != SWITCH_NODE && portnum != port->portnum)
		return ERR_BAD_PARAM;

	if (node->type == SWITCH_NODE && portnum > node->numports
	    && portnum != 0xff)
		return ERR_BAD_PARAM;

	DEBUG("in node %" PRIx64 " port %" PRIx64 " portnum %u",
	      node->nodeguid, port->portguid, portnum);

	mask = mad_get_field(data, 0, IB_PC_COUNTER_SELECT_F);

	if (portnum != 0xff) {
		if (!(p = node_get_port(node, portnum)))
			return ERR_BAD_PARAM;
		if (op == IB_MAD_METHOD_SET)
			pc_reset_ptr(&p->portcounters, mask);
		pc_get_ptr(&p->portcounters, data);
		return 0;
	}

	memset(&totals, 0, sizeof totals);

	for (i = 0; i <= node->numports; i++) {
		if (!(p = node_get_port(node, i)))
			return ERR_BAD_PARAM;
		if (op == IB_MAD_METHOD_SET)
			pc_reset_ptr(&p->portcounters, mask);
		pc_sum_ptr(&totals, &p->portcounters);
	}

	pc_get_ptr(&totals, data);
	return 0;
}

static void pc_rcv_error_details_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_RCV_LOCAL_PHY_ERR_F,
		      pc->rcv_error_details.PortLocalPhysicalErrors);
	mad_set_field(data, 0, IB_PC_RCV_MALFORMED_PKT_ERR_F,
		      pc->rcv_error_details.PortMalformedPacketErrors);
	mad_set_field(data, 0, IB_PC_RCV_BUF_OVR_ERR_F,
		      pc->rcv_error_details.PortBufferOverrunErrors);
	mad_set_field(data, 0, IB_PC_RCV_DLID_MAP_ERR_F,
		      pc->rcv_error_details.PortDLIDMappingErrors);
	mad_set_field(data, 0, IB_PC_RCV_VL_MAP_ERR_F,
		      pc->rcv_error_details.PortVLMappingErrors);
	mad_set_field(data, 0, IB_PC_RCV_LOOPING_ERR_F,
		      pc->rcv_error_details.PortLoopingErrors);
}

static void pc_rcv_error_details_sum(Portcounters * totals, Portcounters * pc)
{
	totals->rcv_error_details.PortLocalPhysicalErrors =
		addval(totals->rcv_error_details.PortLocalPhysicalErrors,
		pc->rcv_error_details.PortLocalPhysicalErrors,
		GS_PERF_LOCAL_PHYSICAL_ERRORS_LIMIT);
	totals->rcv_error_details.PortMalformedPacketErrors =
		addval(totals->rcv_error_details.PortMalformedPacketErrors,
		pc->rcv_error_details.PortMalformedPacketErrors,
		GS_PERF_MALFORMED_PACKET_ERRORS_LIMIT);
	totals->rcv_error_details.PortBufferOverrunErrors =
		addval(totals->rcv_error_details.PortBufferOverrunErrors,
		pc->rcv_error_details.PortBufferOverrunErrors,
		GS_PERF_BUFFER_OVERRUN_ERRORS_LIMIT);
	totals->rcv_error_details.PortDLIDMappingErrors =
		addval(totals->rcv_error_details.PortDLIDMappingErrors,
		pc->rcv_error_details.PortDLIDMappingErrors,
		GS_PERF_DLID_MAPPING_ERRORS_LIMIT);
	totals->rcv_error_details.PortVLMappingErrors =
		addval(totals->rcv_error_details.PortVLMappingErrors,
		pc->rcv_error_details.PortVLMappingErrors,
		GS_PERF_VL_MAPPING_ERRORS_LIMIT);
	totals->rcv_error_details.PortLoopingErrors =
		addval(totals->rcv_error_details.PortLoopingErrors,
		pc->rcv_error_details.PortLoopingErrors,
		GS_PERF_LOOPING_ERRORS_LIMIT);
}

static void pc_rcv_error_details_reset(Portcounters * pc, unsigned mask)
{
	if(mask & GS_PERF_LOCAL_PHYSICAL_ERRORS_MASK)
		pc->rcv_error_details.PortLocalPhysicalErrors = 0;
	if(mask & GS_PERF_MALFORMED_PACKET_ERRORS_MASK)
		pc->rcv_error_details.PortMalformedPacketErrors = 0;
	if(mask & GS_PERF_BUFFER_OVERRUN_ERRORS_MASK)
		pc->rcv_error_details.PortBufferOverrunErrors = 0;
	if(mask & GS_PERF_DLID_MAPPING_ERRORS_MASK)
		pc->rcv_error_details.PortDLIDMappingErrors = 0;
	if(mask & GS_PERF_VL_MAPPING_ERRORS_MASK)
		pc->rcv_error_details.PortVLMappingErrors = 0;
	if(mask & GS_PERF_LOOPING_ERRORS_MASK)
		pc->rcv_error_details.PortLoopingErrors = 0;
}

static int do_rcv_error_details(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_rcv_error_details_reset,
		pc_rcv_error_details_get, pc_rcv_error_details_sum);
}

static void pc_xmit_discard_details_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_XMT_INACT_DISC_F,
		pc->xmit_discard_details.PortInactiveDiscards);
	mad_set_field(data, 0, IB_PC_XMT_NEIGH_MTU_DISC_F,
		pc->xmit_discard_details.PortNeighborMTUDiscards);
	mad_set_field(data, 0, IB_PC_XMT_SW_LIFE_DISC_F,
		pc->xmit_discard_details.PortSwLifetimeLimitDiscards);
	mad_set_field(data, 0, IB_PC_XMT_SW_HOL_DISC_F,
		pc->xmit_discard_details.PortSwHOQLifetimeLimitDiscards);
}

static void pc_xmit_discard_details_sum(Portcounters * totals, Portcounters * pc)
{
	totals->xmit_discard_details.PortInactiveDiscards =
		addval(totals->xmit_discard_details.PortInactiveDiscards,
		pc->xmit_discard_details.PortInactiveDiscards,
		GS_PERF_INACTIVE_DISCARDS_LIMIT);
	totals->xmit_discard_details.PortNeighborMTUDiscards =
		addval(totals->xmit_discard_details.PortNeighborMTUDiscards,
		pc->xmit_discard_details.PortNeighborMTUDiscards,
		GS_PERF_NEIGHBOR_MTU_DISCARDS_LIMIT);
	totals->xmit_discard_details.PortSwLifetimeLimitDiscards =
		addval(totals->xmit_discard_details.PortSwLifetimeLimitDiscards,
		pc->xmit_discard_details.PortSwLifetimeLimitDiscards,
		GS_PERF_SW_LIFETIME_LIMIT_DISCARDS_LIMIT);
	totals->xmit_discard_details.PortSwHOQLifetimeLimitDiscards =
		addval(totals->xmit_discard_details.PortSwHOQLifetimeLimitDiscards,
		pc->xmit_discard_details.PortSwHOQLifetimeLimitDiscards,
		GS_PERF_SW_HOQ_LIFETIME_LIMIT_DISCARDS_LIMIT);
}

static void pc_xmit_discard_details_reset(Portcounters * pc, unsigned mask)
{
	if(mask & GS_PERF_INACTIVE_DISCARDS_MASK)
		pc->xmit_discard_details.PortInactiveDiscards = 0;
	if(mask & GS_PERF_NEIGHBOR_MTU_DISCARDS_MASK)
		pc->xmit_discard_details.PortNeighborMTUDiscards = 0;
	if(mask & GS_PERF_SW_LIFETIME_LIMIT_DISCARDS_MASK)
		pc->xmit_discard_details.PortSwLifetimeLimitDiscards = 0;
	if(mask & GS_PERF_SW_HOQ_LIFETIME_LIMIT_DISCARDS_MASK)
		pc->xmit_discard_details.PortSwHOQLifetimeLimitDiscards = 0;
}

static int do_xmit_discard_details(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_xmit_discard_details_reset,
		pc_xmit_discard_details_get, pc_xmit_discard_details_sum);
}

static void pc_op_rcv_counters_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_PORT_OP_RCV_PKTS_F,
		pc->op_rcv_counters.PortOpRcvPkts);
	mad_set_field(data, 0, IB_PC_PORT_OP_RCV_DATA_F,
		pc->op_rcv_counters.PortOpRcvData);
}

static void pc_op_rcv_counters_sum(Portcounters * totals, Portcounters * pc)
{
	totals->op_rcv_counters.PortOpRcvPkts =
		addval(totals->op_rcv_counters.PortOpRcvPkts,
		pc->op_rcv_counters.PortOpRcvPkts, GS_PERF_OP_RCV_PKTS_LIMIT);
	totals->op_rcv_counters.PortOpRcvData =
		addval(totals->op_rcv_counters.PortOpRcvData,
		pc->op_rcv_counters.PortOpRcvData, GS_PERF_OP_RCV_DATA_LIMIT);
}

static void pc_op_rcv_counters_reset(Portcounters * pc, unsigned mask)
{
	if(mask & GS_PERF_OP_RCV_PKTS_MASK)
		pc->op_rcv_counters.PortOpRcvPkts = 0;
	if(mask & GS_PERF_OP_RCV_DATA_MASK)
		pc->op_rcv_counters.PortOpRcvData = 0;
}

static int do_op_rcv_counters(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_op_rcv_counters_reset,
		pc_op_rcv_counters_get, pc_op_rcv_counters_sum);
}

static void pc_flow_ctl_counters_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_PORT_XMIT_FLOW_PKTS_F,
		pc->flow_ctl_counters.PortXmitFlowPkts);
	mad_set_field(data, 0, IB_PC_PORT_RCV_FLOW_PKTS_F,
		pc->flow_ctl_counters.PortRcvFlowPkts);
}

static void pc_flow_ctl_counters_sum(Portcounters * totals, Portcounters * pc)
{
	totals->flow_ctl_counters.PortXmitFlowPkts =
		addval(totals->flow_ctl_counters.PortXmitFlowPkts,
		pc->flow_ctl_counters.PortXmitFlowPkts,
		GS_PERF_XMIT_FLOW_PKTS_LIMIT);
	totals->flow_ctl_counters.PortRcvFlowPkts =
		addval(totals->flow_ctl_counters.PortRcvFlowPkts,
		pc->flow_ctl_counters.PortRcvFlowPkts,
		GS_PERF_RCV_FLOW_PKTS_LIMIT);
}

static void pc_flow_ctl_counters_reset(Portcounters * pc, unsigned mask)
{
	if(mask & GS_PERF_XMIT_FLOW_PKTS_MASK)
		pc->flow_ctl_counters.PortXmitFlowPkts = 0;
	if(mask & GS_PERF_RCV_FLOW_PKTS_MASK)
		pc->flow_ctl_counters.PortRcvFlowPkts = 0;
}

static int do_flow_ctl_counters(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_flow_ctl_counters_reset,
		pc_flow_ctl_counters_get, pc_flow_ctl_counters_sum);
}

static void pc_vl_op_packets_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS0_F,
		pc->vl_op_packets.PortVLOpPackets[0]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS1_F,
		pc->vl_op_packets.PortVLOpPackets[1]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS2_F,
		pc->vl_op_packets.PortVLOpPackets[2]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS3_F,
		pc->vl_op_packets.PortVLOpPackets[3]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS4_F,
		pc->vl_op_packets.PortVLOpPackets[4]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS5_F,
		pc->vl_op_packets.PortVLOpPackets[5]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS6_F,
		pc->vl_op_packets.PortVLOpPackets[6]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS7_F,
		pc->vl_op_packets.PortVLOpPackets[7]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS8_F,
		pc->vl_op_packets.PortVLOpPackets[8]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS9_F,
		pc->vl_op_packets.PortVLOpPackets[9]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS10_F,
		pc->vl_op_packets.PortVLOpPackets[10]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS11_F,
		pc->vl_op_packets.PortVLOpPackets[11]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS12_F,
		pc->vl_op_packets.PortVLOpPackets[12]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS13_F,
		pc->vl_op_packets.PortVLOpPackets[13]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS14_F,
		pc->vl_op_packets.PortVLOpPackets[14]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_PACKETS15_F,
		pc->vl_op_packets.PortVLOpPackets[15]);
}

static void pc_vl_op_packets_sum(Portcounters * totals, Portcounters * pc)
{
	int i;
	for(i = 0; i < 16; i++)
		totals->vl_op_packets.PortVLOpPackets[i] =
			addval(totals->vl_op_packets.PortVLOpPackets[i],
			       pc->vl_op_packets.PortVLOpPackets[i],
			       GS_PERF_VL_OP_PACKETS_LIMIT);
}

static void pc_vl_op_packets_reset(Portcounters * pc, unsigned mask)
{
	int i;
	for(i = 0; i < 16; i++)
		if(mask & (1UL << i))
			pc->vl_op_packets.PortVLOpPackets[i] = 0;
}

static int do_vl_op_packets(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_vl_op_packets_reset,
				      pc_vl_op_packets_get, pc_vl_op_packets_sum);
}

static void pc_vl_op_data_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA0_F,
		pc->vl_op_data.PortVLOpData[0]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA1_F,
		pc->vl_op_data.PortVLOpData[1]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA2_F,
		pc->vl_op_data.PortVLOpData[2]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA3_F,
		pc->vl_op_data.PortVLOpData[3]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA4_F,
		pc->vl_op_data.PortVLOpData[4]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA5_F,
		pc->vl_op_data.PortVLOpData[5]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA6_F,
		pc->vl_op_data.PortVLOpData[6]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA7_F,
		pc->vl_op_data.PortVLOpData[7]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA8_F,
		pc->vl_op_data.PortVLOpData[8]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA9_F,
		pc->vl_op_data.PortVLOpData[9]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA10_F,
		pc->vl_op_data.PortVLOpData[10]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA11_F,
		pc->vl_op_data.PortVLOpData[11]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA12_F,
		pc->vl_op_data.PortVLOpData[12]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA13_F,
		pc->vl_op_data.PortVLOpData[13]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA14_F,
		pc->vl_op_data.PortVLOpData[14]);
	mad_set_field(data, 0, IB_PC_PORT_VL_OP_DATA15_F,
		pc->vl_op_data.PortVLOpData[15]);
}

static void pc_vl_op_data_sum(Portcounters * totals, Portcounters * pc)
{
	int i;
	for(i = 0; i < 16; i++)
		totals->vl_op_data.PortVLOpData[i] =
			addval(totals->vl_op_data.PortVLOpData[i],
			       pc->vl_op_data.PortVLOpData[i], GS_PERF_VL_OP_DATA_LIMIT);
}

static void pc_vl_op_data_reset(Portcounters * pc, unsigned mask)
{
	int i;
	for(i = 0; i < 16; i++)
	{
		if(mask & (1UL << i))
			pc->vl_op_data.PortVLOpData[i] = 0;
	}
}

static int do_vl_op_data(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_vl_op_data_reset,
		pc_vl_op_data_get, pc_vl_op_data_sum);
}

static void pc_vl_xmit_flow_ctl_update_errors_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS0_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[0]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS1_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[1]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS2_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[2]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS3_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[3]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS4_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[4]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS5_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[5]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS6_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[6]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS7_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[7]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS8_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[8]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS9_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[9]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS10_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[10]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS11_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[11]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS12_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[12]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS13_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[13]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS14_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[14]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_FLOW_CTL_UPDATE_ERRORS15_F,
		      pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[15]);
}

static void pc_vl_xmit_flow_ctl_update_errors_sum(Portcounters * totals, Portcounters * pc)
{
	int i;
	for(i = 0; i < 16; i++)
		totals->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[i] =
			addval(totals->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[i],
			       pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[i],
			       GS_PERF_VL_XMIT_FLOW_CTL_UPDATE_ERRORS);
}

static void pc_vl_xmit_flow_ctl_update_errors_reset(Portcounters * pc, unsigned mask)
{
	int i;
	for(i = 0; i < 16; i++)
		if(mask & (1UL << i))
			pc->vl_xmit_flow_ctl_update_errors.PortVLXmitFlowCtlUpdateErrors[i] = 0;
}

static int do_vl_xmit_flow_ctl_update_errors(Port * port, unsigned op, uint32_t unused, uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data, pc_vl_xmit_flow_ctl_update_errors_reset,
		pc_vl_xmit_flow_ctl_update_errors_get, pc_vl_xmit_flow_ctl_update_errors_sum);
}

static void pc_vl_xmit_wait_counters_get(Portcounters * pc, uint8_t * data)
{
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT0_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[0]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT1_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[1]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT2_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[2]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT3_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[3]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT4_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[4]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT5_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[5]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT6_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[6]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT7_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[7]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT8_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[8]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT9_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[9]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT10_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[10]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT11_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[11]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT12_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[12]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT13_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[13]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT14_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[14]);
	mad_set_field(data, 0, IB_PC_PORT_VL_XMIT_WAIT15_F,
		      pc->vl_xmit_wait_counters.PortVLXmitWait[15]);
}

static void pc_vl_xmit_wait_counters_sum(Portcounters * totals, Portcounters * pc)
{
	int i;
	for(i = 0; i < 16; i++)
		totals->vl_xmit_wait_counters.PortVLXmitWait[i] =
			addval(totals->vl_xmit_wait_counters.PortVLXmitWait[i],
			       pc->vl_xmit_wait_counters.PortVLXmitWait[i],
			       GS_PERF_VL_XMIT_WAIT_COUNTERS_LIMIT);
}

static void pc_vl_xmit_wait_counters_reset(Portcounters * pc, unsigned mask)
{
	int i;
	for(i = 0; i < 16; i++)
		if(mask & (1UL << i))
			pc->vl_xmit_wait_counters.PortVLXmitWait[i] = 0;
}

static int do_vl_xmit_wait_counters(Port * port, unsigned op, uint32_t unused,
				     uint8_t * data)
{
	return do_portcounters_common(port, op, unused, data,
				      pc_vl_xmit_wait_counters_reset,
				      pc_vl_xmit_wait_counters_get,
				      pc_vl_xmit_wait_counters_sum);
}


static char *pathstr(int lid, ib_dr_path_t * path)
{
	static char buf[1024] = "local";
	unsigned n = 0;
	int i;

	if (0 && lid != -1) {
		sprintf(buf, "lid %u", lid);
		return buf;
	}
	for (i = 0; i < path->cnt + 1; i++) {
		if (i == 0)
			n += snprintf(buf + n, sizeof(buf) - n, "%d", path->p[i]);
		else
			n += snprintf(buf + n, sizeof(buf) - n, ",%d", path->p[i]);
		if (n >= sizeof(buf))
			break;
	}

	return buf;
}

static int switch_lookup(Node * node, int lid)
{
	int outport;

	DEBUG("node 0x%" PRIx64 " lid %u", node->nodeguid, lid);
	if (!node->sw)
		return -1;

	if (lid > node->sw->linearFDBtop || (outport = node->sw->fdb[lid]) == 0xff) {
		IBWARN("sw guid %" PRIx64 ": bad lid %u", node->nodeguid, lid);
		return -1;
	}

	return outport;
}

static int port_get_remote(Port * port, Node ** remotenode, Port ** remoteport)
{
	if (!port->remotenode)
		return -1;
	*remotenode = port->remotenode;
	if (!(*remoteport = node_get_port(*remotenode, port->remoteport)))
		return -1;

	return 0;
}

static int is_port_lid(Port * port, int lid)
{
	DEBUG("port 0x%" PRIx64 " lid %u lmc %d target lid %u",
	      port->portguid, port->lid, port->lmc, lid);
	if (lid < port->lid || lid > port->lid + (1 << port->lmc) - 1)
		return 0;
	return 1;
}

static int link_valid(Port * port)
{
	Node *node = port->node;

	if (port->physstate != 5) {	// LinkUP ?
		DEBUG("port %d (link) in not UP (%d)(node %s ports %d)",
		      port->portnum, port->physstate,
		      node->nodeid, node->numports);
		return 0;
	}
	if (port->state != 4) {	// Active ?
		DEBUG("port 0x%" PRIx64
		      " %d in not Active (%d)(node %s ports %d)",
		      port->portguid, port->portnum, port->state, node->nodeid,
		      node->numports);
		return 0;
	}

	return 1;
}

static Port *lid_route_MAD(Port * port, int lid)
{
	int hop, portnum;
	Node *node = port->node;
	Port *tport = port;

	DEBUG("Node %" PRIx64 " port %" PRIx64 " (%d) lid %u",
	      node->nodeguid, port->portguid, port->portnum, lid);

	if (lid == 0) {
		IBWARN("invalid lid 0");
		return NULL;
	}

	if (is_port_lid(port, lid))
		return port;

	if (node->type != SWITCH_NODE && port_get_remote(port, &node, &port) < 0) {
		pc_add_error_xmitdiscards(port);
		IBWARN("failed: disconnected node 0x%" PRIx64 " or port 0x%"
		       PRIx64 "?", node->nodeguid, port->portguid);
		return NULL;
	}

	if (!pc_updated(&tport, port))	// if Client connected via HCA ...
		return NULL;

	for (hop = 0; !is_port_lid(port, lid) && hop < MAXHOPS; hop++) {
		portnum = switch_lookup(node, lid);

		if (portnum < 0 || portnum > node->numports) {
			pc_add_error_rcvswitchrelay(port);
			DEBUG("illegal lid %u (outport %d node %s ports %d)",
			      lid, portnum, node->nodeid, node->numports);
			return NULL;
		}

		DEBUG("node %" PRIx64 " outport %d", node->nodeguid, portnum);
		port = node_get_port(node, portnum);	// out port

		if (!port)
			IBPANIC("no out port");

		DEBUG("outport 0x%" PRIx64 " (%d)", port->portguid,
		      port->portnum);

		if (!link_valid(port)) {
			pc_add_error_xmitdiscards(port);
			return NULL;
		}

		tport = port;	// prepare to pass PKT to next port

		if (is_port_lid(port, lid))
			break;	// must be SMA port

		if (port_get_remote(port, &node, &port) < 0) {
			pc_add_error_xmitdiscards(tport);
			IBWARN("no remote");
			return NULL;
		}

		if (!node || !port)	// double check ?...
			IBPANIC("bad node %p or port %p", node, port);

		if (!link_valid(port)) {
			pc_add_error_xmitdiscards(tport);
			return NULL;
		}

		if (!pc_updated(&tport, port))	//try to transmit PKT
			return NULL;
	}

	DEBUG("routed to node %s port 0x%" PRIx64 " portnum %d (%p)",
	      node->nodeid, port->portguid, port->portnum, port);
	return port;
}

static Port *next_port(Node * node, Port * port, unsigned portnum)
{
	Port *tport;
	if (node->type != SWITCH_NODE && portnum)
		portnum--;
	if (portnum > node->numports) {
		pc_add_error_rcvswitchrelay(port);
		DEBUG("illegal port %d (node %s ports %d)",
		      portnum, node->nodeid, node->numports);
		return NULL;
	}
	port = ports + node->portsbase + portnum;
	tport = port;		// prepare to pass PKT to next port

	if (port->physstate != 5) {	// LinkUP ?
		pc_add_error_xmitdiscards(port);
		DEBUG("port %d (link) in not UP (%d)(node %s ports %d)",
		      port->portnum, port->physstate,
		      node->nodeid, node->numports);
		return NULL;
	}

	node = port->remotenode;
	portnum = port->remoteport;

	if (!node)
		return port;	/* SMA port */

	if (portnum > node->numports) {
		IBPANIC("bad remote port %d in node \"%s\" connected "
			"to node \"%s\" port %d",
			portnum, node->nodeid,
			port->node->nodeid, port->portnum);
		return NULL;
	}
	if (node->type != SWITCH_NODE)
		portnum--;	// hca or rtr first port is 1

	port = ports + node->portsbase + portnum;

	if (port->physstate != 5) {	// LinkUP ?
		pc_add_error_xmitdiscards(tport);
		pc_add_error_errs_rcv(port);
		DEBUG("remote port %d (link) in not UP (%d)(node %s ports %d)",
		      port->portnum, port->physstate,
		      node->nodeid, node->numports);
		return NULL;
	}

	if (!pc_updated(&tport, port))	//try to transmit PKT
		return NULL;

	return port;
}

static Port *direct_route_in_MAD(Port * port, ib_dr_path_t * path)
{
	unsigned ptr;

	DEBUG("route_in: path %s hops %d", pathstr(0, path), path->cnt);

	for (ptr = path->cnt; ptr; ptr--) {
		if (ptr < path->cnt && port->node->type != SWITCH_NODE)
			return NULL;
		port = next_port(port->node, port, path->p[ptr]);
		if (!port)
			return NULL;
	}

	DEBUG("routed in to node %s port %d (%p)",
	      port->node->nodeid, port->portnum, port);

	return port;
}

static Port *direct_route_out_MAD(Port * port, ib_dr_path_t * path)
{
	unsigned ptr = 0;

	DEBUG("route_out: path %s hops %d", pathstr(0, path), path->cnt);

	while (ptr < path->cnt) {
		if (ptr && port->node->type != SWITCH_NODE)
			return NULL;
		path->p[ptr++] = port->portnum;
		port = next_port(port->node, port, path->p[ptr]);
		if (!port)
			return NULL;
	}
	path->p[ptr++] = port->portnum;

	DEBUG("routed out to node %s port %d (%p) return path %s",
	      port->node->nodeid, port->portnum, port, pathstr(0, path));

	return port;
}

static Port *route_MAD(Port * port, int response, int lid, ib_dr_path_t * path)
{
	if (lid >= 0 && lid < 0xffff)
		return lid_route_MAD(port, lid);

	return response ? direct_route_in_MAD(port, path) :
	    direct_route_out_MAD(port, path);
}

static Smpfn *get_handle_fn(ib_rpc_t rpc, int response)
{
	Smpfn *fn;

	if (response)
		return NULL;

	fn = get_smp_handler(rpc.mgtclass & 0xf , rpc.attr.id);
	return fn;
}

int process_packet(Client * cl, void *p, int size, Client ** dcl)
{
	struct sim_request *r = p;
	Port *port;
	uint8_t data[256];
	int status, tlid, tqp;
	int response;
	Smpfn *fn;
	ib_rpc_t rpc = { 0 };
	ib_dr_path_t path = { 0 };

	*dcl = cl;

	DEBUG("client %d, size %d", cl->id, size);
	if (size != sizeof(*r)) {
		IBWARN("bad packet size %d (!= %zu)", size, sizeof(*r));
		return -1;
	}

	if (simverb > 2) {
		xdump(stdout, "--- packet ---\n", r->mad, 256);
		fflush(stdout);
	}
	if ((response = decode_sim_MAD(cl, r, &rpc, &path, data)) < 0)
		return -1;

	if (rpc.method == 0x7) {
		IBWARN("lid %u got trap repress - dropping", ntohs(r->dlid));
		*dcl = NULL;
		return 0;
	}

	if (!(port = route_MAD(cl->port, response, ntohs(r->dlid), &path))) {
		IBWARN("routing failed: no route to dest lid %u path %s",
		       ntohs(r->dlid), pathstr(0, &path));
		goto _dropped;
	}

	VERB("packet (attr 0x%x mod 0x%x) reached host %s port %d",
	     rpc.attr.id, rpc.attr.mod, port->node->nodeid, port->portnum);

	if (!(fn = get_handle_fn(rpc, response))) {
		if (!
		    (*dcl =
		     find_client(port, response, ntohl(r->dqp), rpc.trid))) {
			IBWARN("no one to handle pkt: class 0x%x, attr 0x%x",
			       rpc.mgtclass, rpc.attr.id);
			goto _dropped;
		}
		VERB("forward pkt to client %d pid %d attr 0x%x",
		     (*dcl)->id, (*dcl)->pid, rpc.attr.id);
		forward_MAD(r->mad, &rpc, &path);
		return sizeof(*r);	// forward only
	}

	if (port->errrate && (!port->errattr || port->errattr == rpc.attr.id) &&
	    (random() % 100) < port->errrate) {
		VERB("drop pkt due error rate %d", port->errrate);
		goto _dropped;
	}

	if ((status = fn(port, rpc.method, rpc.attr.mod, data)) < 0)
		goto _dropped;

	reply_MAD(r->mad, &rpc, &path, status, data);

	tlid = r->dlid;
	r->dlid = r->slid;
	r->slid = tlid;

	tqp = r->dqp;
	r->dqp = r->sqp;
	r->sqp = tqp;

	r->status = 0;

	port = route_MAD(port, 1, ntohs(r->dlid), &path);
	if (!port || cl->port->node != port->node) {
		VERB("PKT roll back did not succeed");
		goto _dropped;
	}
	return sizeof(*r);

  _dropped:
	r->status = htonl(110);
	*dcl = cl;
	return sizeof(*r);
}

static int encode_trap128(Port * port, char *data)
{
	if (port->node->type != SWITCH_NODE)
		return -1;
	if (!port->lid || !port->smlid) {
		VERB("switch trap 128 for lid %u with smlid %u",
		     port->lid, port->smlid);
		return -1;
	}

	mad_set_field(data, 0, IB_NOTICE_IS_GENERIC_F, 1);	// Generic
	mad_set_field(data, 0, IB_NOTICE_TYPE_F, 1);	// Urgent
	mad_set_field(data, 0, IB_NOTICE_PRODUCER_F, 2);	// Switch
	mad_set_field(data, 0, IB_NOTICE_TRAP_NUMBER_F, 128);	// PortStateChange
	mad_set_field(data, 0, IB_NOTICE_ISSUER_LID_F, port->lid);
	mad_set_field(data, 0, IB_NOTICE_TOGGLE_F, 0);
	mad_set_field(data, 0, IB_NOTICE_COUNT_F, 0);
	mad_set_field(data, 0, IB_NOTICE_DATA_LID_F, port->lid);

	return 0;
}

static int encode_trap144(Port * port, char *data)
{
	if (!port->lid || !port->smlid) {
		VERB("switch trap 144 for lid %u with smlid %u",
		     port->lid, port->smlid);
		return -1;
	}

	mad_set_field(data, 0, IB_NOTICE_IS_GENERIC_F, 1);
	mad_set_field(data, 0, IB_NOTICE_TYPE_F, 4);	// Informational
	mad_set_field(data, 0, IB_NOTICE_PRODUCER_F, port->node->type);
	mad_set_field(data, 0, IB_NOTICE_TRAP_NUMBER_F, 144);
	mad_set_field(data, 0, IB_NOTICE_ISSUER_LID_F, port->lid);
	mad_set_field(data, 0, IB_NOTICE_TOGGLE_F, 0);
	mad_set_field(data, 0, IB_NOTICE_COUNT_F, 0);
	mad_set_field(data, 0, IB_NOTICE_DATA_144_LID_F, port->lid);
	mad_set_field(data, 0, IB_NOTICE_DATA_144_CAPMASK_F,
		      mad_get_field(port->portinfo, 0, IB_PORT_CAPMASK_F));

	return 0;
}

static int encode_trap_header(char *buf)
{
	mad_set_field(buf, 0, IB_MAD_CLASSVER_F, 0x1);	// Class
	mad_set_field(buf, 0, IB_MAD_MGMTCLASS_F, 0x1);	// MgmtClass
	mad_set_field(buf, 0, IB_MAD_BASEVER_F, 0x1);	// BaseVersion
	mad_set_field(buf, 0, IB_MAD_METHOD_F, 0x5);	// SubnTrap
	mad_set_field(buf, 0, IB_MAD_ATTRID_F, 0x2);	// Notice

	return 0;
}

int send_trap(Port * port, unsigned trapnum)
{
	struct sim_request req;
	Client *cl;
	int ret, lid = port->lid;
	char *data = req.mad + 64;	/* data offset */
	EncodeTrapfn *encode_trapfn;
	Port *destport;

	if (trapnum >= TRAP_NUM_LAST) {
		IBWARN("trap number %d not supported", trapnum);
		return -1;
	}

	encode_trapfn = encodetrap[trapnum];
	memset(&req, 0, sizeof(req));
	encode_trap_header(req.mad);
	if (encode_trapfn(port, data) < 0)
		return -1;

	if (!(destport = lid_route_MAD(port, port->smlid))) {
		IBWARN("routing failed: no route to dest lid %u", port->smlid);
		return -1;
	}

	req.dlid = htons(port->smlid);
	req.slid = htons(lid);
	req.length = htonll(sizeof(req.mad));

	// find SM client
	cl = find_client(destport, 0, 1, 0);

	if (!cl)
		return 0;

	if (simverb > 2) {
		xdump(stdout, "--- packet ---\n", &req, 256);
		fflush(stdout);
	}

	do {
		ret = write(cl->fd, &req, sizeof(req));
	} while ((errno == EAGAIN) && (ret == -1));

	if (ret == sizeof(req))
		return 0;

	if (ret < 0 && (errno == ECONNREFUSED || errno == ENOTCONN)) {
		IBWARN("write: client %u seems to be dead"
		       " - disconnecting.", cl->id);
		disconnect_client(cl->id);
		return -1;
	}

	IBWARN("write failed: %m - pkt dropped");

	return -1;
}
