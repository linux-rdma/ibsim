/*
 * Copyright (c) 2004-2006 Voltaire, Inc. All rights reserved.
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
#include <netinet/in.h>
#include <inttypes.h>

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
    do_pkeytbl, do_sl2vl, do_vlarb, do_nothing;

static EncodeTrapfn encode_trap128;

Smpfn *attrs[IB_PERFORMANCE_CLASS + 1][0xff] = {
	[IB_SMI_CLASS] {[IB_ATTR_NODE_DESC] do_nodedesc,
			[IB_ATTR_NODE_INFO] do_nodeinfo,
			[IB_ATTR_SWITCH_INFO] do_switchinfo,
			[IB_ATTR_PORT_INFO] do_portinfo,
			[IB_ATTR_LINEARFORWTBL] do_linearforwtbl,
			[IB_ATTR_MULTICASTFORWTBL] do_multicastforwtbl,
			[IB_ATTR_PKEY_TBL] do_pkeytbl,
			[IB_ATTR_SLVL_TABLE] do_sl2vl,
			[IB_ATTR_VL_ARBITRATION] do_vlarb,
			[IB_ATTR_SMINFO] NULL,

			[IB_ATTR_LAST] 0,
			},
	[IB_PERFORMANCE_CLASS] {[CLASS_PORT_INFO] = do_nothing,
				[IB_GSI_PORT_SAMPLES_CONTROL] = 0,
				[IB_GSI_PORT_SAMPLES_RESULT] = 0,
				[IB_GSI_PORT_COUNTERS] = do_portcounters,
				[IB_GSI_PORT_COUNTERS_EXT] = do_extcounters,

				[IB_GSI_ATTR_LAST] 0,

				},
};

EncodeTrapfn *encodetrap[] = {
	[TRAP_128] encode_trap128,

	[TRAP_NUM_LAST] 0,

};

extern Node *nodes;
extern Switch *switchs;
extern Port *ports;
extern Port **lids;
extern int netnodes, netports, netswitches;
extern int maxlinearcap;

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
	rpc->trid = mad_get_field64(buf, 0, IB_MAD_TRID_F);

	if (!response)
		cl->trid = rpc->trid;

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

static int do_nothing(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	return 0;
}

static int do_nodedesc(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	int status = 0;

	if (op != 1)		// get
		status = ERR_METHOD_UNSUPPORTED;
	memcpy(data, port->node->nodedesc, IB_SMP_DATA_SIZE);

	return status;
}

static int do_nodeinfo(Port * port, unsigned op, uint32_t mod, uint8_t * data)
{
	Node *node = port->node;
	int status = 0;
	uint64_t portguid = node->nodeguid + port->portnum;

	if (op != IB_MAD_METHOD_GET)	// get
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

	if (op == 2) {		// Set
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
		if (!port && !node_get_port(port->node, n))
			return ERR_BAD_PARAM;
	} else
		n = 0;

	sl2vl = port->sl2vl + 8 * n;

	if (op == IB_MAD_METHOD_SET) {
		memcpy(sl2vl, data, 8);
	} else {
		memcpy(data, sl2vl, 8);
	}

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

	if (op == IB_MAD_METHOD_SET) {
		memcpy(vlarb, data, size);
	} else {
		memset(data, 0, 64);
		memcpy(data, vlarb, size);
	}

	return 0;
}

static int
do_portinfo(Port * port, unsigned op, uint32_t portnum, uint8_t * data)
{
	Node *node = port->node;
	Port *p, *rp;
	int r, newlid, newstate = 0;

	if (portnum > node->numports)
		return ERR_BAD_PARAM;

	if (portnum == 0 && node->type != SWITCH_NODE)	//according to ibspec 14.2.5.6
		portnum = port->portnum;

	p = node_get_port(node, portnum);
	DEBUG("in node %" PRIx64 " port %" PRIx64 ": port %" PRIx64 " (%d(%d))",
	      node->nodeguid, port->portguid, p->portguid, p->portnum, portnum);

	if (op == IB_MAD_METHOD_SET) {	// set
		unsigned val;
		if (node->type != SWITCH_NODE && port->portnum != p->portnum)
			return ERR_BAD_PARAM;	// on HCA or rtr can't "set" on other port
		newlid = mad_get_field(data, 0, IB_PORT_LID_F);
		if (newlid != p->lid) {
			if (p->lid > 0 && p->lid < maxlinearcap
			    && lids[p->lid] == p)
				lids[p->lid] = 0;
		}
		p->lid = newlid;
		p->smlid = mad_get_field(data, 0, IB_PORT_SMLID_F);
//              p->linkwidth = mad_get_field(data, 0, IB_PORT_LINK_WIDTH_ENABLED_F); // ignored
		p->lmc = mad_get_field(data, 0, IB_PORT_LMC_F);
		p->hoqlife = mad_get_field(data, 0, IB_PORT_HOQ_LIFE_F);
		if ((r = mad_get_field(data, 0, IB_PORT_PHYS_STATE_F)))
			p->physstate = r;
		r = mad_get_field(data, 0, IB_PORT_STATE_F);
		if (r > 0 && p->remotenode &&
		    (rp = node_get_port(p->remotenode, p->remoteport))) {
			if (r == 1) {	/* DOWN */
				newstate = p->state = 2;	/* set to INIT */
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
					newstate = p->state = r;	/* set to new state */
				else
					return ERR_BAD_PARAM;
			}
		} else if (r > 1)
			return ERR_BAD_PARAM;	/* trying to change the state of DOWN port */

		if (p->state == 4) {
			if (p->lid > 0 && p->lid < maxlinearcap
			    && lids[p->lid] != p && lids[p->lid])
				IBWARN
				    ("Port %s:%d overwrite lid table entry for lid %d (was %s:%d)",
				     node->nodeid, p->portnum, p->lid,
				     lids[p->lid]->node->nodeid,
				     lids[p->lid]->portnum);
			lids[p->lid] = p;
		}
		val = mad_get_field(data, 0, IB_PORT_OPER_VLS_F);
		if (val > mad_get_field(data, 0, IB_PORT_VL_CAP_F))
			return ERR_BAD_PARAM;
		p->op_vls = val;
	}

	update_portinfo(p);
	memcpy(data, p->portinfo, IB_SMP_DATA_SIZE);

	return 0;
}

static int do_linearforwtbl(Port * port, unsigned op, uint32_t mod,
			    uint8_t * data)
{
	Switch *sw = port->node->sw;

	if (!sw)		// not a Switch?
		return ERR_ATTR_UNSUPPORTED;

	if (mod < 0 || mod > 767)
		return ERR_BAD_PARAM;

	if (op == IB_MAD_METHOD_SET) {	// Set
		mad_get_array(data, 0, IB_LINEAR_FORW_TBL_F,
			      sw->fdb + mod * 64);
	}

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
	if (numBlock32 > LASTBLOCK32 || numPortMsk > LASTPORTMASK) {
		int8_t zeroblock[64] = { 0 };
		mad_set_array(data, 0, IB_MULTICAST_FORW_TBL_F, zeroblock);
		return 0;
	}

	blockposition = (numBlock32 * NUMBEROFPORTMASK + numPortMsk) * 64;
	if (op == IB_MAD_METHOD_SET) {	// Set
		mad_get_array(data, 0, IB_MULTICAST_FORW_TBL_F,
			      sw->mfdb + blockposition);
	}
	mad_set_array(data, 0, IB_MULTICAST_FORW_TBL_F,
		      sw->mfdb + blockposition);
	return 0;
}

static void pc_reset(Portcounters * pc, uint mask)
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
}

static inline uint32_t addval(uint32_t val, uint32_t delta, uint32_t max)
{
	uint32_t newval = val + delta;

	return (newval > max || newval < val) ? max : newval;
}

#define ADDVAL64(val, add) { uint64_t new = val + add; \
		val = new < val ? 0xffffffffffffffffULL : new ; }

void pc_add_error_xmitdiscards(Port * port)
{
	Portcounters *pc = &(port->portcounters);

	pc->xmitdiscards =
	    addval(pc->xmitdiscards, 1, GS_PERF_XMT_DISCARDS_LIMIT);
}

void pc_add_error_rcvswitchrelay(Port * port)
{
	Portcounters *pc = &(port->portcounters);

	pc->errs_rcvswitchrelay =
	    addval(pc->errs_rcvswitchrelay, 1, GS_PERF_ERR_SWITCH_REL_LIMIT);
}

void pc_add_error_errs_rcv(Port * port)
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
		//PKT get out of port ..
		srcpc->flow_xmt_pkts =
		    addval(srcpc->flow_xmt_pkts, 1, GS_PERF_XMT_PKTS_LIMIT);
		srcpc->flow_xmt_bytes =
		    addval(srcpc->flow_xmt_bytes, madsize_div_4,
			   GS_PERF_XMT_BYTES_LIMIT);
		ADDVAL64(destpc->ext_xmit_data, madsize_div_4);
		ADDVAL64(destpc->ext_xmit_pkts, 1);

		if (destport->errrate && (random() % 100) < destport->errrate) {
			pc_add_error_errs_rcv(destport);
			VERB("drop pkt due error rate %d", destport->errrate);
			return 0;
		}
		//PKT get in to the port ..
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
	uint mask;
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

static void pc_ext_reset(Portcounters * pc, uint mask)
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

static char *pathstr(int lid, ib_dr_path_t * path)
{
	static char buf[1024] = "local";
	char *s = buf;
	int i;

	if (0 && lid != -1) {
		sprintf(s, "lid 0x%x", lid);
		return buf;
	}
	for (i = 0; i < path->cnt + 1; i++)
		s += sprintf(s, "[%d]", path->p[i]);

	return buf;
}

static int switch_lookup(Node * node, int lid)
{
	int outport;

	DEBUG("node 0x%" PRIx64 " lid %d", node->nodeguid, lid);
	if (!node->sw)
		return -1;

	if (lid > node->sw->linearFDBtop || (outport = node->sw->fdb[lid]) < 0) {
		IBWARN("sw guid %" PRIx64 ": bad lid %d", node->nodeguid, lid);
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
	DEBUG("port 0x%" PRIx64 " lid %d lmc %d target lid %d",
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

	DEBUG("Node %" PRIx64 " port %" PRIx64 " (%d) lid %d",
	      node->nodeguid, port->portguid, port->portnum, lid);

	if (lid == 0) {
		IBWARN("invalid lid 0");
		return 0;
	}

	if (is_port_lid(port, lid))
		return port;

	if (node->type != SWITCH_NODE && port_get_remote(port, &node, &port) < 0) {
		pc_add_error_xmitdiscards(port);
		IBWARN("failed: disconnected node 0x%" PRIx64 " or port 0x%"
		       PRIx64 "?", node->nodeguid, port->portguid);
		return 0;
	}

	if (!pc_updated(&tport, port))	// if Client connected via HCA ...
		return 0;

	for (hop = 0; !is_port_lid(port, lid) && hop < MAXHOPS; hop++) {
		portnum = switch_lookup(node, lid);

		if (portnum < 0 || portnum > node->numports) {
			pc_add_error_rcvswitchrelay(port);
			DEBUG("illegal lid %d (outport %d node %s ports %d)",
			      lid, portnum, node->nodeid, node->numports);
			return 0;
		}

		DEBUG("node %" PRIx64 " outport %d", node->nodeguid, portnum);
		port = node_get_port(node, portnum);	// out port

		if (!port)
			IBPANIC("no out port");

		DEBUG("outport 0x%" PRIx64 " (%d)", port->portguid,
		      port->portnum);

		if (!link_valid(port)) {
			pc_add_error_xmitdiscards(port);
			return 0;
		}

		tport = port;	// prepare to pass PKT to next port

		if (is_port_lid(port, lid))
			break;	// must be SMA port

		if (port_get_remote(port, &node, &port) < 0) {
			pc_add_error_xmitdiscards(tport);
			IBWARN("no remote");
			return 0;
		}

		if (!node || !port)	// double check ?...
			IBPANIC("bad node %p or port %p", node, port);

		if (!link_valid(port)) {
			pc_add_error_xmitdiscards(tport);
			return 0;
		}

		if (!pc_updated(&tport, port))	//try to transmit PKT
			return 0;
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

	DEBUG("route_in: path %s hops %d\n", pathstr(0, path), path->cnt);

	for (ptr = path->cnt; ptr; ptr--) {
		if (ptr < path->cnt && port->node->type != SWITCH_NODE)
			return NULL;
		port = next_port(port->node, port, path->p[ptr]);
		if (!port)
			return NULL;
	}

	DEBUG("routed in to node %s port %d (%p)\n",
	      port->node->nodeid, port->portnum, port);

	return port;
}

static Port *direct_route_out_MAD(Port * port, ib_dr_path_t * path)
{
	unsigned ptr = 0;

	DEBUG("route_out: path %s hops %d\n", pathstr(0, path), path->cnt);

	while (ptr < path->cnt) {
		if (ptr && port->node->type != SWITCH_NODE)
			return NULL;
		path->p[ptr++] = port->portnum;
		port = next_port(port->node, port, path->p[ptr]);
		if (!port)
			return NULL;
	}
	path->p[ptr++] = port->portnum;

	DEBUG("routed out to node %s port %d (%p) return path %s\n",
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

int modified;

Smpfn *get_handle_fn(ib_rpc_t rpc, int response)
{
	Smpfn *fn;

	if (response)
		return 0;

	if (rpc.mgtclass == IB_SMI_CLASS || rpc.mgtclass == IB_SMI_DIRECT_CLASS) {
		if (rpc.attr.id >= IB_ATTR_LAST
		    || !(fn = attrs[rpc.mgtclass & 0xf][rpc.attr.id]))
			return 0;	// not supported attribute ???
		return fn;
	}

	if (rpc.mgtclass == IB_PERFORMANCE_CLASS) {
		if (rpc.attr.id >= IB_GSI_ATTR_LAST
		    || !(fn = attrs[rpc.mgtclass & 0xf][rpc.attr.id]))
			return 0;	// not supported attribute ???
		return fn;
	}

	return 0;		// No MGTCLASS matched .
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

	DEBUG("client id %d, size %d", cl->id, size);
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
		IBWARN("got trap repress - drop");
		*dcl = 0;
		return 0;
	}

	if (!(port = route_MAD(cl->port, response, ntohs(r->dlid), &path))) {
		IBWARN("routing failed: no route to dest lid %d %s",
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
		VERB("forward pkt to client %d pid %d attr %d",
		     (*dcl)->id, (*dcl)->pid, rpc.attr.id);
		forward_MAD(r->mad, &rpc, &path);
		return sizeof(*r);	// forward only
	}

	if (port->errrate && (random() % 100) < port->errrate) {
		VERB("drop pkt due error rate %d", port->errrate);
		goto _dropped;
	}

	if ((status = fn(port, rpc.method, rpc.attr.mod, data)) < 0)
		return -1;

	if (rpc.method == 2)
		modified++;

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
		VERB("PKT roll back not succeeded");
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
	if (!port->lid || !port->smlid || port->node->type != SWITCH_NODE) {
		VERB("trap 128 supported for switches only");
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

static int encode_trap_header(char *buf)
{
	mad_set_field(buf, 0, IB_MAD_CLASSVER_F, 0x1);	// Class
	mad_set_field(buf, 0, IB_MAD_MGMTCLASS_F, 0x1);	// MgmtClass
	mad_set_field(buf, 0, IB_MAD_BASEVER_F, 0x1);	// BaseVersion
	mad_set_field(buf, 0, IB_MAD_METHOD_F, 0x5);	// SubnTrap
	mad_set_field(buf, 0, IB_MAD_ATTRID_F, 0x2);	// Notice

	return 0;
}

int send_trap(Port * port, int trapnum)
{
	struct sim_request req;
	Client *cl;
	int lid = port->lid;
	char *data = req.mad + 64;	/* data offset */
	EncodeTrapfn *encode_trapfn = encodetrap[trapnum];
	Port *destport;

	if (!encode_trapfn) {
		IBWARN("trap number %d not upported", trapnum);
		return -1;
	}

	memset(req.mad, 0, sizeof(req.mad));
	encode_trap_header(req.mad);
	if (encode_trapfn(port, data) < 0)
		return -1;

	if (!(destport = lid_route_MAD(port, port->smlid))) {
		IBWARN("routing failed: no route to dest lid %d", port->smlid);
		return -1;
	}

	req.dlid = htons(port->smlid);
	req.slid = htons(lid);
	req.sqp = 0;
	req.dqp = 0;
	req.context = 0;

	// find SM client
	cl = find_client(destport, 0, 1, 0);

	if (!cl)
		return 0;

	if (simverb > 2) {
		xdump(stdout, "--- packet ---\n", &req, 256);
		fflush(stdout);
	}

	if (write(cl->outfd, &req, sizeof(req)) == sizeof(req))
		return 0;

	IBWARN("write failed: %m - pkt dropped");

	return -1;
}
