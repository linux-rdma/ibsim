/*
 * Copyright (c) 2006-2008 Voltaire, Inc. All rights reserved.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#define info(fmt, arg...) fprintf(stderr, "INFO: " fmt, ##arg )
#define err(fmt, arg...) fprintf(stderr, "ERR: " fmt, ##arg )
#ifdef NOISY_DEBUG
#define dbg(fmt, arg...) fprintf(stderr, "DBG: " fmt, ##arg )
#else
#define dbg(fmt, arg...)
#endif

#define TMO 100

#define DEFAULT_PREFIX 0xfe80000000000000ULL

/* Multicast Member Record Component Masks */
#define IB_MCR_COMPMASK_MGID        (1ULL<<0)
#define IB_MCR_COMPMASK_PORT_GID    (1ULL<<1)
#define IB_MCR_COMPMASK_QKEY        (1ULL<<2)
#define IB_MCR_COMPMASK_MLID        (1ULL<<3)
#define IB_MCR_COMPMASK_MTU_SEL     (1ULL<<4)
#define IB_MCR_COMPMASK_MTU         (1ULL<<5)
#define IB_MCR_COMPMASK_TCLASS      (1ULL<<6)
#define IB_MCR_COMPMASK_PKEY        (1ULL<<7)
#define IB_MCR_COMPMASK_RATE_SEL    (1ULL<<8)
#define IB_MCR_COMPMASK_RATE        (1ULL<<9)
#define IB_MCR_COMPMASK_LIFE_SEL    (1ULL<<10)
#define IB_MCR_COMPMASK_LIFE        (1ULL<<11)
#define IB_MCR_COMPMASK_SL          (1ULL<<12)
#define IB_MCR_COMPMASK_FLOW        (1ULL<<13)
#define IB_MCR_COMPMASK_HOP         (1ULL<<14)
#define IB_MCR_COMPMASK_SCOPE       (1ULL<<15)
#define IB_MCR_COMPMASK_JOIN_STATE  (1ULL<<16)
#define IB_MCR_COMPMASK_PROXY       (1ULL<<17)

struct addr_data {
	int port;
	int agent;
	int timeout;
	ib_portid_t dport;
};

static ibmad_gid_t mgid_ipoib = {
	0xff, 0x12, 0x40, 0x1b, 0xff, 0xff, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

uint64_t build_mcm_rec(uint8_t * data, ibmad_gid_t mgid, ibmad_gid_t port_gid,
		       uint8_t join_state)
{
	memset(data, 0, IB_SA_DATA_SIZE);
	mad_set_array(data, 0, IB_SA_MCM_MGID_F, mgid);
	mad_set_array(data, 0, IB_SA_MCM_PORTGID_F, port_gid);
	mad_set_field(data, 0, IB_SA_MCM_JOIN_STATE_F, join_state);

	return IB_MCR_COMPMASK_MGID | IB_MCR_COMPMASK_PORT_GID |
	    IB_MCR_COMPMASK_JOIN_STATE;
}

uint64_t build_mcm_create_rec(uint8_t * data, ibmad_gid_t mgid,
			      ibmad_gid_t port_gid, uint8_t join_state)
{
	uint64_t comp_mask = build_mcm_rec(data, mgid, port_gid, join_state);

	mad_set_field(data, 0, IB_SA_MCM_QKEY_F, 0x80010000);
	mad_set_field(data, 0, IB_SA_MCM_SL_F, 0);
	mad_set_field(data, 0, IB_SA_MCM_MTU_F, 4);
	mad_set_field(data, 0, IB_SA_MCM_RATE_F, 3);
	mad_set_field(data, 0, IB_SA_MCM_TCLASS_F, 0);
	mad_set_field(data, 0, IB_SA_MCM_PKEY_F, 0xffff);
	mad_set_field(data, 0, IB_SA_MCM_FLOW_LABEL_F, 0);

	return comp_mask | IB_MCR_COMPMASK_QKEY | IB_MCR_COMPMASK_SL |
	    IB_MCR_COMPMASK_MTU | IB_MCR_COMPMASK_RATE | IB_MCR_COMPMASK_PKEY |
	    IB_MCR_COMPMASK_TCLASS | IB_MCR_COMPMASK_FLOW;
}

static void build_mcm_rec_umad(void *umad, ib_portid_t * dport, int method,
			       uint64_t comp_mask, uint8_t * data)
{
	ib_rpc_t rpc;

	memset(&rpc, 0, sizeof(rpc));
	rpc.mgtclass = IB_SA_CLASS;
	rpc.method = method;
	rpc.attr.id = IB_SA_ATTR_MCRECORD;
	rpc.attr.mod = 0;	// ???
	rpc.mask = comp_mask;
	rpc.datasz = IB_SA_DATA_SIZE;
	rpc.dataoffs = IB_SA_DATA_OFFS;

	mad_build_pkt(umad, &rpc, dport, NULL, data);
}

static uint64_t get_guid_ho(ibmad_gid_t gid)
{
	uint64_t guid;
	memcpy(&guid, &gid[8], sizeof(guid));
	return ntohll(guid);
}

static int send_req(struct addr_data *a, uint8_t * umad, int len,
		    int method, uint64_t comp_mask, uint8_t data[])
{
	build_mcm_rec_umad(umad, &a->dport, method, comp_mask, data);
	if (umad_send(a->port, a->agent, umad, len, a->timeout, 0) < 0) {
		err("umad_send method %u, tid 0x%016" PRIx64 "failed: %s\n",
		    method,
		    mad_get_field64(umad_get_mad(umad), 0, IB_MAD_TRID_F),
		    strerror(errno));
		return -1;
	}
	dbg("umad_send %d: tid = 0x%016" PRIx64 "\n", method,
	    mad_get_field64(umad_get_mad(umad), 0, IB_MAD_TRID_F));

	return 0;
}

static int recv_res(struct addr_data *a, uint8_t * umad, int length)
{
	int ret, retry = 0;
	int len = length;

	while ((ret = umad_recv(a->port, umad, &len, a->timeout)) < 0 &&
	       errno == ETIMEDOUT) {
		if (retry++ > 3)
			return 0;
	}
	if (ret < 0) {
		err("umad_recv %d failed: %s\n", ret, strerror(errno));
		return -1;
	}
	dbg("umad_recv (retries %d), tid = 0x%016" PRIx64
	    ": len = %d, status = %d\n", retry,
	    mad_get_field64(umad_get_mad(umad), 0, IB_MAD_TRID_F), len,
	    umad_status(umad));

	return 1;
}

static int rereg_send(struct addr_data *a, uint8_t * umad, int len,
		      int method, ibmad_gid_t port_gid)
{
	uint8_t data[IB_SA_DATA_SIZE];
	uint64_t comp_mask;

	comp_mask = build_mcm_rec(data, mgid_ipoib, port_gid, 1);

	if (send_req(a, umad, len, method, comp_mask, data)) {
		err("umad_send method %u failed for guid 0x%016" PRIx64
		    ": %s\n", method, get_guid_ho(port_gid), strerror(errno));
		return -1;
	}

	return 0;
}

struct port_list {
	ibmad_gid_t gid;
	uint64_t guid;
	uint64_t trid;
	unsigned mgrp_count;
};

struct mgrp_list {
	ibmad_gid_t mgid;
};

static int rereg_port(struct addr_data *a, uint8_t * umad, int len,
		      struct port_list *list)
{
	if (rereg_send(a, umad, len, IB_MAD_METHOD_DELETE, list->gid))
		return -1;

	if (rereg_send(a, umad, len, IB_MAD_METHOD_SET, list->gid))
		return -1;
	list->trid = mad_get_field64(umad_get_mad(umad), 0, IB_MAD_TRID_F);

	return 0;
}

static int rereg_send_all(struct addr_data *a,
			  struct port_list *list, unsigned cnt)
{
	uint8_t *umad;
	int len = 256;
	int i;

	info("rereg_send_all... cnt = %u\n", cnt);

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < cnt; i++)
		rereg_port(a, umad, len, &list[i]);

	info("rereg_send_all: sent %u requests\n", cnt * 2);

	free(umad);

	return 0;
}

static int rereg_recv_all(struct addr_data *a,
			  struct port_list *list, unsigned cnt)
{
	uint8_t *umad, *mad;
	int len = 256;
	uint64_t trid;
	unsigned n, method, status;
	int i;

	info("rereg_recv_all...\n");

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}

	n = 0;
	while (recv_res(a, umad, len) > 0) {
		dbg("rereg_recv_all: done %d\n", n);
		n++;
		mad = umad_get_mad(umad);

		method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
		status = mad_get_field(mad, 0, IB_MAD_STATUS_F);

		if (status)
			dbg("MAD status %x, method %x\n", status, method);

		if (status &&
		    (method & 0x7f) == (IB_MAD_METHOD_GET_RESPONSE & 0x7f)) {
			trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
			for (i = 0; i < cnt; i++)
				if (trid == list[i].trid)
					break;
			if (i == cnt) {
				err("cannot find trid 0x%016" PRIx64
				    ", status %x\n", trid, status);
				continue;
			}
			info("guid 0x%016" PRIx64
			     ": method = %x status = %x. Resending\n",
			     ntohll(list[i].guid), method, status);
			rereg_port(a, umad, len, &list[i]);
		}
	}

	info("rereg_recv_all: got %u responses\n", n);

	free(umad);
	return 0;
}

static int rereg_query_all(struct addr_data *a,
			   struct port_list *list, unsigned cnt)
{
	uint8_t *umad, *mad;
	int len = 256;
	unsigned method, status;
	int i, ret;

	info("rereg_query_all...\n");

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < cnt; i++) {
		ret = rereg_send(a, umad, len, IB_MAD_METHOD_GET, list[i].gid);
		if (ret < 0) {
			err("query_all: rereg_send failed.\n");
			continue;
		}

		ret = recv_res(a, umad, len);
		if (ret < 0) {
			err("query_all: recv_res failed.\n");
			continue;
		}

		mad = umad_get_mad(umad);

		method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
		status = mad_get_field(mad, 0, IB_MAD_STATUS_F);

		if (status)
			info("guid 0x%016" PRIx64 ": status %x, method %x\n",
			     ntohll(list[i].guid), status, method);
	}

	info("rereg_query_all: %u queried.\n", cnt);

	free(umad);
	return 0;
}

static int parse_port_guids_file(const char *guid_file,
				 struct port_list **port_list)
{
	char line[256];
	FILE *f;
	ibmad_gid_t port_gid;
	uint64_t guid, prefix = htonll(DEFAULT_PREFIX);
	struct port_list *list = NULL;
	unsigned list_size = 0;
	int i = 0;

	f = fopen(guid_file, "r");
	if (!f) {
		fprintf(stderr, "cannot fopen \'%s\' %s\n",
			guid_file, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		guid = strtoull(line, NULL, 0);
		guid = htonll(guid);
		memcpy(&port_gid[0], &prefix, 8);
		memcpy(&port_gid[8], &guid, 8);

		if (i >= list_size) {
			list_size += 256;
			list = realloc(list, list_size * sizeof(list[0]));
			if (!list) {
				err("cannot alloc mem for guid/trid list: %s\n",
				    strerror(errno));
				return -1;
			}
		}

		memset(&list[i], 0, sizeof(list[i]));
		list[i].guid = guid;
		memcpy(list[i].gid, port_gid, sizeof(list[i].gid));
		i++;
	}
	fclose(f);

	*port_list = list;

	return i;
}

#define MAX_CLIENTS 100

static int run_port_rereg_test(struct addr_data *a, const char *guid_file)
{
	struct port_list *list;
	int size, cnt, i;

	size = parse_port_guids_file(guid_file, &list);
	if (size < 0)
		return size;

	for (cnt = size; cnt;) {
		i = cnt > MAX_CLIENTS ? MAX_CLIENTS : cnt;
		rereg_send_all(a, list + (size - cnt), i);
		rereg_recv_all(a, list, size);
		cnt -= i;
	}

	rereg_query_all(a, list, size);

	free(list);
	return 0;
}

static int run_mcast_storm_test(struct addr_data *a,
				const char *file_gile, const char *mcgroup_file)
{
	return 0;
}

int main(int argc, char **argv)
{
	const char *guid_file = "port_guids.list";
	const char *mcast_file = "mcast_groups.list";
	int mgmt_classes[2] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS };
	struct addr_data addr;
	int ret;

	if (argc > 1)
		guid_file = argv[1];

	madrpc_init(NULL, 0, mgmt_classes, 2);

	ib_resolve_smlid(&addr.dport, TMO);
	if (!addr.dport.lid) {
		/* dport.lid = 1; */
		err("No SM. Exit.\n");
		exit(1);
	}
	addr.dport.qp = 1;
	if (!addr.dport.qkey)
		addr.dport.qkey = IB_DEFAULT_QP1_QKEY;

	addr.port = madrpc_portid();
	addr.agent = umad_register(addr.port, IB_SA_CLASS, 2, 0, NULL);
	addr.timeout = TMO;

	ret = run_port_rereg_test(&addr, guid_file);
	ret = run_mcast_storm_test(&addr, guid_file, mcast_file);

	umad_unregister(addr.port, addr.agent);
	umad_close_port(addr.port);
	umad_done();

	return ret;
}
