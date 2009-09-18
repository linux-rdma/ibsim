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
#include <ctype.h>
#include <getopt.h>

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
#define DEFAULT_MGID_PREFIX 0xff00000000000000ULL

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

struct mcmember_params {
	uint32_t qkey;
	uint16_t mlid;
	uint8_t mtu;
	int tclass;
	uint16_t pkey;
	uint8_t rate;
	int sl;
	int flow_label;
	int hop_limit;
	uint8_t scope;
	uint8_t join_state;
	int proxy_join;
};

static const struct mcmember_params null_params = {
	.tclass = -1,
	.sl = -1,
	.flow_label = -1,
	.hop_limit = -1,
	.proxy_join = -1,
};

static const struct mcmember_params mcmember_params_join = {
	.tclass = -1,
	.sl = -1,
	.flow_label = -1,
	.hop_limit = -1,
	.join_state = 1,
	.proxy_join = -1,
};

static const struct mcmember_params mcmember_params_create = {
	.qkey = 0x80010000,
	.mtu = 4,
	.tclass = 0,
	.pkey = 0xffff,
	.rate = 3,
	.sl = 0,
	.flow_label = 0,
	.hop_limit = -1,
	.join_state = 1,
	.proxy_join = -1,
};

static ibmad_gid_t mgid_ipoib = {
	0xff, 0x12, 0x40, 0x1b, 0xff, 0xff, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

static int64_t add_rid(uint8_t *data, ibmad_gid_t mgid, ibmad_gid_t port_gid)
{
	mad_set_array(data, 0, IB_SA_MCM_MGID_F, mgid);
	mad_set_array(data, 0, IB_SA_MCM_PORTGID_F, port_gid);

	return IB_MCR_COMPMASK_MGID | IB_MCR_COMPMASK_PORT_GID;
}

static uint64_t build_mcm_rec(uint8_t * data, const struct mcmember_params *p)
{
#define SET_FIELD1(val, mask, field) \
	if (val) { \
		mad_set_field(data, 0, field, val); \
		comp_mask |= mask; \
	}

#define SET_FIELD(obj, name, mask, field) \
	if (obj->name != null_params.name) { \
		mad_set_field(data, 0, field, obj->name); \
		comp_mask |= mask; \
	}

	uint64_t comp_mask = 0;

	memset(data, 0, IB_SA_DATA_SIZE);

	if (!p)
		return comp_mask;

	SET_FIELD(p, qkey, IB_MCR_COMPMASK_QKEY, IB_SA_MCM_QKEY_F);
	SET_FIELD(p, mlid, IB_MCR_COMPMASK_MLID, IB_SA_MCM_MLID_F);
	SET_FIELD(p, mtu, IB_MCR_COMPMASK_MTU, IB_SA_MCM_MTU_F);
	SET_FIELD(p, tclass, IB_MCR_COMPMASK_TCLASS, IB_SA_MCM_TCLASS_F);
	SET_FIELD(p, pkey, IB_MCR_COMPMASK_PKEY, IB_SA_MCM_PKEY_F);
	SET_FIELD(p, rate, IB_MCR_COMPMASK_RATE, IB_SA_MCM_RATE_F);
	SET_FIELD(p, sl, IB_MCR_COMPMASK_SL, IB_SA_MCM_SL_F);
	SET_FIELD(p, flow_label, IB_MCR_COMPMASK_FLOW, IB_SA_MCM_FLOW_LABEL_F);
	SET_FIELD(p, join_state, IB_MCR_COMPMASK_JOIN_STATE, IB_SA_MCM_JOIN_STATE_F);
	SET_FIELD(p, proxy_join, IB_MCR_COMPMASK_PROXY, IB_SA_MCM_PROXY_JOIN_F);

	return comp_mask;
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

static int send_join(struct addr_data *a, uint8_t * umad, int len,
		     ibmad_gid_t mgid, ibmad_gid_t port_gid,
		     uint64_t comp_mask, uint8_t data[])
{
	comp_mask |= add_rid(data, mgid, port_gid);

	return send_req(a, umad, len, IB_MAD_METHOD_SET, comp_mask, data);
}

static int send_leave(struct addr_data *a, uint8_t * umad, int len,
		      ibmad_gid_t mgid, ibmad_gid_t port_gid,
		      uint64_t comp_mask, uint8_t data[])
{
	comp_mask |= add_rid(data, mgid, port_gid);

	return send_req(a, umad, len, IB_MAD_METHOD_DELETE, comp_mask, data);
}

static int send_query(struct addr_data *a, uint8_t * umad, int len,
		      ibmad_gid_t mgid, ibmad_gid_t port_gid,
		      uint64_t comp_mask, uint8_t data[])
{
	comp_mask |= add_rid(data, mgid, port_gid);

	return send_req(a, umad, len, IB_MAD_METHOD_GET, comp_mask, data);
}

struct gid_list {
	ibmad_gid_t gid;
	uint64_t trid;
};

static int recv_all(struct addr_data *a, void *umad, int len)
{
	uint8_t *mad;
	uint64_t trid;
	unsigned n, method, status;

	info("%s...\n", __func__);

	n = 0;
	while (recv_res(a, umad, len) > 0) {
		dbg("%s: done %d\n", __func__, n);
		n++;
		mad = umad_get_mad(umad);

		method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
		status = mad_get_field(mad, 0, IB_MAD_STATUS_F);

		if (status) {
			trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
			info("mad trid 0x%016" PRIx64
			     ": method = %x status = %x.\n",
			     trid, method, status);
		}
	}

	info("%s: got %u responses\n", __func__, n);

	return 0;
}

static int rereg_port(struct addr_data *a, uint8_t * umad, int len,
		      ibmad_gid_t mgid, struct gid_list *list,
		      uint64_t comp_mask, uint8_t data[])
{
	if (send_leave(a, umad, len, mgid, list->gid, comp_mask, data))
		return -1;

	if (send_join(a, umad, len, mgid, list->gid, comp_mask, data))
		return -1;

	list->trid = mad_get_field64(umad_get_mad(umad), 0, IB_MAD_TRID_F);

	return 0;
}

static int rereg_recv_all(struct addr_data *a, void *umad, int len,
			  ibmad_gid_t mgid,
			  struct gid_list *list, unsigned cnt,
			  uint64_t comp_mask, uint8_t data[])
{
	uint8_t *mad;
	uint64_t trid;
	unsigned n, method, status;
	int i;

	info("%s...\n", __func__);

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
			     get_guid_ho(list[i].gid), method, status);
			rereg_port(a, umad, len, mgid, &list[i],
				   comp_mask, data);
		}
	}

	info("%s: got %u responses\n", __func__, n);

	return 0;
}

static int rereg_query_all(struct addr_data *a, void *umad, int len,
			   ibmad_gid_t mgid,
			   struct gid_list *list, unsigned cnt,
			   uint64_t comp_mask, uint8_t data[])
{
	uint8_t *mad;
	unsigned method, status;
	int i, ret;

	info("%s...\n", __func__);

	for (i = 0; i < cnt; i++) {
		ret = send_query(a, umad, len, mgid, list[i].gid,
				 comp_mask, data);
		if (ret < 0) {
			err("%s: rereg_send failed.\n", __func__);
			continue;
		}

		ret = recv_res(a, umad, len);
		if (ret < 0) {
			err("%s: recv_res failed.\n", __func__);
			continue;
		}

		mad = umad_get_mad(umad);

		method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
		status = mad_get_field(mad, 0, IB_MAD_STATUS_F);

		if (status)
			info("guid 0x%016" PRIx64 ": status %x, method %x\n",
			     get_guid_ho(list[i].gid), status, method);
	}

	info("%s: %u queried.\n", __func__, cnt);

	return 0;
}

/* tests framework */

struct test_data {
	unsigned gids_size;
	struct gid_list *gids;
	unsigned mgids_size;
	struct gid_list *mgids;
	const struct mcmember_params *params;
};

#define MAX_CLIENTS 100

static int run_port_rereg_test(struct addr_data *a, struct test_data *td)
{
	uint8_t data[256];
	uint64_t comp_mask;
	uint8_t *umad;
	int len = 256;
	int cnt, i, n, size = td->gids_size;

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}

	if (!td->params)
		td->params = &mcmember_params_join;

	comp_mask = build_mcm_rec(data, td->params);

	for (cnt = size; cnt;) {
		n = cnt > MAX_CLIENTS ? MAX_CLIENTS : cnt;
		for (i = 0; i < n; i++) {
			rereg_port(a, umad, len, td->mgids[0].gid,
				   &td->gids[size - cnt + i], comp_mask, data);
			info("%s: sent %u requests\n", __func__, n * 2);
		}
		rereg_recv_all(a, umad, len, td->mgids[0].gid, td->gids, size,
			       comp_mask, data);
		cnt -= i;
	}

	rereg_query_all(a, umad, len, td->mgids[0].gid, td->gids, size,
			comp_mask, data);

	free(umad);

	return 0;
}

static int run_mcast_member_test(struct addr_data *a, struct test_data *td,
				 int (*func)(struct addr_data *a,
					     uint8_t * umad, int len,
					     ibmad_gid_t mgid, ibmad_gid_t gid,
					     uint64_t comp_mask, uint8_t *data))
{
	uint8_t data[256];
	uint64_t comp_mask;
	uint8_t *umad;
	int len = 256;
	unsigned i, j;

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}

	comp_mask = build_mcm_rec(data, td->params);

	for (i = 0; i < td->gids_size; i++)
		for (j = 0; j < td->mgids_size; j++)
			if (func(a, umad, len, td->mgids[j].gid,
				 td->gids[i].gid, comp_mask, data))
				return -1;

	if (recv_all(a, umad, len) < 0)
		return -1;

	free(umad);

	return 0;
}

static int run_mcast_joins_test(struct addr_data *a, struct test_data *td)
{
	if (!td->params)
		td->params = &mcmember_params_create;
	return run_mcast_member_test(a, td, send_join);
}

static int run_mcast_leave_test(struct addr_data *a, struct test_data *td)
{
	if (!td->params)
		td->params = &mcmember_params_join;
	return run_mcast_member_test(a, td, send_leave);
}

/* main stuff */

struct test {
	const char *name;
	int (*func)(struct addr_data *, struct test_data *);
	const char *description;
};

static int run_test(const struct test *t, struct test_data *td,
		    struct ibmad_port *mad_port)
{
	struct addr_data addr;
	int ret;

	info("Running \'%s\'...\n", t->name);

	ib_resolve_smlid_via(&addr.dport, TMO, mad_port);
	if (!addr.dport.lid) {
		/* dport.lid = 1; */
		err("No SM. Exit.\n");
		exit(1);
	}
	addr.dport.qp = 1;
	if (!addr.dport.qkey)
		addr.dport.qkey = IB_DEFAULT_QP1_QKEY;

	addr.port = mad_rpc_portid(mad_port);
	addr.agent = umad_register(addr.port, IB_SA_CLASS, 2, 0, NULL);
	addr.timeout = TMO;

	ret = t->func(&addr, td);

	umad_unregister(addr.port, addr.agent);
	umad_close_port(addr.port);
	umad_done();

	info("\'%s\' %s.\n", t->name, ret ? "failed" : "is done");

	return ret;
}

static void make_gid(ibmad_gid_t gid, uint64_t prefix, uint64_t guid)
{
	prefix = ntohll(prefix);
	guid = ntohll(guid);
	memcpy(&gid[0], &prefix, 8);
	memcpy(&gid[8], &guid, 8);
}

static int make_gids_list(ibmad_gid_t gid, unsigned n, struct gid_list **gid_list)
{
	struct gid_list *list = NULL;
	uint64_t guid, prefix;
	unsigned i;

	list = calloc(1 + n, sizeof(list[0]));
	if (!list) {
		err("cannot alloc mem for guid/trid list: %s\n",
		    strerror(errno));
		return -1;
	}

	memcpy(&prefix, &gid[0], 8);
	prefix = ntohll(prefix);
	memcpy(&guid, &gid[8], 8);
	guid = ntohll(guid);

	for (i = 0; i <= n; i++)
		make_gid(list[i].gid, prefix, guid++);

	*gid_list = list;

	return i;
}

static int parse_gid_str(ibmad_gid_t gid, char *str, uint64_t default_prefix)
{
	uint64_t guid, prefix = 0;
	char *p, *e;

	p = str;
	while (isspace(*p))
		p++;
	e = strchr(p, '\n');
	if (e) {
		while (isspace(*e))
			*e-- = '\0';
	}

	if (*p == '\0' || *p == '#')
		return 1;

	if (inet_pton(AF_INET6, p, gid) > 0)
		return 0;

	e = strchr(p, ':');
	if (e) {
		prefix = strtoull(p, NULL, 0);
		guid = strtoull(e + 1, NULL, 0);
	} else if (strlen(p) > 18) {
		e = p + strlen(p) - 16;
		guid = strtoull(e, NULL, 16);
		*e = '\0';
		prefix = strtoull(p, NULL, 0);
	} else
		guid = strtoull(p, NULL, 0);

	if (!guid)
		return -1;

	if (!prefix)
		prefix = default_prefix;

	make_gid(gid, prefix, guid);

	return 0;
}

static int parse_gids_file(const char *guid_file, struct gid_list **gid_list)
{
	char line[256];
	ibmad_gid_t gid;
	FILE *f;
	struct gid_list *list = NULL;
	unsigned list_size = 0;
	int i = 0;

	f = fopen(guid_file, "r");
	if (!f) {
		fprintf(stderr, "cannot fopen \'%s\' %s\n",
			guid_file, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (parse_gid_str(gid, line, DEFAULT_PREFIX))
			continue;

		if (i >= list_size) {
			list_size += 256;
			list = realloc(list, list_size * sizeof(list[0]));
			if (!list) {
				err("cannot alloc mem for guid/trid list: %s\n",
				    strerror(errno));
				return -1;
			}
			memset(&list[i], 0, 256 * sizeof(list[0]));
		}

		memcpy(list[i].gid, gid, 16);
		i++;
	}
	fclose(f);

	*gid_list = list;

	return i;
}

static void make_str_opts(char *p, unsigned size, const struct option *o)
{
	int i, n = 0;

	for (n = 0; o->name  && n + 2 + o->has_arg < size; o++) {
		p[n++] = o->val;
		for (i = 0; i < o->has_arg; i++)
			p[n++] = ':';
	}
	p[n] = '\0';
}

static const struct test *find_test(const struct test *t, const char *name)
{
	int len = strlen(name);

	for (; t->name; t++)
		if (!strncasecmp(name, t->name, len))
			return t;

	return NULL;
}

static void usage(char *prog, const struct option *o, const struct test *t)
{
	printf("Usage: %s [options] <test>\n", prog);

	printf("\n, where <test> could be:\n");
	for (; t->name; t++)
		printf("\t%s - %s\n", t->name, t->description ? t->description : "");
	printf("\n, and [options] could be:\n");
	for (; o->name; o++)
		printf("\t--%s (-%c)\n", o->name, o->val);

	printf("\n");

	exit(2);
}

int main(int argc, char **argv)
{
	const struct option long_opts [] = {
		{"guidfile", 1, 0, 'g'},
		{"mgidfile", 1, 0, 'm'},
		{"GUID", 1, 0, 'G'},
		{"MGID", 1, 0, 'M'},
		{"ipv4", 0, 0, 'i'},
		{"increment", 1, 0, 'I'},
		{"qkey", 1, 0, 'q'},
		{"mlid", 1, 0, 'z'},
		{"mtu", 1, 0, 'y'},
		{"tclass", 1, 0, 't'},
		{"pkey", 1, 0, 'p'},
		{"rate", 1, 0, 'r'},
		{"sl", 1, 0, 's'},
		{"flowlabel", 1, 0, 'f'},
		{"joinstate", 1, 0, 'j'},
		{"proxy", 0, 0, 'x'},
		{"version", 0, 0, 'V'},
		{"verbose", 0, 0, 'v'},
		{"help", 0, 0, 'h'},
		{}
	};
	const struct test tests[] = {
		{"rereg", run_port_rereg_test, "simulates port reregistration"},
		{"joins", run_mcast_joins_test, "run a lot of join requests"},
		{"leave", run_mcast_leave_test, "run a lot of leave requests"},
		{0}
	};

	char opt_str[256];
	int mgmt_classes[2] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS };
	struct mcmember_params params;
	struct test_data tdata;
	ibmad_gid_t gid, mgid = {};
	uint64_t guid = 0;
	const char *guid_file = NULL, *mgid_file = NULL;
	struct ibmad_port *mad_port;
	const struct test *t;
	unsigned is_mgid = 0, is_ipv4 = 1, increment = 0;
	int ret, ch;

	params = null_params;

	make_str_opts(opt_str, sizeof(opt_str), long_opts);

	while ((ch = getopt_long(argc, argv, opt_str, long_opts, NULL)) != -1) {
		switch (ch) {
		case 'G':
			guid = strtoull(optarg, NULL, 0);
			break;
		case 'M':
			if (parse_gid_str(mgid, optarg, DEFAULT_MGID_PREFIX)) {
				err("cannot parse MGID \'%s\'", optarg);
				exit(2);
			}
			is_mgid = 1;
			break;
		case 'I':
			increment = strtoul(optarg, NULL, 0);
			break;
		case 'g':
			guid_file = optarg;
			break;
		case 'm':
			mgid_file = optarg;
			break;
		case 'q':
			params.qkey = strtoul(optarg, NULL, 0);
			break;
		case 'z':
			params.mlid = strtoul(optarg, NULL, 0);
			break;
		case 'y':
			params.mtu = strtoul(optarg, NULL, 0);
			break;
		case 't':
			params.tclass = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			params.pkey = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			params.rate = strtoul(optarg, NULL, 0);
			break;
		case 's':
			params.sl = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			params.flow_label = strtoul(optarg, NULL, 0);
			break;
		case 'j':
			params.join_state = strtoul(optarg, NULL, 0);
			break;
		case 'x':
			params.proxy_join = 1;
			break;
		case 'v':
			break;
		case 'V':
			printf("%s version %s\n", argv[0], "0.1");
			exit(0);
		case 'h':
		default:
			usage(argv[0], long_opts, tests);
			break;
		}
	}

	mad_port = mad_rpc_open_port(NULL, 0, mgmt_classes, 2);
	if (!mad_port) {
		err("Cannot open local port...\n");
		exit(-1);
	}

	memset(&tdata, 0, sizeof(tdata));

	if (guid) {
		make_gid(gid, DEFAULT_PREFIX, guid);
		ret = make_gids_list(gid, increment, &tdata.gids);
	} else if (guid_file) {
		ret = parse_gids_file(guid_file, &tdata.gids);
		guid = get_guid_ho(tdata.gids[0].gid);
	} else {
		ib_portid_t portid = {0};
		if (ib_resolve_self_via(&portid, NULL, &gid, mad_port) < 0) {
			err("Cannot resolve self port...\n");
			exit(1);
		}
		guid = get_guid_ho(gid);
		ret = make_gids_list(gid, increment, &tdata.gids);
	}

	if (ret < 0)
		return ret;
	tdata.gids_size = ret;

	if (is_mgid)
		ret = make_gids_list(mgid, increment, &tdata.mgids);
	else if (mgid_file)
		ret = parse_gids_file(mgid_file, &tdata.mgids);
	else if (is_ipv4)
		ret = make_gids_list(mgid_ipoib, increment, &tdata.mgids);
	else {
		make_gid(gid, DEFAULT_MGID_PREFIX, guid);
		ret = make_gids_list(gid, increment, &tdata.mgids);
	}

	if (ret < 0)
		return ret;
	tdata.mgids_size = ret;

	if (memcmp(&params, &null_params, sizeof(params)))
		tdata.params = &params;

	if (argc <= optind)
		return run_test(&tests[0], &tdata, mad_port);

	do {
		t = find_test(tests, argv[optind]);
		if (!t)
			usage(argv[0], long_opts, tests);
		ret = run_test(t, &tdata, mad_port);
		if (ret)
			break;
	} while (argc > ++optind);

	if (tdata.gids)
		free(tdata.gids);
	if (tdata.mgids)
		free(tdata.mgids);

	mad_rpc_close_port(mad_port);

	return ret;
}
