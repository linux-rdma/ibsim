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

static int send_create(struct addr_data *a, uint8_t * umad, int len,
		      ibmad_gid_t mgid, ibmad_gid_t port_gid)
{
	uint8_t data[IB_SA_DATA_SIZE];
	uint64_t comp_mask;

	comp_mask = build_mcm_create_rec(data, mgid, port_gid, 1);

	return send_req(a, umad, len, IB_MAD_METHOD_SET, comp_mask, data);
}

struct gid_list {
	ibmad_gid_t gid;
	uint64_t trid;
};

static int rereg_port(struct addr_data *a, uint8_t * umad, int len,
		      struct gid_list *list)
{
	if (rereg_send(a, umad, len, IB_MAD_METHOD_DELETE, list->gid))
		return -1;

	if (rereg_send(a, umad, len, IB_MAD_METHOD_SET, list->gid))
		return -1;
	list->trid = mad_get_field64(umad_get_mad(umad), 0, IB_MAD_TRID_F);

	return 0;
}

static int rereg_send_all(struct addr_data *a,
			  struct gid_list *list, unsigned cnt)
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
			  struct gid_list *list, unsigned cnt)
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
			     get_guid_ho(list[i].gid), method, status);
			rereg_port(a, umad, len, &list[i]);
		}
	}

	info("rereg_recv_all: got %u responses\n", n);

	free(umad);
	return 0;
}

static int rereg_query_all(struct addr_data *a,
			   struct gid_list *list, unsigned cnt)
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
			     get_guid_ho(list[i].gid), status, method);
	}

	info("rereg_query_all: %u queried.\n", cnt);

	free(umad);
	return 0;
}

/* tests framework */

struct test_data {
	unsigned gids_size;
	struct gid_list *gids;
	unsigned mgids_size;
	struct gid_list *mgids;
};

#define MAX_CLIENTS 100

static int run_port_rereg_test(struct addr_data *a, struct test_data *td)
{
	int cnt, i, size = td->gids_size;

	for (cnt = size; cnt;) {
		i = cnt > MAX_CLIENTS ? MAX_CLIENTS : cnt;
		rereg_send_all(a, td->gids + (size - cnt), i);
		rereg_recv_all(a, td->gids, size);
		cnt -= i;
	}

	rereg_query_all(a, td->gids, size);

	return 0;
}

static int run_mcast_joins_test(struct addr_data *a, struct test_data *td)
{
	uint8_t *umad;
	int len = 256;
	unsigned status;

	info("%s...\n", __func__);

	umad = calloc(1, len + umad_size());
	if (!umad) {
		err("cannot alloc mem for umad: %s\n", strerror(errno));
		return -1;
	}

	if (send_create(a, umad, len, td->mgids[0].gid, td->gids[0].gid))
		return -1;

	status = mad_get_field(umad_get_mad(umad), 0, IB_MAD_STATUS_F);
	if (status)
		err("1 create MAD status %x\n", status);

	if (recv_res(a, umad, len) < 0)
		return -1;

	status = mad_get_field(umad_get_mad(umad), 0, IB_MAD_STATUS_F);
	if (status)
		err("2 create MAD status %x\n", status);

	free(umad);

	return 0;
}

/* main stuff */

struct test {
	const char *name;
	int (*func)(struct addr_data *, struct test_data *);
	const char *description;
};

static int run_test(const struct test *t, struct test_data *td)
{
	int mgmt_classes[2] = { IB_SMI_CLASS, IB_SMI_DIRECT_CLASS };
	struct addr_data addr;
	int ret;

	info("Running \'%s\'...\n", t->name);

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

static int parse_gids_file(const char *guid_file, struct gid_list **gid_list)
{
	char line[256];
	FILE *f;
	uint64_t guid, prefix;
	struct gid_list *list = NULL;
	char *e;
	unsigned list_size = 0;
	int i = 0;

	f = fopen(guid_file, "r");
	if (!f) {
		fprintf(stderr, "cannot fopen \'%s\' %s\n",
			guid_file, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		guid = strtoull(line, &e, 0);
		if (e && isxdigit(*e)) {
			prefix = guid;
			guid = strtoull(line, NULL, 0);
		} else
			prefix = DEFAULT_PREFIX;

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

		make_gid(list[i].gid, prefix, guid);
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
		{"increment", 1, 0, 'I'},
		{"version", 0, 0, 'V'},
		{"verbose", 0, 0, 'v'},
		{"help", 0, 0, 'h'},
		{}
	};
	const struct test tests[] = {
		{"rereg", run_port_rereg_test, "simulates port reregistration"},
		{"joins", run_mcast_joins_test, "run a single (yet) join"},
		{0}
	};

	char opt_str[256];
	struct test_data tdata;
	ibmad_gid_t gid, mgid = {};
	uint64_t guid = 0;
	const char *guid_file = NULL, *mgid_file = NULL;
	const struct test *t;
	unsigned is_mgid = 0, increment = 0;
	int ret, ch;


	make_str_opts(opt_str, sizeof(opt_str), long_opts);

	while ((ch = getopt_long(argc, argv, opt_str, long_opts, NULL)) != -1) {
		switch (ch) {
		case 'G':
			guid = strtoull(optarg, NULL, 0);
			break;
		case 'M':
			{ char *e; uint64_t val1, val2;
			val1 = strtoull(optarg, &e, 0);
			val2 = strtoull(e, NULL, 0);
			make_gid(mgid, val1, val2);
			is_mgid = 1;
			}
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

	memset(&tdata, 0, sizeof(tdata));

	if (guid) {
		make_gid(gid, DEFAULT_PREFIX, guid);
		ret = make_gids_list(gid, increment, &tdata.gids);
	} else if (guid_file)
		ret = parse_gids_file(guid_file, &tdata.gids);
	else {
		err("Unkown port guid(s) - use -G or -g option...\n");
		usage(argv[0], long_opts, tests);
		return -1;
	}

	if (ret < 0)
		return ret;
	tdata.gids_size = ret;

	if (is_mgid)
		ret = make_gids_list(mgid, increment, &tdata.mgids);
	else if (mgid_file)
		ret = parse_gids_file(mgid_file, &tdata.mgids);
	else
		ret = make_gids_list(mgid_ipoib, increment, &tdata.mgids);

	if (ret < 0)
		return ret;
	tdata.mgids_size = ret;

	if (argc <= optind)
		return run_test(&tests[0], &tdata);

	do {
		t = find_test(tests, argv[optind]);
		if (!t)
			usage(argv[0], long_opts, tests);
		ret = run_test(t, &tdata);
		if (ret)
			break;
	} while (argc > ++optind);

	if (tdata.gids)
		free(tdata.gids);
	if (tdata.mgids)
		free(tdata.mgids);

	return ret;
}
