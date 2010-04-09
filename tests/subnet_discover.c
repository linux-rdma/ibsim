/*
 * Copyright (c) 2009 Voltaire, Inc. All rights reserved.
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
#include <getopt.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

#define MAX_HOPS 63

struct port {
	struct node *node;
	uint64_t guid;
	struct port *remote;
	uint8_t port_info[IB_SMP_DATA_SIZE];
};

struct node {
	uint64_t guid;
	unsigned num_ports;
	unsigned is_switch;
	size_t path_size;
	uint8_t path[64];
	uint8_t node_info[IB_SMP_DATA_SIZE];
	uint8_t node_desc[IB_SMP_DATA_SIZE];
	uint8_t switch_info[IB_SMP_DATA_SIZE];
	struct port ports[];
};

static struct node *node_array[32 * 1024];
static unsigned node_count = 0;
static unsigned trid_cnt = 0;
static unsigned outstanding = 0;
static unsigned max_outstanding = 8;
static unsigned timeout = 100;
static unsigned retries = 3;
static unsigned verbose = 0;

static unsigned total_mads = 0;
static unsigned max_hops = 0;

#define ERROR(fmt, ...) fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)
#define VERBOSE(fmt, ...) if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__)
#define VERBOSE1(fmt, ...) if (verbose > 1) fprintf(stderr, fmt, ##__VA_ARGS__)
#define VERBOSE2(fmt, ...) if (verbose > 2) fprintf(stderr, fmt, ##__VA_ARGS__)
#define NOISE(fmt, ...) VERBOSE2(fmt, ##__VA_ARGS__)

static const char *print_path(uint8_t path[], size_t path_cnt)
{
	static char buf[256];
	int i, n = 0;
	for (i = 0; i <= path_cnt; i++)
		n += snprintf(buf + n, sizeof(buf) - n, "%u,", path[i]);
	buf[n] = '\0';
	return buf;
}

#define DBG_DUMP_FUNC(name) static void dbg_dump_##name(void *data) \
{ \
	char buf[2048]; \
	mad_dump_##name(buf, sizeof(buf), data, IB_SMP_DATA_SIZE); \
	NOISE("### "#name":\n%s\n", buf); \
}

DBG_DUMP_FUNC(nodeinfo);
DBG_DUMP_FUNC(nodedesc);
DBG_DUMP_FUNC(portinfo);
DBG_DUMP_FUNC(switchinfo);

static void build_umad_req(void *umad, uint8_t path[], unsigned path_cnt,
			   uint64_t trid, uint8_t method,
			   uint16_t attr_id, uint32_t attr_mod, uint64_t mkey)
{
	void *mad = umad_get_mad(umad);

	memset(umad, 0, umad_size() + IB_MAD_SIZE);
	umad_set_addr(umad, 0xffff, 0, 0, 0);
	mad_set_field(mad, 0, IB_MAD_METHOD_F, method);
	mad_set_field(mad, 0, IB_MAD_CLASSVER_F, 1);
	mad_set_field(mad, 0, IB_MAD_MGMTCLASS_F, IB_SMI_DIRECT_CLASS);
	mad_set_field(mad, 0, IB_MAD_BASEVER_F, 1);
	mad_set_field(mad, 0, IB_DRSMP_HOPCNT_F, path_cnt);
	mad_set_field(mad, 0, IB_DRSMP_HOPPTR_F, 0);
	mad_set_field64(mad, 0, IB_MAD_TRID_F, trid);
	mad_set_field(mad, 0, IB_DRSMP_DRDLID_F, 0xffff);
	mad_set_field(mad, 0, IB_DRSMP_DRSLID_F, 0xffff);
	mad_set_array(mad, 0, IB_DRSMP_PATH_F, path);
	mad_set_field(mad, 0, IB_MAD_ATTRID_F, attr_id);
	mad_set_field(mad, 0, IB_MAD_ATTRMOD_F, attr_mod);
	mad_set_field64(mad, 0, IB_MAD_MKEY_F, mkey);
}

static int send_request(int fd, int agent, uint64_t trid, uint8_t * path,
			size_t path_cnt, uint16_t attr_id, uint32_t attr_mod)
{
	uint8_t umad[IB_MAD_SIZE + umad_size()];
	int ret;

	build_umad_req(umad, path, path_cnt, trid, IB_MAD_METHOD_GET, attr_id,
		       attr_mod, 0);

	ret = umad_send(fd, agent, umad, IB_MAD_SIZE, timeout, retries);
	if (ret < 0) {
		ERROR("umad_send failed: trid 0x%016" PRIx64
		      ", attr_id %x, attr_mod %x: %s\n",
		      trid, attr_id, attr_mod, strerror(errno));
		return -1;
	}

	VERBOSE1("send %016" PRIx64 ": attr %x, mod %x to %s\n", trid, attr_id,
		 attr_mod, print_path(path, path_cnt));

	return ret;
}

static struct request_queue {
	struct request_queue *next;
	uint64_t trid;
	uint16_t attr_id;
	uint32_t attr_mod;
	size_t path_cnt;
	uint8_t path[0];
} request_queue;

static struct request_queue *request_last = &request_queue;

static unsigned tr_table_size;
static struct request_queue **tr_table;

static void add_to_tr_table(struct request_queue *q, uint64_t trid)
{
	unsigned n = trid >> 16;
	if (n >= tr_table_size) {
		unsigned new_size = tr_table_size ? tr_table_size * 2 : 4096;
		if (n > new_size)
			new_size = n + 1;
		tr_table = realloc(tr_table, new_size * sizeof(tr_table[0]));
		if (!tr_table) {
			ERROR("cannot realloc request table\n");
			tr_table_size = 0;
			return;
		}
		memset(tr_table + tr_table_size, 0,
		       (new_size - tr_table_size) * sizeof(tr_table[0]));
		tr_table_size = new_size;
	}

	tr_table[n] = q;
}

static void clean_from_tr_table(uint64_t trid)
{
	unsigned n = (trid >> 16) & 0xffff;
	if (n >= tr_table_size) {
		ERROR("invalid request table index %u\n", n);
		return;
	}
	free(tr_table[n]);
	tr_table[n] = NULL;
}

static void free_unresponded()
{
	struct request_queue *q;
	unsigned i;

	for (i = 0 ; i < tr_table_size; i++) {
		if (!(q = tr_table[i]))
			continue;
		fprintf(stderr, "Unresponded transaction %016" PRIx64 ": %s "
			"attr_id %x, attr_mod %x\n", q->trid,
			print_path(q->path, q->path_cnt), q->attr_id,
			q->attr_mod);
		free(q);
	}
}

static void run_request_queue(int fd, int agent)
{
	struct request_queue *q = request_queue.next;

	while (q) {
		if (outstanding >= max_outstanding)
			break;
		if (send_request(fd, agent, q->trid, q->path, q->path_cnt,
				 q->attr_id, q->attr_mod) < 0)
			break;
		q = q->next;
		outstanding++;
		total_mads++;
	}
	request_queue.next = q;
	if (!q)
		request_last = &request_queue;
}

static int queue_request(uint64_t trid, uint8_t * path, size_t path_cnt,
			 uint16_t attr_id, uint32_t attr_mod)
{
	struct request_queue *q = malloc(sizeof(*q) + path_cnt + 1);
	if (!q)
		return -1;
	q->next = NULL;
	q->trid = trid;
	q->attr_id = attr_id;
	q->attr_mod = attr_mod;
	memcpy(q->path, path, path_cnt + 1);
	q->path_cnt = path_cnt;

	request_last->next = q;
	request_last = q;

	add_to_tr_table(q, trid);

	return 0;
}

static int send_query(int fd, int agent, unsigned node_id, uint8_t path[],
		      size_t path_cnt, uint16_t attr_id, uint32_t attr_mod)
{
	uint64_t trid;
	int ret;

	trid = (trid_cnt++ << 16) | (node_id & 0xffff);

	ret = queue_request(trid, path, path_cnt, attr_id, attr_mod);
	if (ret < 0) {
		ERROR("queue failed: trid 0x%016" PRIx64 ", attr_id %x,"
		      " attr_mod %x\n", trid, attr_id, attr_mod);
		return -1;
	}

	VERBOSE1("queue %016" PRIx64 ": attr %x, mod %x to %s\n", trid, attr_id,
		 attr_mod, print_path(path, path_cnt));

	run_request_queue(fd, agent);

	return ret;
}

static int recv_response(int fd, int agent, uint8_t * umad, size_t length)
{
	int len = length, ret;

	do {
		ret = umad_recv(fd, umad, &len, timeout);
	} while (ret >= 0 && ret != agent);

	if (ret < 0 || umad_status(umad)) {
		ERROR("umad_recv failed: umad status %x: %s\n",
		      umad_status(umad), strerror(errno));
		return len > umad_size() ? 1 : -1;
	}

	return 0;
}

static int query_node_info(int fd, int agent, unsigned node_id,
			   uint8_t path[], size_t path_cnt)
{
	return send_query(fd, agent, node_id, path, path_cnt,
			  IB_ATTR_NODE_INFO, 0);
}

static int query_node_desc(int fd, int agent, unsigned node_id,
			   uint8_t path[], size_t path_cnt)
{
	return send_query(fd, agent, node_id, path, path_cnt,
			  IB_ATTR_NODE_DESC, 0);
}

static int query_switch_info(int fd, int agent, unsigned node_id,
			     uint8_t path[], size_t path_cnt)
{
	return send_query(fd, agent, node_id, path, path_cnt,
			  IB_ATTR_SWITCH_INFO, 0);
}

static int query_port_info(int fd, int agent, unsigned node_id,
			   uint8_t path[], size_t path_cnt, unsigned port_num)
{
	return send_query(fd, agent, node_id, path, path_cnt,
			  IB_ATTR_PORT_INFO, port_num);
}

static int add_node(uint8_t * node_info, uint8_t path[], size_t path_size)
{
	struct node *node;
	unsigned i, num_ports = mad_get_field(node_info, 0, IB_NODE_NPORTS_F);

	node = malloc(sizeof(*node) + (num_ports + 1) * sizeof(node->ports[0]));
	if (!node)
		return -1;
	memset(node, 0,
	       sizeof(*node) + (num_ports + 1) * sizeof(node->ports[0]));

	node->num_ports = num_ports;
	node->guid = mad_get_field64(node_info, 0, IB_NODE_GUID_F);
	node->is_switch = ((mad_get_field(node_info, 0, IB_NODE_TYPE_F)) ==
			   IB_NODE_SWITCH);
	memcpy(node->path, path, path_size + 1);
	node->path_size = path_size;
	memcpy(node->node_info, node_info, sizeof(node->node_info));
	for (i = 0; i <= num_ports; i++)
		node->ports[i].node = node;

	node_array[node_count] = node;

	return node_count++;
}

static int find_node(uint8_t * node_info)
{
	uint64_t guid = mad_get_field64(node_info, 0, IB_NODE_GUID_F);
	unsigned i;

	for (i = 0; i < node_count; i++)
		if (node_array[i]->guid == guid)
			return i;
	return -1;
}

static int process_port_info(void *umad, unsigned node_id, int fd, int agent,
			     uint8_t path[], size_t path_cnt)
{
	struct node *node = node_array[node_id];
	struct port *port;
	uint8_t *port_info = umad + umad_size() + IB_SMP_DATA_OFFS;
	unsigned port_num, local_port;

	dbg_dump_portinfo(port_info);

	port_num = mad_get_field(umad_get_mad(umad), 0, IB_MAD_ATTRMOD_F);
	local_port = mad_get_field(port_info, 0, IB_PORT_LOCAL_PORT_F);

	port = &node->ports[port_num];
	memcpy(port->port_info, port_info, sizeof(port->port_info));

	if (port_num &&
	    mad_get_field(port_info, 0, IB_PORT_PHYS_STATE_F) == 5 &&
	    ((node->is_switch && port_num != local_port) ||
	     (node_id == 0 && port_num == local_port)) &&
	    path_cnt++ < MAX_HOPS) {
		if (path_cnt > max_hops)
			max_hops = path_cnt;
		path[path_cnt] = port_num;
		return query_node_info(fd, agent, node_id, path, path_cnt);
	}

	return 0;
}

static int process_switch_info(unsigned node_id, uint8_t * switch_info)
{
	struct node *node = node_array[node_id];

	dbg_dump_switchinfo(switch_info);
	memcpy(node->switch_info, switch_info, sizeof(node->switch_info));

	return 0;
}

static int process_node_desc(unsigned node_id, uint8_t * node_desc)
{
	struct node *node = node_array[node_id];

	dbg_dump_nodedesc(node_desc);
	memcpy(node->node_desc, node_desc, sizeof(node->node_desc));

	return 0;
}

static void connect_ports(unsigned node1_id, unsigned port1_num,
			  unsigned node2_id, unsigned port2_num)
{
	struct port *port1 = &node_array[node1_id]->ports[port1_num];
	struct port *port2 = &node_array[node2_id]->ports[port2_num];
	VERBOSE1("connecting %u:%u <--> %u:%u\n",
		 node1_id, port1_num, node2_id, port2_num);
	port1->remote = port2;
	port2->remote = port1;
}

static int process_node(void *umad, unsigned remote_id, int fd, int agent,
			uint8_t path[], size_t path_cnt)
{
	struct node *node;
	uint8_t *node_info = umad_get_mad(umad) + IB_SMP_DATA_OFFS;
	unsigned port_num = mad_get_field(node_info, 0, IB_NODE_LOCAL_PORT_F);
	unsigned node_is_new = 0;
	int i, id;

	dbg_dump_nodeinfo(node_info);

	if ((id = find_node(node_info)) < 0) {
		id = add_node(node_info, path, path_cnt);
		if (id < 0)
			return -1;
		node_is_new = 1;
	}

	node = node_array[id];

	VERBOSE("%-5s %-6s with guid 0x%" PRIx64 " discovered at %s\n",
		node_is_new ? "new" : "known",
		node->is_switch ? "Switch" : "Ca", node->guid,
		print_path(path, path_cnt));

	node->ports[port_num].guid =
	    mad_get_field64(node_info, 0, IB_NODE_PORT_GUID_F);

	if (id)			/* skip connect for very first node */
		connect_ports(id, port_num, remote_id, path[path_cnt]);

	if (!node_is_new)
		return 0;

	query_node_desc(fd, agent, id, path, path_cnt);

	if (node->is_switch)
		query_switch_info(fd, agent, id, path, path_cnt);

	for (i = !node->is_switch; i <= node->num_ports; i++)
		query_port_info(fd, agent, id, path, path_cnt, i);

	return 0;
}

static int recv_smp_resp(int fd, int agent, uint8_t * umad, uint8_t path[])
{
	void *mad;
	uint64_t trid;
	uint8_t method;
	uint16_t status;
	uint16_t attr_id;
	uint32_t attr_mod;
	size_t path_cnt;
	unsigned node_id;
	int ret;

	ret = recv_response(fd, agent, umad, IB_MAD_SIZE);

	mad = umad_get_mad(umad);
	status = mad_get_field(mad, 0, IB_DRSMP_STATUS_F);
	method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
	trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
	attr_id = mad_get_field(mad, 0, IB_MAD_ATTRID_F);
	attr_mod = mad_get_field(mad, 0, IB_MAD_ATTRMOD_F);
	path_cnt = mad_get_field(mad, 0, IB_DRSMP_HOPCNT_F);
	mad_get_array(mad, 0, IB_DRSMP_PATH_F, path);

	if (method != IB_MAD_METHOD_GET)
		return 0;

	outstanding--;
	run_request_queue(fd, agent);

	if (ret < 0)
		return ret;
	else if (ret || status) {
		ERROR("error response 0x%016" PRIx64 ": attr_id %x"
		      ", attr_mod %x from %s with status %x\n", trid,
		      attr_id, attr_mod, print_path(path, path_cnt), status);
		return -1;
	}

	clean_from_tr_table(trid);

	node_id = trid & 0xffff;

	VERBOSE1("recv %016" PRIx64 ": attr %x, mod %x from %s\n", trid,
		 attr_id, attr_mod, print_path(path, path_cnt));

	switch (attr_id) {
	case IB_ATTR_NODE_INFO:
		process_node(umad, node_id, fd, agent, path, path_cnt);
		break;
	case IB_ATTR_NODE_DESC:
		process_node_desc(node_id, mad + IB_SMP_DATA_OFFS);
		break;
	case IB_ATTR_SWITCH_INFO:
		process_switch_info(node_id, mad + IB_SMP_DATA_OFFS);
		break;
	case IB_ATTR_PORT_INFO:
		process_port_info(umad, node_id, fd, agent, path, path_cnt);
		break;
	default:
		VERBOSE("unsolicited response 0x%016" PRIx64 ": attr_id %x"
			", attr_mod %x\n", trid, attr_id, attr_mod);
		return 0;
	}

	return ret;
}

static int discover(int fd, int agent)
{
	uint8_t umad[IB_MAD_SIZE + umad_size()];
	uint8_t path[64] = { 0 };
	int ret;

	ret = query_node_info(fd, agent, 0, path, 0);
	if (ret < 0)
		return ret;

	while (outstanding)
		if (recv_smp_resp(fd, agent, umad, path))
			ret = 1;

	free_unresponded();

	return ret;
}

static int umad_discover(char *card_name, unsigned int port_num)
{
	int fd, agent, ret;

	ret = umad_init();
	if (ret) {
		ERROR("cannot init umad\n");
		return -1;
	}

	fd = umad_open_port(card_name, port_num);
	if (fd < 0) {
		ERROR("cannot open umad port %s:%u: %s\n",
		      card_name ? card_name : "NULL", port_num,
		      strerror(errno));
		return -1;
	}

	agent = umad_register(fd, IB_SMI_DIRECT_CLASS, 1, 0, NULL);
	if (agent < 0) {
		ERROR("cannot register SMI DR class for umad port %s:%u: %s\n",
		      card_name ? card_name : "NULL", port_num,
		      strerror(errno));
		return -1;
	}

	ret = discover(fd, agent);
	if (ret)
		fprintf(stderr, "\nThere are problems during discovery.\n");

	umad_unregister(fd, agent);
	umad_close_port(fd);

	umad_done();

	return ret;
}

static void print_subnet()
{
	struct node *node;
	struct port *local, *remote;
	unsigned i, j;

	printf("\n# The subnet discovered using %u mads, reaching %d hops\n\n",
	       total_mads, max_hops);

	for (i = 0; i < node_count; i++) {
		node = node_array[i];
		printf("%s %u \"%s-%016" PRIx64 "\" \t# %s %s\n",
		       node->is_switch ? "Switch" : "Ca", node->num_ports,
		       node->is_switch ? "S" : "H", node->guid,
		       print_path(node->path, node->path_size), node->node_desc);
		for (j = 1; j <= node->num_ports; j++) {
			local = &node->ports[j];
			remote = local->remote;
			if (!remote)
				continue;
			printf("[%u] \t\"%s-%016" PRIx64 "\"[%lu] \t# %s\n", j,
			       remote->node->is_switch ? "S" : "H",
			       remote->node->guid, remote - remote->node->ports,
			       remote->node->node_desc);
		}
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	const struct option long_opts[] = {
		{"Card", 1, 0, 'C'},
		{"Port", 1, 0, 'P'},
		{"maxsmps", 1, 0, 'n'},
		{"timeout", 1, 0, 't'},
		{"retries", 1, 0, 'r'},
		{"verbose", 0, 0, 'v'},
		{"help", 0, 0, 'h'},
		{}
	};
	char *card_name = NULL;
	unsigned int port_num = 0;
	int ch, ret;

	while (1) {
		ch = getopt_long(argc, argv, "C:P:n:t:r:vh", long_opts, NULL);
		if (ch == -1)
			break;
		switch (ch) {
		case 'C':
			card_name = optarg;
			break;
		case 'P':
			port_num = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			max_outstanding = strtoul(optarg, NULL, 0);
			if (!max_outstanding)
				max_outstanding = -1;
			break;
		case 't':
			timeout = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			retries = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			printf("usage: %s [-C card_name] [-P port_num]"
			       " [-n maxsmps] [-t timeout] [-r retries]"
			       " [-v[v]]\n", argv[0]);
			exit(2);
			break;
		}
	}

	ret = umad_discover(card_name, port_num);

	print_subnet();

	return ret;
}
