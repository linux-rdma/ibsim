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
#include <sys/time.h>

#include <infiniband/umad.h>
#include <infiniband/mad.h>

static unsigned number_queries = 1;
static uint8_t dr_path[64];
static size_t dr_path_size = 0;
static uint16_t attribute_id = IB_ATTR_NODE_INFO;
static uint32_t attribute_mod = 0;

static unsigned timeout = 100;
static unsigned retries = 3;
static unsigned verbose = 0;

#define ERROR(fmt, ...) fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__)
#define VERBOSE(fmt, ...) if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__)
#define NOISE(fmt, ...) if (verbose > 1) fprintf(stderr, fmt, ##__VA_ARGS__)

static const char *print_path(uint8_t path[], size_t path_cnt)
{
	static char buf[256];
	int i, n = 0;
	for (i = 0; i <= path_cnt; i++)
		n += snprintf(buf + n, sizeof(buf) - n, "%u,", path[i]);
	buf[n] = '\0';
	return buf;
}

static size_t parse_direct_path(const char *str, uint8_t path[], size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		path[i] = strtoul(str, NULL, 0);
		str = strchr(str, ',');
		if (!str)
			break;
		str++;
	}

	return i;
}

static void build_umad_req(void *umad, uint8_t * path, unsigned path_cnt,
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

static void check_diff(const char *name, void *mad,
		       struct timeval *tv1, struct timeval *tv)
{
	unsigned long diff = (tv1->tv_sec - tv->tv_sec) * 1000000 +
	    tv1->tv_usec - tv->tv_usec;

	if (diff > 1000) {
		uint8_t path[256];
		uint8_t method = mad_get_field(mad, 0, IB_MAD_METHOD_F);
		uint64_t trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
		uint16_t attr_id = mad_get_field(mad, 0, IB_MAD_ATTRID_F);
		uint32_t attr_mod = mad_get_field(mad, 0, IB_MAD_ATTRMOD_F);
		size_t path_cnt = mad_get_field(mad, 0, IB_DRSMP_HOPCNT_F);
		mad_get_array(mad, 0, IB_DRSMP_PATH_F, path);
		printf("LONG %s (%lu) %016" PRIx64 ": method %x, attr %x,"
		       " mod %x, path %s\n", name, diff, trid, method,
		       attr_id, attr_mod, print_path(path, path_cnt));
		fflush(stdout);
	}
}

static int send_query(int fd, int agent, void *umad, uint64_t trid,
		      uint8_t * path, size_t path_cnt, uint16_t attr_id,
		      uint32_t attr_mod)
{
	struct timeval tv, tv1;
	int ret;

	build_umad_req(umad, path, path_cnt, trid, IB_MAD_METHOD_GET, attr_id,
		       attr_mod, 0);

	gettimeofday(&tv, NULL);

	ret = umad_send(fd, agent, umad, IB_MAD_SIZE, timeout, retries);

	gettimeofday(&tv1, NULL);

	if (ret < 0) {
		ERROR("umad_send failed: trid 0x%016" PRIx64
		      ", attr_id %x, attr_mod %x: %s\n",
		      trid, attr_id, attr_mod, strerror(errno));
		return -1;
	}

	VERBOSE("send %016" PRIx64 ": attr %x, mod %x to %s\n", trid, attr_id,
		attr_mod, print_path(path, path_cnt));

	check_diff("SEND", umad_get_mad(umad), &tv1, &tv);

	return ret;
}

static int recv_response(int fd, int agent, uint8_t * umad, uint8_t path[])
{
	struct timeval tv, tv1;
	void *mad;
	uint64_t trid;
	uint32_t attr_mod;
	uint16_t attr_id, status;
	size_t path_size;
	int len = IB_MAD_SIZE, ret;

	gettimeofday(&tv, NULL);

	do {
		ret = umad_recv(fd, umad, &len, timeout);
	} while (ret >= 0 && ret != agent);

	gettimeofday(&tv1, NULL);

	if (ret < 0 || umad_status(umad)) {
		ERROR("umad_recv failed: umad status %x: %s\n",
		      umad_status(umad), strerror(errno));
		return -1;
	}

	check_diff("RESP", umad_get_mad(umad), &tv1, &tv);

	mad = umad_get_mad(umad);
	status = mad_get_field(mad, 0, IB_DRSMP_STATUS_F);
	trid = mad_get_field64(mad, 0, IB_MAD_TRID_F);
	attr_id = mad_get_field(mad, 0, IB_MAD_ATTRID_F);
	attr_mod = mad_get_field(mad, 0, IB_MAD_ATTRMOD_F);
	path_size = mad_get_field(mad, 0, IB_DRSMP_HOPCNT_F);
	mad_get_array(mad, 0, IB_DRSMP_PATH_F, path);

	if (status) {
		ERROR("error response 0x%016" PRIx64 ": attr_id %x"
		      ", attr_mod %x from %s with status %x\n", trid,
		      attr_id, attr_mod, print_path(path, path_size), status);
		return -1;
	}

	VERBOSE("recv %016" PRIx64 ": attr %x, mod %x from %s\n", trid, attr_id,
		attr_mod, print_path(path, path_size));

	return ret;
}

static int query(int fd, int agent)
{
	uint8_t path[64] = { 0 };
	uint64_t trid = 0x20090000;
	void *umad;
	unsigned n = 0;
	int ret = 0;

	umad = malloc(IB_MAD_SIZE + umad_size());
	if (!umad)
		return -ENOMEM;

	while (n++ < number_queries)
		send_query(fd, agent, umad, trid++, dr_path, dr_path_size,
			   attribute_id, attribute_mod);

	n = 0;
	do {
		ret = recv_response(fd, agent, umad, path);
	} while (ret >= 0 && ++n < number_queries);

	free(umad);

	return ret;
}

static int umad_query(char *card_name, unsigned int port_num)
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

	ret = query(fd, agent);
	if (ret)
		ERROR("Failed.\n");

	umad_unregister(fd, agent);
	umad_close_port(fd);

	umad_done();

	return ret;
}

int main(int argc, char **argv)
{
	const struct option long_opts[] = {
		{"number", 1, 0, 'n'},
		{"drpath", 1, 0, 'd'},
		{"attribute", 1, 0, 'a'},
		{"modifier", 1, 0, 'm'},
		{"Card", 1, 0, 'C'},
		{"Port", 1, 0, 'P'},
		{"timeout", 1, 0, 't'},
		{"retries", 1, 0, 'r'},
		{}
	};
	char *card_name = NULL;
	unsigned int port_num = 0;
	int ch, ret;

	while (1) {
		ch = getopt_long(argc, argv, "n:d:a:m:C:P:t:r:v", long_opts, NULL);
		if (ch == -1)
			break;
		switch (ch) {
		case 'n':
			number_queries = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			dr_path_size = parse_direct_path(optarg, dr_path,
							 sizeof(dr_path));
			break;
		case 'a':
			attribute_id = strtoul(optarg, NULL, 0);
			break;
		case 'm':
			attribute_mod = strtoul(optarg, NULL, 0);
			break;
		case 'C':
			card_name = optarg;
			break;
		case 'P':
			port_num = strtoul(optarg, NULL, 0);
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
		default:
			printf("Usage: %s [-n num_queries] [-d path]"
			       " [-a attr] [-m mod]"
			       " [-C card_name] [-P port_num]"
			       " [-t timeout] [-r retries] [-v[v]]\n", argv[0]);
			exit(2);
			break;
		}
	}

	ret = umad_query(card_name, port_num);

	return ret;
}
