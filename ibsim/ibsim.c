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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <getopt.h>
#include <inttypes.h>

#include <ibsim.h>
#include "sim.h"

#undef DEBUG
#define PDEBUG	if (parsedebug) IBWARN
#define DEBUG	if (simverb > 1 || ibdebug) IBWARN
#define VERB	if (simverb || ibdebug) IBWARN

int ibdebug;
int parsedebug;
int simverb;

int netcon[IBSIM_MAX_CLIENTS];
Client clients[IBSIM_MAX_CLIENTS];
int simctl = -1;
int maxfd;
FILE *simout;
char *simnetfile;

extern int maxnetnodes;
extern int maxnetswitchs;
extern int maxnetports;
extern int maxlinearcap;
extern int maxnetaliases;
extern int ignoreduplicate;

/**
 * initialize the in/out connections
 *
 * @param basename base name for abstract namespace
 *
 * @return unix status
 */
static int sim_init_conn(char *basename)
{
	struct sockaddr_un name;
	int fd, i;

	DEBUG("initializing network connections (basename \"%s\")", basename);

	memset(&name, 0, sizeof(name));
	name.sun_family = AF_UNIX;
	name.sun_path[0] = 0;	// abstract name space

	// create ctl channel
	fd = simctl = socket(PF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		IBPANIC("can't create socket for ctl");
	if (maxfd < fd)
		maxfd = fd;

	sprintf(name.sun_path + 1, "%s:ctl", basename);
	if (bind(fd, (struct sockaddr *)&name, sizeof(name)) < 0)
		IBPANIC("can't bind socket %d to name %s",
			fd, name.sun_path + 1);

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		IBPANIC("can't set non blocking flags for ctl");

	for (i = 0; i < IBSIM_MAX_CLIENTS; i++) {
		fd = netcon[i] = socket(PF_LOCAL, SOCK_DGRAM, 0);
		if (fd < 0)
			IBPANIC("can't create socket for conn %d", i);
		if (maxfd < fd)
			maxfd = fd;

		memset(name.sun_path, 0, sizeof(name.sun_path));
		sprintf(name.sun_path + 1, "%s:out%d", basename, i);
		if (bind(fd, (struct sockaddr *)&name, sizeof(name)) < 0)
			IBPANIC("can't bind socket %d to name %s",
				fd, name.sun_path + 1);

		if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
			IBPANIC("can't set non blocking flags for "
			        "client conn %d", i);

		DEBUG("opening net connection fd %d %s", fd, name.sun_path + 1);
	}
	return 0;
}

static int sm_exists(Node * node)
{
	Client *cl, *e;

	for (cl = clients, e = cl + IBSIM_MAX_CLIENTS; cl < e; cl++) {
		if (!cl->pid)
			continue;
		if (cl->port->node != node)
			continue;
		if (cl->issm)
			return 1;
	}
	return 0;
}

static int sim_ctl_new_client(Client * cl, struct sim_ctl * ctl)
{
	struct sockaddr_un name;
	Node *node;
	struct sim_client_info *scl = (void *)ctl->data;
	int id = scl->id;
	int i, fd = -1;

	DEBUG("connecting client pid %d", id);

	// allocated free client
	for (i = 0; i < IBSIM_MAX_CLIENTS; i++) {
		cl = clients + i;
		if (!cl->pid)
			break;
	}

	if (i >= IBSIM_MAX_CLIENTS || (fd = netcon[i]) <= 0) {
		IBWARN("can't open new connection for client pid %d", id);
		ctl->type = SIM_CTL_ERROR;
		return -1;
	}

	if (scl->nodeid[0]) {
		if (!(node = find_node(scl->nodeid))) {
			IBWARN("client %d attempt to attach to unknown host"
			       " \"%s\"", i, scl->nodeid);
			ctl->type = SIM_CTL_ERROR;
			return -1;
		}
		cl->port = node_get_port(node, 0);
		VERB("Attaching client %d at node \"%s\"/port 0x%" PRIx64,
		     i, node->nodeid, cl->port->portguid);
	} else {
		VERB("Attaching client %d at default node \"%s\"/port 0x%"
		     PRIx64, i, defport->node->nodeid, defport->portguid);
		cl->port = defport;
	}

	if (scl->issm && sm_exists(cl->port->node)) {
		IBWARN("client %d (pid %d) connection attempt failed:"
		       " SM already exists on \"%s\"",
		       i, id, cl->port->node->nodeid);
		ctl->type = SIM_CTL_ERROR;
		return -1;
	}

	memset(&name, 0, sizeof(name));
	name.sun_family = AF_UNIX;
	name.sun_path[0] = 0;	// abstract name space

	sprintf(name.sun_path + 1, "%s:in%d", SIM_BASENAME, id);

	if (connect(fd, (struct sockaddr *)&name, sizeof(name)) < 0)
		IBPANIC("can't connect to in socket %s - fd %d client pid %d",
			name.sun_path + 1, fd, id);

	cl->pid = id;
	cl->id = i;
	cl->qp = scl->qp;
	cl->issm = scl->issm;
	cl->outfd = fd;

	strncpy(scl->nodeid, cl->port->node->nodeid, sizeof(scl->nodeid) - 1);

	scl->id = i;
	DEBUG("client %d (%s) is connected - fd %d", i, name.sun_path + 1, fd);

	return 1;
}

static int sim_ctl_disconnect_client(Client * cl, struct sim_ctl * ctl)
{
	int client = ctl->clientid;
	int fd = -1;

	VERB("disconnecting client %d", client);
	if (client >= IBSIM_MAX_CLIENTS || (fd = netcon[client]) <= 0) {
		IBWARN("no connection for client %d", client);
		ctl->type = SIM_CTL_ERROR;
		return -1;
	}
	if (!cl->pid) {
		DEBUG("client %d is not connected", client);
		return 0;	// ?
	}

	DEBUG("Detaching client %d from node \"%s\"/port 0x%" PRIx64,
	      client, cl->port->node->nodeid, cl->port->portguid);
	cl->pid = 0;
	return 0;
}

static int sim_ctl_get_port(Client * cl, struct sim_ctl * ctl)
{
	struct sim_port *p = (void *)ctl->data;

	p->lid = cl->port->lid;
	p->state = cl->port->state;
	return 0;
}

static int sim_ctl_get_gid(Client * cl, struct sim_ctl * ctl)
{
	char *gid = (void *)ctl->data;

	mad_get_array(cl->port->portinfo, 0, IB_PORT_GID_PREFIX_F, gid);
	memcpy(gid + 8, &cl->port->node->nodeguid, 8);
	return 0;
}

static int sim_ctl_get_guid(Client * cl, struct sim_ctl * ctl)
{
	char *guid = (void *)ctl->data;

	memcpy(guid, &cl->port->node->nodeguid, 8);
	return 0;
}

static int sim_ctl_get_nodeinfo(Client * cl, struct sim_ctl * ctl)
{
	memcpy(ctl->data, cl->port->node->nodeinfo, sizeof(ctl->data));
	return 0;
}

static int sim_ctl_get_portinfo(Client * cl, struct sim_ctl * ctl)
{
	Port *p;
	uint8_t port_num = ctl->data[0];
	if (port_num == 0 || port_num > cl->port->node->numports)
		p = cl->port;
	else if (cl->port->node->type == SWITCH_NODE)
		p = node_get_port(cl->port->node, port_num);
	else
		p = node_get_port(cl->port->node, port_num - 1);
	update_portinfo(p);
	memcpy(ctl->data, p->portinfo, sizeof(ctl->data));
	return 0;
}

#define CAPMASK_ISSM	(1<<1)

static int sim_ctl_set_issm(Client * cl, struct sim_ctl * ctl)
{
	int issm = *(int *)ctl->data;
	uint32_t capmask;

	VERB("set issm %d port %" PRIx64, issm, cl->port->portguid);
	capmask = mad_get_field(cl->port->portinfo, 0, IB_PORT_CAPMASK_F);
	if (issm)
		capmask |= CAPMASK_ISSM;
	else
		capmask &= ~CAPMASK_ISSM;
	mad_set_field(cl->port->portinfo, 0, IB_PORT_CAPMASK_F, capmask);
	cl->issm = issm;
	return 0;
}

static int sim_ctl_get_vendor(Client * cl, struct sim_ctl * ctl)
{
	struct sim_vendor *v = (void *)ctl->data;

	v->vendor_id =
	    mad_get_field(cl->port->node->nodeinfo, 0, IB_NODE_VENDORID_F);
	v->vendor_part_id =
	    mad_get_field(cl->port->node->nodeinfo, 0, IB_NODE_DEVID_F);
	v->hw_ver =
	    mad_get_field(cl->port->node->nodeinfo, 0, IB_NODE_REVISION_F);
	v->fw_ver = 1;
	return 0;
}

static int sim_ctl(int fd)
{
	struct sockaddr_un from;
	socklen_t addrlen = sizeof from;
	struct sim_ctl ctl = { 0 };
	Client *cl;

	if (recvfrom(fd, &ctl, sizeof(ctl), 0, (struct sockaddr *)&from,
		     &addrlen) != sizeof(struct sim_ctl))
		return -1;

	DEBUG("perform ctl type %d for client %s (%d)",
	      ctl.type, from.sun_path + 1, ctl.clientid);

	if (ctl.magic != SIM_MAGIC) {
		IBWARN("bad control pkt: magic %x (%x)", ctl.magic, SIM_MAGIC);
		return -1;
	}

	if (ctl.clientid >= IBSIM_MAX_CLIENTS && ctl.type != SIM_CTL_CONNECT) {
		IBWARN("bad client id %d", ctl.clientid);
		ctl.type = SIM_CTL_ERROR;
		return -1;
	}

	cl = clients + ctl.clientid;

	switch (ctl.type) {
	case SIM_CTL_CONNECT:
		sim_ctl_new_client(cl, &ctl);
		break;

	case SIM_CTL_DISCONNECT:
		sim_ctl_disconnect_client(cl, &ctl);
		break;

	case SIM_CTL_GET_PORT:
		sim_ctl_get_port(cl, &ctl);
		break;

	case SIM_CTL_GET_VENDOR:
		sim_ctl_get_vendor(cl, &ctl);
		break;

	case SIM_CTL_GET_GID:
		sim_ctl_get_gid(cl, &ctl);
		break;

	case SIM_CTL_GET_GUID:
		sim_ctl_get_guid(cl, &ctl);
		break;

	case SIM_CTL_GET_NODEINFO:
		sim_ctl_get_nodeinfo(cl, &ctl);
		break;

	case SIM_CTL_GET_PORTINFO:
		sim_ctl_get_portinfo(cl, &ctl);
		break;

	case SIM_CTL_SET_ISSM:
		sim_ctl_set_issm(cl, &ctl);
		break;

	default:
	case SIM_CTL_ERROR:
		IBWARN("bad ctl pkt type %d", ctl.type);
	}

	if (sendto(fd, &ctl, sizeof ctl, 0, (struct sockaddr *)&from,
		   sizeof from) != sizeof ctl) {
		IBWARN("cannot response ctl: %m");
		return -1;
	}

	return 0;
}

static int sim_read_pkt(int fd, int client)
{
	char buf[512];
	Client *cl = clients + client, *dcl;
	int size;

	if (client >= IBSIM_MAX_CLIENTS || !cl->pid) {
		IBWARN("pkt from unconnected client %d?!", client);
		return -1;
	}
	for (;;) {
		if ((size = read(fd, buf, sizeof(buf))) <= 0)
			return size;

		if ((size = process_packet(cl, buf, size, &dcl)) < 0) {
			IBWARN("process packet error - discarded.");
			continue;	// not a network error
		}

		if (!dcl)
			continue;

		VERB("%s %d bytes (%zu) to client %d fd %d",
		     dcl == cl ? "replying" : "forwarding",
		     size, sizeof(struct sim_request), dcl->id, dcl->outfd);

		// reply
		if (write(dcl->outfd, buf, size) == size)
			return 0;
		IBWARN("write failed: %m - pkt dropped");
	}

	return -1;		// never reached
}

int sim_cmd_file(FILE * f, char *s)
{
	char line[4096];
	FILE *cmd_file;
	char *p;

	s++;
	while (isspace(*s))
		s++;

	if (!s || !*s) {
		fprintf(f, "do_cmd_from_file: no file name - skip\n");
		return -1;
	}

	p = s + strlen(s) - 1;
	while (isspace(*p)) {
		*p = '\0';
		p--;
	}

	cmd_file = fopen(s, "r");
	if (!cmd_file) {
		fprintf(f, "do_cmd_from_file: cannot open file \'%s\': %s\n",
			s, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line) - 1, cmd_file) != NULL) {
		do_cmd(line, f);
	}

	fclose(cmd_file);
	return 0;
}

static int sim_init_net(char *netconf, FILE * out)
{
	DEBUG("reading %s", netconf);
	if (read_netconf(netconf, out) < 0)
		return -1;

	if (connect_ports() < 0)
		return -2;

	if (set_def(0) < 0)
		return -3;

	return 0;
}

static int sim_init_console(FILE *out)
{
	simout = out;

	fprintf(simout, "########################\n");
	fprintf(simout, "Network simulator ready.\n");
	fprintf(simout, "MaxNetNodes    = %d\n", maxnetnodes);
	fprintf(simout, "MaxNetSwitches = %d\n", maxnetswitchs);
	fprintf(simout, "MaxNetPorts    = %d\n", maxnetports);
	fprintf(simout, "MaxLinearCap   = %d\n", maxlinearcap);
	fprintf(simout, "sim%s> ", netstarted ? "" : " (inactive)");
	fflush(simout);
	return 0;
}

static int sim_run_console(int fd)
{
	char line[128];
	int ret = 0;

	ret = readline(fd, line, sizeof(line) - 1);
	if (ret <= 0)
		return ret;

	do_cmd(line, simout);
	fprintf(simout, "sim%s> ", netstarted ? "" : " (inactive)");
	fflush(simout);

	return 0;
}

static int sim_run(int con_fd)
{
	fd_set rfds;
	int i;

	if (sim_init_conn(SIM_BASENAME) < 0)
		return -1;

	while (!netstarted)
		sleep(2);

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(simctl, &rfds);
		FD_SET(con_fd, &rfds);
		for (i = 0; i < IBSIM_MAX_CLIENTS; i++)
			if (clients[i].pid)
				FD_SET(netcon[i], &rfds);

		if (select(maxfd, &rfds, NULL, NULL, 0) < 0)
			break;	// timeout or error

		if (FD_ISSET(simctl, &rfds))
			sim_ctl(simctl);

		for (i = 0; i < IBSIM_MAX_CLIENTS; i++)
			if (clients[i].pid && FD_ISSET(netcon[i], &rfds))
				sim_read_pkt(netcon[i], i);

		if (FD_ISSET(con_fd, &rfds))
			sim_run_console(con_fd);
	}

	return 0;
}

int list_connections(FILE * out)
{
	int i;

	for (i = 0; i < IBSIM_MAX_CLIENTS; i++) {
		if (!clients[i].pid)
			continue;
		fprintf(out,
			"Client %d: pid %d connected at \"%s\" port 0x%" PRIx64
			", lid %d, qp %d %s\n", i, clients[i].pid,
			clients[i].port->node->nodeid,
			clients[i].port->portguid, clients[i].port->lid,
			clients[i].qp, clients[i].issm ? "SM" : "");
	}
	return 0;
}

int disconnect_client(FILE * out, int id)
{
	if (id < 0 || id >= IBSIM_MAX_CLIENTS) {
		fprintf(out, "disconnect client: bad clientid %d\n", id);
		return -1;
	}
	clients[id].pid = 0;
	return 0;
}

Client *find_client(Port * port, int response, int qp, uint64_t trid)
{
	Client *cl, *e;

	if (port)
		DEBUG("port %" PRIx64 " res %d qp %d trid %" PRIx64,
		      port->portguid, response, qp, trid);
	for (cl = clients, e = cl + IBSIM_MAX_CLIENTS; cl < e; cl++) {
		if (!cl->pid)
			continue;
		if (cl->port->portguid != port->portguid)
			continue;
		// if there is a non zero/1 qp (sma/sa) - match qps
		if (qp > 1 && qp == cl->qp)
			return cl;
		if (qp > 1)
			continue;
		// zero qp - only issm clients may get requests
		if (!response && cl->issm)
			return cl;
		// response - match trids
		if (response && trid == cl->trid)
			return cl;
	}
	DEBUG("no client found");
	return 0;
}

void usage(char *prog_name)
{
	fprintf(stderr,
		"Usage: %s [-f outfile -d debug_level -p parse_debug -s(tart) -v(erbose) "
		"-I(gnore_duplicate) -N nodes -S switchs -P ports -L linearcap] <netfile>\n",
		prog_name);
	fprintf(stderr, "%s %s\n", prog_name, get_build_version());

	exit(-1);
}

int main(int argc, char **argv)
{
	extern int alloc_core(void);
	char *outfname = 0, *netfile;
	FILE *outfile;

	static char const str_opts[] = "f:dpvIsN:S:P:L:Vhu";
	static const struct option long_opts[] = {
		{"file", 1, 0, 'f'},
		{"Nodes", 1, 0, 'N'},
		{"Switches", 1, 0, 'S'},
		{"Ports", 1, 0, 'P'},
		{"Linearcap", 1, 0, 'L'},
		{"Ignoredups", 0, 0, 'I'},
		{"start", 0, 0, 's'},
		{"debug", 0, 0, 'd'},
		{"parsedebug", 0, 0, 'p'},
		{"verbose", 0, 0, 'v'},
		{"Version", 0, 0, 'V'},
		{"help", 0, 0, 'h'},
		{"usage", 0, 0, 'u'},
		{}
	};

	while (1) {
		int ch = getopt_long(argc, argv, str_opts, long_opts, NULL);
		if (ch == -1)
			break;
		switch (ch) {
		case 'f':
			outfname = optarg;
			break;
		case 'd':
			ibdebug++;
			break;
		case 'p':
			parsedebug++;
			break;
		case 'v':
			simverb++;
			break;
		case 's':
			netstarted = 1;
			break;
		case 'I':
			ignoreduplicate = 1;
			break;
		case 'N':
			maxnetnodes = strtoul(optarg, 0, 0);
			break;
		case 'S':
			maxnetswitchs = strtoul(optarg, 0, 0);
			break;
		case 'P':
			maxnetports = strtoul(optarg, 0, 0);
			break;
		case 'L':
			maxlinearcap = strtoul(optarg, 0, 0);
			break;
		case 'V':
		default:
			usage(argv[0]);
		}
	}

	maxnetaliases = maxnetports;

	outfile = stdout;
	if (outfname && (outfile = fopen(outfname, "w")) == 0)
		IBPANIC("can't open out file %s for write", outfname);

	if (optind >= argc)
		usage(argv[0]);

	netfile = argv[optind];

	if (alloc_core() < 0)
		IBPANIC("not enough memory for core structure");

	DEBUG("initializing net \"%s\"", netfile);
	if (sim_init_net(netfile, outfile) < 0)
		IBPANIC("sim_init failed");

	sim_init_console(outfile);

	sim_run(0);

	exit(0);
}
