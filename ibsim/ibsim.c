/*
 * Copyright (c) 2004-2008 Voltaire, Inc. All rights reserved.
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
#include <stdarg.h>
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
#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>

#include <ibsim.h>
#include "sim.h"

#define IBSIM_VERSION "0.5"

#undef DEBUG
#define PDEBUG	if (parsedebug) IBWARN
#define DEBUG	if (simverb > 1 || ibdebug) IBWARN
#define VERB	if (simverb || ibdebug) IBWARN

extern int maxnetnodes;
extern int maxnetswitches;
extern int maxnetports;
extern int maxlinearcap;
extern int maxmcastcap;
extern int maxnetaliases;
extern int ignoreduplicate;

int ibdebug;
int parsedebug;
int simverb;

static Client clients[IBSIM_MAX_CLIENTS];
static int simctl = -1;
static int maxfd;
static FILE *simout;
static int listen_to_port = IBSIM_DEFAULT_SERVER_PORT;
static int remote_mode = 0;
static char* socket_basename;

static size_t make_name(union name_t *name, uint32_t addr, unsigned short port,
			const char *fmt, ...)
{
	size_t size;
	memset(name, 0, sizeof(*name));
	if (remote_mode) {
		struct sockaddr_in *name_i = &name->name_i;
	        name_i->sin_family = AF_INET;
		name_i->sin_addr.s_addr = addr ? addr : htonl(INADDR_ANY);
	        name_i->sin_port = htons(port);
		size = sizeof(*name_i);
	} else {
		va_list args;
		struct sockaddr_un *name_u = &name->name_u;
		size = sizeof(*name_u) -
				((void *)name_u->sun_path + 1 - (void*)name_u);
		name_u->sun_family = AF_UNIX;
		name_u->sun_path[0] = 0;	// abstract name space
		va_start(args, fmt);
		size = vsnprintf(name_u->sun_path + 1, size, fmt, args);
		va_end(args);
		size += 1 + ((void *)name_u->sun_path + 1 - (void*)name_u);
	}
	return size;
}

static char *get_name(union name_t *name)
{
	if (remote_mode)
		return inet_ntoa(name->name_i.sin_addr);
	else
		return name->name_u.sun_path + 1;
}

/**
 * initialize the in/out connections
 *
 * @param basename base name for abstract namespace
 *
 * @return unix status
 */
static int sim_init_conn(char *basename)
{
	union name_t name;
	size_t size;
	int fd, i;

	DEBUG("initializing network connections (basename \"%s\")", basename);

	// create ctl channel
	fd = simctl = socket(remote_mode ? PF_INET : PF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		IBPANIC("can't create socket for ctl");
	if (maxfd < fd)
		maxfd = fd;

	size = make_name(&name, 0, listen_to_port, "%s:ctl", basename);

	if (bind(fd, (struct sockaddr *)&name, size) < 0)
		IBPANIC("can't bind socket %d to name %s",
			fd, get_name(&name));

	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		IBPANIC("can't set non blocking flags for ctl");

	for (i = 0; i < IBSIM_MAX_CLIENTS; i++) {
		fd = socket(remote_mode ? PF_INET : PF_LOCAL, SOCK_DGRAM, 0);
		if (fd < 0)
			IBPANIC("can't create socket for conn %d", i);
		if (maxfd < fd)
			maxfd = fd;

		size = make_name(&name, 0, listen_to_port + i + 1,
				 "%s:out%d", basename, i);
		if (bind(fd, (struct sockaddr *)&name, size) < 0)
			IBPANIC("can't bind socket %d to name %s",
				fd, get_name(&name));

		if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
			IBPANIC("can't set non blocking flags for "
			        "client conn %d", i);

		DEBUG("opening net connection fd %d %s", fd, get_name(&name));

		clients[i].fd = fd;
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

static int sim_ctl_new_client(Client * cl, struct sim_ctl * ctl, union name_t *from)
{
	union name_t name;
	size_t size;
	Node *node;
	struct sim_client_info *scl = (void *)ctl->data;
	int id = scl->id;
	int i;

	DEBUG("connecting client pid %d", id);

	// allocated free client
	for (i = 0; i < IBSIM_MAX_CLIENTS; i++) {
		cl = clients + i;
		if (!cl->pid)
			break;
	}

	if (i >= IBSIM_MAX_CLIENTS) {
		IBWARN("can't open new connection for client pid %d", id);
		ctl->type = SIM_CTL_ERROR;
		return -1;
	}

	if (scl->nodeid[0]) {
		if (!(node = find_node(scl->nodeid)) &&
		    !(node = find_node_by_desc(scl->nodeid))) {
			IBWARN("client %d attempt to attach to unknown host"
			       " \"%s\"", i, scl->nodeid);
			ctl->type = SIM_CTL_ERROR;
			return -1;
		}
		cl->port = node_get_port(node, 0);
		VERB("Attaching client %d at node \"%s\" port 0x%" PRIx64,
		     i, node->nodeid, cl->port->portguid);
	} else {
		VERB("Attaching client %d at default node \"%s\" port 0x%"
		     PRIx64, i, default_port->node->nodeid,
		     default_port->portguid);
		cl->port = default_port;
	}

	if (scl->issm && sm_exists(cl->port->node)) {
		IBWARN("client %d (pid %d) connection attempt failed:"
		       " SM already exists on \"%s\"",
		       i, id, cl->port->node->nodeid);
		ctl->type = SIM_CTL_ERROR;
		return -1;
	}

	size = make_name(&name, from->name_i.sin_addr.s_addr, id,
			 "%s:in%d", socket_basename, id);

	if (connect(cl->fd, (struct sockaddr *)&name, size) < 0)
		IBPANIC("can't connect to in socket %s - fd %d client pid %d",
			get_name(&name), cl->fd, id);

	cl->pid = id;
	cl->id = i;
	cl->qp = scl->qp;
	cl->issm = scl->issm;

	strncpy(scl->nodeid, cl->port->node->nodeid, sizeof(scl->nodeid) - 1);

	scl->id = i;

	DEBUG("client %d (%s) is connected - fd %d",
	      i, get_name(&name), cl->fd);

	return 1;
}

static int sim_ctl_disconnect_client(Client * cl, struct sim_ctl * ctl)
{
	int client = ctl->clientid;

	VERB("disconnecting client %d", client);
	if (client >= IBSIM_MAX_CLIENTS) {
		IBWARN("no connection for client %d", client);
		ctl->type = SIM_CTL_ERROR;
		return -1;
	}
	if (!cl->pid) {
		DEBUG("client %d is not connected", client);
		return 0;	// ?
	}

	DEBUG("Detaching client %d from node \"%s\" port 0x%" PRIx64,
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

static void set_issm(Port *port, unsigned issm)
{
	uint32_t old_capmask, capmask;

	capmask = mad_get_field(port->portinfo, 0, IB_PORT_CAPMASK_F);
	old_capmask = capmask;
	if (issm)
		capmask |= CAPMASK_ISSM;
	else
		capmask &= ~CAPMASK_ISSM;
	mad_set_field(port->portinfo, 0, IB_PORT_CAPMASK_F, capmask);
	if (old_capmask != capmask && capmask&(CAPMASK_ISNOTICE|CAPMASK_ISTRAP)
	    && capmask&CAPMASK_ISCAPMASKTRAP)
		send_trap(port, TRAP_144);
}

static int sim_ctl_set_issm(Client * cl, struct sim_ctl * ctl)
{
	int issm = *(int *)ctl->data;

	VERB("set issm %d port %" PRIx64, issm, cl->port->portguid);
	cl->issm = issm;
	set_issm(cl->port, issm);

	return 0;
}

static int sim_ctl_get_pkeys(Client * cl, struct sim_ctl * ctl)
{
	Port *port = cl->port;
	unsigned size = (port->node->sw && port->portnum) ?
	    mad_get_field(port->node->sw->switchinfo, 0,
			  IB_SW_PARTITION_ENFORCE_CAP_F) :
	    mad_get_field(port->node->nodeinfo, 0, IB_NODE_PARTITION_CAP_F);

	size *= sizeof(port->pkey_tbl[0]);
	if (size > sizeof(ctl->data))
		size = sizeof(ctl->data);
	memcpy(ctl->data, port->pkey_tbl, size);
	if (size < sizeof(ctl->data))
		memset(ctl->data + size, 0, sizeof(ctl->data) - size);
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
	union name_t from;
	socklen_t addrlen = sizeof from;
	struct sim_ctl ctl = { 0 };
	Client *cl;

	if (recvfrom(fd, &ctl, sizeof(ctl), 0, (struct sockaddr *)&from,
		     &addrlen) != sizeof(struct sim_ctl))
		return -1;

	DEBUG("perform ctl type %d for client %s (%d)",
	      ctl.type, get_name(&from), ctl.clientid);

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
		sim_ctl_new_client(cl, &ctl, &from);
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

	case SIM_CTL_GET_PKEYS:
		sim_ctl_get_pkeys(cl, &ctl);
		break;

	default:
	case SIM_CTL_ERROR:
		IBWARN("bad ctl pkt type %d", ctl.type);
	}

	if (sendto(fd, &ctl, sizeof ctl, 0, (struct sockaddr *)&from,
		   addrlen) != sizeof ctl) {
		IBWARN("cannot response ctl: %m");
		return -1;
	}

	return 0;
}

static int sim_read_pkt(int fd, int client)
{
	char buf[512];
	Client *cl = clients + client, *dcl;
	int size, ret;

	if (client >= IBSIM_MAX_CLIENTS || !cl->pid) {
		IBWARN("pkt from unconnected client %d?!", client);
		return -1;
	}
	for (;;) {
		if ((size = read(fd, buf, sizeof(buf))) <= 0)
			return size;

		if ((size = process_packet(cl, buf, size, &dcl)) < 0) {
			IBWARN("process packet error - discarded");
			continue;	// not a network error
		}

		if (!dcl)
			continue;

		VERB("%s %d bytes (%zu) to client %d fd %d",
		     dcl == cl ? "replying" : "forwarding",
		     size, sizeof(struct sim_request), dcl->id, dcl->fd);

		// reply
		do {
			ret = write(dcl->fd, buf, size);
		} while ((errno == EAGAIN) && (ret == -1));
			 
		if (ret == size)
			return 0;

		if (ret < 0 && (errno == ECONNREFUSED || errno == ENOTCONN)) {
			IBWARN("client %u seems to be dead - disconnecting.",
			       dcl->id);
			disconnect_client(dcl->id);
		}
		IBWARN("write failed: %m - pkt dropped");
		if (dcl != cl) { /* reply timeout */
			struct sim_request *r = (struct sim_request *)buf;
			r->status = htonl(110);
			ret = write(cl->fd, buf, size);
		}
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

	if (set_default_port(NULL) < 0)
		return -3;

	return 0;
}

static int sim_init_console(FILE *out)
{
	simout = out;

	fprintf(simout, "########################\n");
	fprintf(simout, "Network simulator ready.\n");
	fprintf(simout, "MaxNetNodes    = %d\n", maxnetnodes);
	fprintf(simout, "MaxNetSwitches = %d\n", maxnetswitches);
	fprintf(simout, "MaxNetPorts    = %d\n", maxnetports);
	fprintf(simout, "MaxLinearCap   = %d\n", maxlinearcap);
	fprintf(simout, "MaxMcastCap    = %d\n", maxmcastcap);
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

	socket_basename=getenv("IBSIM_SOCKNAME");
	if(!socket_basename)
		socket_basename = SIM_BASENAME;

	if (sim_init_conn(socket_basename) < 0)
		return -1;

	while (!netstarted)
		sim_run_console(con_fd);

	for (;;) {
		FD_ZERO(&rfds);
		FD_SET(simctl, &rfds);
		FD_SET(con_fd, &rfds);
		for (i = 0; i < IBSIM_MAX_CLIENTS; i++)
			if (clients[i].pid)
				FD_SET(clients[i].fd, &rfds);

		if (select(maxfd + 1, &rfds, NULL, NULL, 0) < 0)
			break;	// timeout or error

		if (FD_ISSET(simctl, &rfds))
			sim_ctl(simctl);

		for (i = 0; i < IBSIM_MAX_CLIENTS; i++)
			if (clients[i].pid && FD_ISSET(clients[i].fd, &rfds))
				sim_read_pkt(clients[i].fd, i);

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
			", lid %u, qp %d %s\n", i, clients[i].pid,
			clients[i].port->node->nodeid,
			clients[i].port->portguid, clients[i].port->lid,
			clients[i].qp, clients[i].issm ? "SM" : "");
	}
	return 0;
}

int disconnect_client(int id)
{
	if (id < 0 || id >= IBSIM_MAX_CLIENTS || !clients[id].pid)
		return -1;
	clients[id].pid = 0;
	if (clients[id].issm)
		set_issm(clients[id].port, 0);
	return 0;
}

static Client *client_by_trid(Port *port, uint64_t trid)
{
	unsigned i = (unsigned)(trid >> 48);
	if (i < IBSIM_MAX_CLIENTS && clients[i].pid &&
	    clients[i].port->portguid == port->portguid)
		return &clients[i];
	return NULL;
}

Client *find_client(Port * port, int response, int qp, uint64_t trid)
{
	Client *cl, *e;

	DEBUG("port %" PRIx64 " res %d qp %d trid %" PRIx64,
	      port->portguid, response, qp, trid);
	// response - match trids
	if (response && (cl = client_by_trid(port, trid)))
		return cl;
	for (cl = clients, e = cl + IBSIM_MAX_CLIENTS; cl < e; cl++) {
		if (!cl->pid || cl->port->portguid != port->portguid)
			continue;
		// if there is a non zero/1 qp (sma/sa) - match qps
		if (qp > 1) {
			if (qp == cl->qp)
				return cl;
		// zero qp - only issm clients may get requests
		} else if (!response && cl->issm)
			return cl;
	}
	DEBUG("no client found");
	return 0;
}

void usage(char *prog_name)
{
	fprintf(stderr,
		"Usage: %s [-f outfile -d(ebug) -p(arse_debug) -s(tart) -v(erbose) "
		"-I(gnore_duplicate) -N nodes -S switchs -P ports -L linearcap"
		" -M mcastcap -r(emote_mode) -l(isten_to_port) <port>] <netfile>\n",
		prog_name);
	fprintf(stderr, "%s %s\n", prog_name, IBSIM_VERSION);

	exit(-1);
}

int main(int argc, char **argv)
{
	extern int alloc_core(void);
	extern void free_core(void);
	char *outfname = 0, *netfile;
	FILE *infile, *outfile;
	int status;

	static char const str_opts[] = "rf:dpvIsN:S:P:L:M:l:Vhu";
	static const struct option long_opts[] = {
		{"remote", 0, 0, 'r'},
		{"file", 1, 0, 'f'},
		{"Nodes", 1, 0, 'N'},
		{"Switches", 1, 0, 'S'},
		{"Ports", 1, 0, 'P'},
		{"Linearcap", 1, 0, 'L'},
		{"Mcastcap", 1, 0, 'M'},
	        {"listen", 1, 0, 'l'},
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
		case 'r':
			remote_mode = 1;
			break;
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
			maxnetswitches = strtoul(optarg, 0, 0);
			break;
		case 'P':
			maxnetports = strtoul(optarg, 0, 0);
			break;
		case 'L':
			maxlinearcap = strtoul(optarg, 0, 0);
			break;
		case 'M':
			maxmcastcap = strtoul(optarg, 0, 0);
			break;
	        case 'l':
			listen_to_port = strtoul(optarg, 0, 0);
			break;
		case 'V':
		default:
			usage(argv[0]);
		}
	}

	maxnetaliases = maxnetports;

	infile = stdin;
	outfile = stdout;
	if (outfname && (outfile = fopen(outfname, "w")) == 0)
		IBPANIC("can't open out file %s for write", outfname);

	if (optind >= argc)
		usage(argv[0]);

	netfile = argv[optind];

	if (alloc_core() < 0)
		IBPANIC("not enough memory for core structure");

	DEBUG("initializing net \"%s\"", netfile);
	status = sim_init_net(netfile, outfile);
	if (status < 0)
		IBPANIC("sim_init failed, status %d", status);

	sim_init_console(outfile);

	sim_run(fileno(infile));

	free_core();

	exit(0);
}
