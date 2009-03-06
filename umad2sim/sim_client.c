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
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <infiniband/mad.h>

#include <ibsim.h>

#include "sim_client.h"

#ifdef SIM_CLIENT_NOISY_DEBUG
#undef DEBUG
#define DEBUG	IBWARN
#else
#define DEBUG(fmt...)
#endif

static unsigned int remote_mode = 0;
static char* socket_basename;

static int sim_ctl(struct sim_client *sc, int type, void *data, int len)
{
	struct sim_ctl ctl;

	DEBUG("type %d len %d", type, len);

	memset(&ctl, 0, sizeof(ctl));

	if (sc->fd_ctl < 0) {
		IBWARN("no ctl connection");
		return -1;
	}

	ctl.magic = SIM_MAGIC;
	ctl.type = type;
	ctl.clientid = sc->clientid;
	ctl.len = len;
	if (len)
		memcpy(ctl.data, data, len);

	if (write(sc->fd_ctl, &ctl, sizeof(ctl)) != sizeof(ctl)) {
		IBWARN("ctl failed(write)");
		return -1;
	}

	ctl.type = SIM_CTL_ERROR;

	if (read(sc->fd_ctl, &ctl, sizeof(ctl)) != sizeof(ctl)) {
		IBWARN("ctl failed(read)");
		return -1;
	}

	if (ctl.type == SIM_CTL_ERROR) {
		IBWARN("ctl error");
		return -1;
	}
	if (len)
		memcpy(data, &ctl.data, len);

	return 0;
}

static size_t make_name(union name_t *name, char *host, unsigned port,
			const char *fmt, ...)
{
	size_t size;
	memset(name, 0, sizeof(*name));
	if (remote_mode) {
		struct sockaddr_in *name_i = &name->name_i;
	        name_i->sin_family = AF_INET;
		if (host) {
			name_i->sin_addr.s_addr = inet_addr(host);
			if (name_i->sin_addr.s_addr == (unsigned long)INADDR_NONE) {
				struct hostent *hostp;
				if(!(hostp = gethostbyname(host)))
					IBPANIC("cannot resolve ibsim server"
						" %s: h_errno = %d\n",
						host, h_errno);
				memcpy(&name_i->sin_addr, hostp->h_addr,
				       sizeof(name_i->sin_addr));
			}
		} else
			name_i->sin_addr.s_addr = htonl(INADDR_ANY);
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

static int sim_attach(int fd, union name_t *name, size_t size)
{
	int retries;
	int r;

	for (retries = 0;; retries++) {
		DEBUG("attempt to connect to %s (attempt %d)",
		      get_name(name), retries);

		if ((r = connect(fd, (struct sockaddr *)name, size)) >= 0)
			break;

		if (r < 0 && errno == ECONNREFUSED) {
			DEBUG("waiting for %s to start", get_name(name));
			sleep(2);
			continue;
		}

		IBPANIC("can't connect to sim socket %s", get_name(name));
	}

	return 0;
}

static int sim_connect(struct sim_client *sc, int id, int qp, char *nodeid)
{
	struct sim_client_info info = { 0 };

	info.id = id;
	info.issm = 0;
	info.qp = qp;

	if (nodeid)
		strncpy(info.nodeid, nodeid, sizeof(info.nodeid) - 1);

	if (sim_ctl(sc, SIM_CTL_CONNECT, &info, sizeof(info)) < 0)
		return -1;

	id = info.id;

	if (!nodeid || strcmp(nodeid, info.nodeid))
		IBWARN("attached as client %d at node \"%s\"", id,
		       info.nodeid);
	return id;
}

static int sim_disconnect(struct sim_client *sc)
{
	return sim_ctl(sc, SIM_CTL_DISCONNECT, 0, 0);
}

static int sim_init(struct sim_client *sc, char *nodeid)
{
	union name_t name;
	socklen_t size;
	int fd, ctlfd;
	int pid = getpid();
	char *connect_port;
	char *connect_host;
	unsigned short port;

	connect_port = getenv("IBSIM_SERVER_PORT");
	connect_host = getenv("IBSIM_SERVER_NAME");
	socket_basename = getenv("IBSIM_SOCKNAME");

	if(!socket_basename)
		socket_basename = SIM_BASENAME;

	if (connect_host && *connect_host)
		remote_mode = 1;

	DEBUG("init client pid=%d, nodeid=%s", pid, nodeid ? nodeid : "none");

	if ((fd = socket(remote_mode ? PF_INET : PF_LOCAL, SOCK_DGRAM, 0)) < 0)
		IBPANIC("can't get socket (fd)");

	if ((ctlfd = socket(remote_mode ? PF_INET : PF_LOCAL, SOCK_DGRAM, 0)) < 0)
		IBPANIC("can't get socket (ctlfd)");

	size = make_name(&name, NULL, 0, "%s:ctl%d", socket_basename, pid);

	if (bind(ctlfd, (struct sockaddr *)&name, size) < 0)
		IBPANIC("can't bind ctl socket");

	DEBUG("init %d: opened ctl fd %d as \'%s\'",
	      pid, ctlfd, get_name(&name));

	port = connect_port ? atoi(connect_port) : IBSIM_DEFAULT_SERVER_PORT;
	size = make_name(&name, connect_host, port, "%s:ctl", socket_basename);

	sim_attach(ctlfd, &name, size);

	sc->fd_ctl = ctlfd;

	size = make_name(&name, NULL, 0, "%s:in%d", socket_basename, pid);

	if (bind(fd, (struct sockaddr *)&name, size) < 0)
		IBPANIC("can't bind input socket");

	DEBUG("init client %d: opened input data fd %d as \'%s\'\n",
	      pid, fd, get_name(&name));
	if (getsockname(fd, (struct sockaddr *)&name, &size) < 0 )
		IBPANIC("can't read data from bound socket");
	port = ntohs(name.name_i.sin_port);

	sc->clientid = sim_connect(sc, remote_mode ? port : pid, 0, nodeid);
	if (sc->clientid < 0)
		IBPANIC("connect failed");

	port = connect_port ? atoi(connect_port) : IBSIM_DEFAULT_SERVER_PORT;
	size = make_name(&name, connect_host, port + sc->clientid + 1,
			 "%s:out%d", socket_basename, sc->clientid);

	sim_attach(fd, &name, size);

	DEBUG("init client %d: connect data fd %d to \'%s\'\n",
	      sc->clientid, fd, get_name(&name));

	sc->fd_pktin = fd;
	sc->fd_pktout = fd;

	return fd;
}

/*************************/

int sim_client_set_sm(struct sim_client *sc, unsigned issm)
{
	DEBUG("sim_client_is_sm: setting to %d", issm);
	return sim_ctl(sc, SIM_CTL_SET_ISSM, &issm, sizeof(int));
}

int sim_client_init(struct sim_client *sc)
{
	char *nodeid;

	nodeid = getenv("SIM_HOST");
	if (sim_init(sc, nodeid) < 0)
		return -1;
	if (sim_ctl(sc, SIM_CTL_GET_VENDOR, &sc->vendor,
		    sizeof(sc->vendor)) < 0)
		goto _exit;
	if (sim_ctl(sc, SIM_CTL_GET_NODEINFO, sc->nodeinfo,
		    sizeof(sc->nodeinfo)) < 0)
		goto _exit;

	sc->portinfo[0] = 0;	// portno requested
	if (sim_ctl(sc, SIM_CTL_GET_PORTINFO, sc->portinfo,
		    sizeof(sc->portinfo)) < 0)
		goto _exit;
	if (sim_ctl(sc, SIM_CTL_GET_PKEYS, sc->pkeys, sizeof(sc->pkeys)) < 0)
		goto _exit;
	if (getenv("SIM_SET_ISSM"))
		sim_client_set_sm(sc, 1);
	return 0;
  _exit:
	sim_disconnect(sc);
	sc->fd_ctl = sc->fd_pktin = sc->fd_pktout = -1;
	return -1;
}

void sim_client_exit(struct sim_client *sc)
{
	sim_disconnect(sc);
	sc->fd_ctl = sc->fd_pktin = sc->fd_pktout = -1;
}
