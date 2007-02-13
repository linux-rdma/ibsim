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
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <infiniband/common.h>
#include <infiniband/mad.h>

#include <ibsim.h>

#include "sim_client.h"

#ifdef SIM_CLIENT_NOISY_DEBUG
#undef DEBUG
#define DEBUG	IBWARN
#else
#define DEBUG(fmt...)
#endif

int sim_client_recv_packet(struct sim_client *sc, void *buf, int size)
{
	int len, ret, cnt;

	if (size < sizeof(struct sim_request)) {
		LOG("buffer too small %d < %zu", size,
		    sizeof(struct sim_request));
		return -1;
	}

	ret = 0;
	len = sizeof(struct sim_request);
	while (len > 0) {
		cnt = read(sc->fd_pktin, buf + ret, len);
		if (cnt < 0) {
			LOG("sim_client_recv_packet: read(%d) failed (%m)",
			    size);
			return -1;
		} else if (cnt == 0)
			return ret;
		len -= cnt;
		ret += cnt;
	}

	return size;
}

int sim_client_send_packet(struct sim_client *sc, char *p, int size)
{
	if (write(sc->fd_pktout, p, size) == size)
		return 0;
	IBWARN("write failed: %m");
	return -1;
}

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

static int sim_attach(int fd, struct sockaddr_un *name)
{
	int retries;
	int r;

	for (retries = 0;; retries++) {
		DEBUG("attempt to connect to %s (attempt %d)",
		      name->sun_path + 1, retries);

		if ((r =
		     connect(fd, (struct sockaddr *)name, sizeof(*name))) >= 0)
			break;

		if (r < 0 && errno == ECONNREFUSED) {
			DEBUG("waiting for %s to start", name->sun_path + 1);
			sleep(2);
			continue;
		}

		IBPANIC("can't connect to sim socket %s", name->sun_path + 1);
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

static int sim_init(struct sim_client *sc, int qp, char *nodeid)
{
	struct sockaddr_un name;
	int fd, ctlfd;
	int pid = getpid();

	DEBUG("init client pid=%d, qp=%d nodeid=%s",
	      pid, qp, nodeid ? nodeid : "none");

	if ((fd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0)
		IBPANIC("can't get socket (fd)");

	if ((ctlfd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0)
		IBPANIC("can't get socket (ctlfd)");

	memset(&name, 0, sizeof(name));
	name.sun_family = AF_LOCAL;
	name.sun_path[0] = 0;

	sprintf(name.sun_path + 1, "%s:ctl%d", SIM_BASENAME, pid);

	if (bind(ctlfd, (struct sockaddr *)&name, sizeof(name)) < 0)
		IBPANIC("can't bind ctl socket");

	DEBUG("init %d: opened ctl fd %d as %s",
	      pid, ctlfd, name.sun_path + 1);

	memset(name.sun_path, 0, sizeof(name.sun_path));
	sprintf(name.sun_path + 1, "%s:ctl", SIM_BASENAME);

	sim_attach(ctlfd, &name);

	sc->fd_ctl = ctlfd;

	memset(name.sun_path, 0, sizeof(name.sun_path));
	sprintf(name.sun_path + 1, "%s:in%d", SIM_BASENAME, pid);

	if (bind(fd, (struct sockaddr *)&name, sizeof(name)) < 0)
		IBPANIC("can't bind input socket");

	DEBUG("init client %d: opened input data fd %d as %s",
	      pid, fd, name.sun_path + 1);

	if ((sc->clientid = sim_connect(sc, pid, qp, nodeid)) < 0)
		IBPANIC("connect failed");

	memset(name.sun_path, 0, sizeof(name.sun_path));
	sprintf(name.sun_path + 1, "%s:out%d", SIM_BASENAME, sc->clientid);

	sim_attach(fd, &name);

	DEBUG("init client %d: connect data fd %d to %s",
	      sc->clientid, fd, name.sun_path + 1);

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

int sim_client_init(struct sim_client *sc, char *nodeid)
{
	if (!nodeid)
		nodeid = getenv("SIM_HOST");
	if (sim_init(sc, 0, nodeid) < 0)
		return -1;
	if (sim_ctl(sc, SIM_CTL_GET_VENDOR, &sc->vendor, sizeof(sc->vendor)) <
	    0)
		goto _exit;
	if (sim_ctl(sc, SIM_CTL_GET_NODEINFO, sc->nodeinfo,
		    sizeof(sc->nodeinfo)) < 0)
		goto _exit;
	sc->portinfo[0] = 0;
	if (sim_ctl(sc, SIM_CTL_GET_PORTINFO, sc->portinfo,
		    sizeof(sc->portinfo)) < 0)
		goto _exit;
	return 0;
  _exit:
	sim_disconnect(sc);
	sc->fd_ctl = sc->fd_pktin = sc->fd_pktout = -1;
	return 0;
}

void sim_client_exit(struct sim_client *sc)
{
	sim_disconnect(sc);
	sc->fd_ctl = sc->fd_pktin = sc->fd_pktout = -1;
}
