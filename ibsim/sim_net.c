/*
 * Copyright (c) 2004-2007 Voltaire, Inc. All rights reserved.
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
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#include <ibsim.h>
#include "sim.h"

#undef DEBUG
#define PDEBUG	if (parsedebug) IBWARN
#define DEBUG	if (simverb || ibdebug) IBWARN

#define MAX_INCLUDE 9
int inclines[MAX_INCLUDE];
char *incfiles[MAX_INCLUDE];
int inclevel;

int parsedebug;
int simverb;

Port *defport;

static const uint8_t smaport[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x48,
	0x00, 0x00, 0x0F, 0xF9, 0x00, 0x03, 0x03, 0x01,
	0x14, 0x52, 0x00, 0x11, 0x10, 0x40, 0x00, 0x08,
	0x08, 0x03, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x1F, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t swport[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x02,
	0x14, 0x52, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t swport_down[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x01,
	0x11, 0x22, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xE9, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t hcaport[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x00, 0x10, 0x02, 0x48,
	0x00, 0x00, 0x0F, 0xF9, 0x01, 0x03, 0x03, 0x02,
	0x14, 0x52, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x20, 0x1F, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t hcaport_down[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x00, 0x10, 0x02, 0x48,
	0x00, 0x00, 0x0F, 0xF9, 0x01, 0x03, 0x03, 0x01,
	0x11, 0x22, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xE9, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x20, 0x1F, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t switchinfo[] = {
	0xC0, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
	0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t swnodeinfo[] = {
	0x01, 0x01, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
	0xF1, 0x04, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x08,
	0xF1, 0x04, 0x00, 0x0D, 0x00, 0x08, 0xA8, 0x7C,
	0x00, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x08, 0xF1,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t hcanodeinfo[] = {
	0x01, 0x01, 0x01, 0x02, 0x00, 0x02, 0xC9, 0x00,
	0x01, 0x13, 0x6E, 0x40, 0x00, 0x02, 0xC9, 0x00,
	0x01, 0x13, 0x6E, 0x40, 0x00, 0x02, 0xC9, 0x00,
	0x01, 0x13, 0x6E, 0x41, 0x00, 0x40, 0x5A, 0x44,
	0x00, 0x00, 0x00, 0xA1, 0x01, 0x00, 0x02, 0xC9,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t default_sl2vl[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe7,
};

static const struct vlarb default_vlarb_high[] = {
	{0, 4}, {1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 0}, {6, 0}, {7, 0},
	{8, 0}, {9, 0}, {10, 0}, {11, 0}, {12, 0}, {13, 0}, {14, 0},
};

static const struct vlarb default_vlarb_low[] = {
	{0, 0}, {1, 4}, {2, 4}, {3, 4}, {4, 4}, {5, 4}, {6, 4}, {7, 4},
	{8, 4}, {9, 4}, {10, 4}, {11, 4}, {12, 4}, {13, 4}, {14, 4},
};

#define MAXLINE	256

// map is in format "alias@nodeid[portnum]"
#define ALIASMAPLEN (ALIASLEN+NODEIDLEN+6)

uint64_t absguids[NODE_TYPES] = { ~0, 0x100000, 0x200000 };
uint64_t guids[NODE_TYPES] = { ~0, 0x100000, 0x200000 };

int maxnetnodes = MAXNETNODES;
int maxnetswitchs = MAXNETSWITCHS;
int maxnetports = MAXNETPORTS;
int maxlinearcap = MAXLINEARCAP;
int maxmcastcap = MAXMCASTCAP;
int maxnetaliases = MAXNETALIASES;
int ignoreduplicate = 0;

Node *nodes;
Switch *switchs;
Port *ports;
Port **lids;
char (*aliases)[NODEIDLEN + NODEPREFIX + 1];	// aliases map format: "%s@%s"

int netnodes, netswitchs, netports, netaliases;
char netprefix[NODEPREFIX + 1];
int netdevid;
int netwidth = DEFAULT_LINKWIDTH;
int netspeed = DEFAULT_LINKSPEED;

const char *node_type_name(unsigned type)
{
	switch(type) {
	case SWITCH_NODE:
		return "Switch";
	case HCA_NODE:
		return "Ca";
	case ROUTER_NODE:
		return "Router";
	default:
		return "Unknown";
	}
}

static int new_ports(Node * node, int portnum, int firstport)
{
	int first, i;

	if (netports + portnum > maxnetports) {
		IBPANIC("no more ports (max %d)", maxnetports);
		return 0;
	}

	first = netports;

	netports += portnum;

	for (i = first; i < netports; i++) {
		ports[i].node = node;
		ports[i].portnum = firstport++;
	}

	return first;
}

static Switch *new_switch(Node * nd)
{
	Switch *sw;

	if (netswitchs >= maxnetswitchs) {
		IBPANIC("no more switches (max %d)", maxnetswitchs);
		return 0;
	}

	sw = switchs + netswitchs++;

	sw->node = nd;
	sw->linearcap = maxlinearcap;	// assume identical val for all switches
	sw->multicastcap = maxmcastcap;	// assume identical val for all switches
	memcpy(sw->switchinfo, switchinfo, sizeof(sw->switchinfo));
	mad_set_field(sw->switchinfo, 0, IB_SW_LINEAR_FDB_CAP_F, sw->linearcap);
	mad_set_field(sw->switchinfo, 0, IB_SW_MCAST_FDB_CAP_F,
		      sw->multicastcap);
	memset(sw->fdb, 0xff, sizeof(sw->fdb));
	return sw;
}

static int new_hca(Node * nd)
{
	return 0;
}

static int build_nodeid(char *nodeid, char *base)
{
	if (strchr(base, '#') || strchr(base, '@')) {
		IBWARN("bad nodeid \"%s\": '#' & '@' characters are resereved",
		       base);
		return -1;
	}
	if (netprefix[0] == 0)
		strncpy(nodeid, base, NODEIDLEN);
	else
		snprintf(nodeid, NODEIDLEN, "%s#%s", netprefix, base);
	return 0;
}

static Node *new_node(int type, char *nodename, char *nodedesc, int nodeports)
{
	int firstport = 1;
	char nodeid[NODEIDLEN];
	Node *nd;

	if (build_nodeid(nodeid, nodename) < 0)
		return 0;

	if (find_node(nodeid)) {
		IBWARN("node id %s already exists", nodeid);
		return 0;
	}

	if (netnodes >= maxnetnodes) {
		IBPANIC("no more nodes (max %d)", maxnetnodes);
		return 0;
	}

	if (find_node_by_guid(guids[type])) {
		IBWARN("node %s guid %" PRIx64 " already exists",
		       node_type_name(type), guids[type]);
		return 0;
	}

	nd = nodes + netnodes++;

	nd->type = type;
	nd->numports = nodeports;
	strncpy(nd->nodeid, nodeid, NODEIDLEN - 1);
	if (nodedesc[0] == 0)
		strncpy(nd->nodedesc, nodeid, NODEIDLEN - 1);
	else
		strncpy(nd->nodedesc, nodedesc, NODEIDLEN - 1);
	nd->sysguid = nd->nodeguid = guids[type];
	if (type == SWITCH_NODE) {
		nodeports++;	// port 0 is SMA
		firstport = 0;
		memcpy(nd->nodeinfo, swnodeinfo, sizeof(nd->nodeinfo));
		guids[type]++;	// reserve single guid;
	} else {
		memcpy(nd->nodeinfo, hcanodeinfo, sizeof(nd->nodeinfo));
		guids[type] += nodeports + 1;	// reserve guids;
	}

	mad_set_field(nd->nodeinfo, 0, IB_NODE_NPORTS_F, nd->numports);
	mad_set_field(nd->nodeinfo, 0, IB_NODE_DEVID_F, netdevid);

	mad_encode_field(nd->nodeinfo, IB_NODE_GUID_F, &nd->nodeguid);
	mad_encode_field(nd->nodeinfo, IB_NODE_PORT_GUID_F, &nd->nodeguid);
	mad_encode_field(nd->nodeinfo, IB_NODE_SYSTEM_GUID_F, &nd->nodeguid);

	if ((nd->portsbase = new_ports(nd, nodeports, firstport)) < 0) {
		IBWARN("can't alloc %d ports for node %s", nodeports,
		       nd->nodeid);
		return 0;
	}

	return nd;
}

static int parse_node_ports(char *buf)
{
	while (*buf && !isdigit(*buf))
		buf++;
	return strtoul(buf, 0, 0);
}

static char *parse_node_id(char *buf, char **rest_buf)
{
	char *s, *e = 0;

	if (!(s = strchr(buf, '"')) || !(e = strchr(s + 1, '"'))) {
		IBWARN("can't find valid id in <%s>", buf);
		return 0;
	}
	*e = 0;
	if (rest_buf)
		*rest_buf = e + 1;
	return s + 1;
}

static int parse_node_desc(char *buf, char *nodedesc)
{
	char *s, *e = 0;

	if (!(s = strchr(buf, '#')) || !(s = strchr(s + 1, '"'))
	    || !(e = strchr(s + 1, '"'))) {
		*nodedesc = 0;
		return 0;
	}

	memcpy(nodedesc, s + 1, e - s - 1);
	nodedesc[e - s - 1] = 0;
	return 1;
}

static int is_linkwidth_valid(int width)
{
	/* width is 1x 4x 8x 12x */
	if (width < 1 || width > 15) {
		IBWARN("bad enabled width %d - should be between 1 to 15",
		       width);
		return 0;
	}
	return 1;
}

static int is_linkspeed_valid(int speed)
{
	/* speed is 2.5G or 5.0G */
	if (speed < 1 || speed > 7) {
		IBWARN("bad speed %d - should be between 1 to 7", speed);
		return 0;
	}
	return 1;
}

static int parse_port_lid_and_lmc(Port * port, char *line)
{
	char *s;

	if (!(line = strchr(line, '#')))
		return 0;
	while (*line == '#')
		line++;
	if ((s = strstr(line, "lid "))) {
		s += 4;
		port->lid = strtoul(s, NULL, 0);
	}
	if ((s = strstr(line, "lmc "))) {
		s += 4;
		port->lmc = strtoul(s, NULL, 0);
	}

	return 0;
}

static int parse_port_opt(Port * port, char *opt, char *val)
{
	int width;
	int speed;

	if (*opt == 'w') {
		width = strtoul(val, 0, 0);
		if (!is_linkwidth_valid(width))
			return -1;

		port->linkwidthena = width;
		DEBUG("port %p linkwidth enabled set to %d", port,
		      port->linkwidthena);
		return 0;
	} else if (*opt == 's') {
		speed = strtoul(val, 0, 0);

		if (!is_linkspeed_valid(speed))
			return -1;

		port->linkspeedena = speed;
		DEBUG("port %p linkspeed enabled set to %d", port,
		      port->linkspeedena);
		return 0;
	} else {
		IBWARN("unknown opt %c", *opt);
		return -1;
	}
}

static void init_ports(Node * node, int type, int maxports)
{
	Port *port;
	unsigned size, sw_pkey_size;
	unsigned i, j;

	size = mad_get_field(node->nodeinfo, 0, IB_NODE_PARTITION_CAP_F);
	if (type == SWITCH_NODE)
		sw_pkey_size = mad_get_field(node->sw->switchinfo, 0,
					     IB_SW_PARTITION_ENFORCE_CAP_F);

	for (i = (type == SWITCH_NODE ? 0 : 1); i <= maxports; i++) {
		port = node_get_port(node, i);

		if (type == SWITCH_NODE)
			port->portguid = node->nodeguid;
		else
			port->portguid = node->nodeguid + i;
		port->portnum = i;
		port->linkwidthena = netwidth;
		port->linkwidth = LINKWIDTH_4x;
		port->linkspeedena = netspeed;
		port->linkspeed = LINKSPEED_SDR;

		if (type == SWITCH_NODE && i)
			size = sw_pkey_size;
		if (size) {
			port->pkey_tbl = calloc(size, sizeof(uint16_t));
			if (!port->pkey_tbl)
				IBPANIC("cannot alloc port's pkey table\n");
			port->pkey_tbl[0] = 0xffff;
		}

		size = node->sw ? maxports : 1;
		port->sl2vl = calloc(8 * sizeof(uint8_t), size);
		if (!port->sl2vl) {
			IBPANIC("cannot alloc port's sl2vl table\n");
		}
		for (j = 0; j < size; j++)
			memcpy(port->sl2vl + 8 * j, default_sl2vl, 8);

		memcpy(port->vlarb_high, default_vlarb_high,
		       sizeof(port->vlarb_high));
		memcpy(port->vlarb_low, default_vlarb_low,
		       sizeof(port->vlarb_low));
	}
}

static int build_alias(char *alias, char *base, int check)
{
	if (strchr(base, '#') || strchr(base, '@')) {
		if (!check) {
			strncpy(alias, base, ALIASLEN);
			return 0;
		}
		IBWARN("bad alias \"%s\": '#' & '@' characters are resereved",
		       base);
		return -1;
	}
	snprintf(alias, ALIASLEN, "%s@%s", netprefix, base);
	return 0;
}

char *map_alias(char *alias)
{
	int i;
	int len = strlen(alias);

	for (i = 0; i < netaliases; i++) {
		if (strncmp(alias, aliases[i], len))
			continue;
		if (aliases[i][len] == '#')
			return aliases[i] + len + 1;
	}
	return 0;
}

char *expand_name(char *base, char *name, char **portstr)
{
	char *s;

	if (!base)
		return 0;

	if (!strchr(base, '@')) {
		if (netprefix[0] != 0 && !strchr(base, '#'))
			snprintf(name, NODEIDLEN, "%s#%s", netprefix, base);
		else
			strcpy(name, base);
		if (portstr)
			*portstr = 0;
		PDEBUG("name %s port %s", name, portstr ? *portstr : 0);
		return name;
	}
	if (base[0] == '@')
		snprintf(name, ALIASLEN, "%s%s", netprefix, base);
	else
		strcpy(name, base);
	PDEBUG("alias %s", name);

	if (!(s = map_alias(name)))
		return 0;

	strcpy(name, s);

	if (portstr) {
		*portstr = name;
		strsep(portstr, "[");
	}
	PDEBUG("name %s port %s", name, portstr ? *portstr : 0);
	return name;
}

static int new_alias(char *alias, Node * node, int portnum)
{
	char aliasname[ALIASLEN];
	char *s;

	PDEBUG("new alias: a %s n %s pn %d", alias, node->nodeid, portnum);
	if (netaliases >= maxnetaliases) {
		IBPANIC("max net aliases %d limit exceeded", maxnetaliases);
		return -1;
	}

	if (build_alias(aliasname, alias, 1) < 0)
		return -1;

	if ((s = map_alias(aliasname))) {
		IBWARN("alias %s is already mapped to %s", aliasname, s);
		return -1;
	}

	snprintf(aliases[netaliases], ALIASMAPLEN,
		 "%s#%s[%d]", aliasname, node->nodeid, portnum);
	PDEBUG("new alias: %s", aliases[netaliases]);
	netaliases++;
	return 0;
}

static int parse_port(char *line, Node * node, int type, int maxports)
{
	char remotenodeid[NODEIDLEN], *sp;
	int portnum, isalias = 0;
	Port *port;
	char *s;

	if (line[0] == '@') {
		isalias = 1;
		line++;
	}

	portnum = atoi(line + 1);

	if (portnum < 0 || portnum > maxports) {
		IBWARN("bad port num %d: <%s>", portnum, line);
		return -1;
	}
	if (!portnum && line[1] != 0) {
		IBWARN("bad port: <%s>", line);
		return -1;
	}

	port = node_get_port(node, portnum);

	if (type != SWITCH_NODE && !portnum) {
		IBWARN("Port0 in non switch node <%s>", line);
		return -1;
	}

	if (!(s = parse_node_id(line, NULL))) {
		IBWARN("invalid remote nodeid: <%s>", line);
		return -1;
	}

	if (isalias) {
		if (new_alias(s, node, portnum) < 0)
			return -1;
		build_alias(port->alias, s, 1);
		s += strlen(s) + 1;
		goto parse_opt;
	}

	if (strchr(s, '@'))
		build_alias(port->remotealias, s, 0);

	expand_name(s, remotenodeid, &sp);
	PDEBUG("remotenodid %s s %s sp %s", remotenodeid, s, sp);

	s += strlen(s) + 1;
	if (!sp && *s == '[')
		sp = s + 1;

	strncpy(port->remotenodeid, remotenodeid,
		sizeof(port->remotenodeid) - 1);
	if (!sp) {
		port->remoteport = 1;	// default
		goto parse_opt;
	}
	if ((port->remoteport = atoi(sp)) <= 0) {
		IBWARN("invalid remote portnum %d: <%s>", port->remoteport, sp);
		port->remoteport = 0;	// no remote
		return -1;
	}
      parse_opt:
	line = s;
	while (s && (s = strchr(s + 1, '='))) {
		char *opt = s;
		while (opt && !isalpha(*opt))
			opt--;
		if (!opt || parse_port_opt(port, opt, s + 1) < 0) {
			IBWARN("bad port option");
			return -1;
		}
		line = s + 1;
	}
	if (type != SWITCH_NODE && line && parse_port_lid_and_lmc(port, line) < 0) {
		IBWARN("cannot parse lid, lmc");
		return -1;
	}
	return 1;
}

static int parse_ports(int fd, Node * node, int type, int maxports)
{
	char line[MAXLINE], *s;
	int lines = 0, portnum, r;

	init_ports(node, type, maxports);

	for (lines = 0, portnum = maxports; portnum; lines++) {
		if (!readline(fd, line, sizeof(line) - 1))
			return lines;	// EOF - check errno?

		if ((s = strchr(line, '\n')))
			*s = 0;

		if (line[0] == '#')	// comment line
			continue;

		if (line[0] != '[' && line[0] != '@')	// end of record
			return lines;

		if ((r = parse_port(line, node, type, maxports)) > 0) {
			portnum--;
			continue;
		}
		return -(lines - r);
	}

	return lines;
}

static int parse_endnode(int fd, char *line, int type)
{
	Node *nd;
	char *nodeid;
	char nodedesc[NODEIDLEN];
	int ports, r;

	parse_node_desc(line, nodedesc);

	if (!(ports = parse_node_ports(line + 3)) ||
	    !(nodeid = parse_node_id(line, NULL)))
		return 0;

	if (!(nd = new_node(type, nodeid, nodedesc, ports)))
		return 0;

	if (new_hca(nd) < 0)
		return 0;

	r = parse_ports(fd, nd, type, ports);

	PDEBUG("%d ports found", r);

	// return number of lines + 1 for the header line
	if (r >= 0)
		return r + 1;
	return r - 1;
}

static int parse_switch(int fd, char *line)
{
	Node *nd;
	Switch *sw;
	Port *port;
	char *nodeid;
	char nodedesc[NODEIDLEN];
	int nports, r;

	parse_node_desc(line, nodedesc);

	if (!(nports = parse_node_ports(line + 6)) ||
	    !(nodeid = parse_node_id(line, &line)))
		return 0;

	if (!(nd = new_node(SWITCH_NODE, nodeid, nodedesc, nports)))
		return 0;

	if (!(sw = new_switch(nd)))
		return 0;

	nd->sw = sw;

	r = parse_ports(fd, nd, SWITCH_NODE, nports);

	port = node_get_port(nd, 0);
	if (line && parse_port_lid_and_lmc(port, line) < 0) {
		IBWARN("cannot parse switch lid, lmc");
		return -1;
	}
	// return number of lines + 1 for the header line
	PDEBUG("%d ports found", r);
	if (r >= 0)
		return r + 1;
	return r - 1;
}

static int parse_guidbase(int fd, char *line, int type)
{
	uint64_t guidbase;
	int relative = 0;
	char *s;

	if (!(s = strchr(line, '=')) && !(s = strchr(line, '+'))) {
		IBWARN("bad assignemnt: missing '=|+' sign");
		return -1;
	}

	if (*s == '+')
		relative = 1;

	guidbase = strtoull(s + 1, 0, 0);

	if (!relative) {
		absguids[type] = guidbase;
		guidbase = 0;
	}
	guids[type] = absguids[type] + guidbase;
	PDEBUG("new guidbase for %s: base %" PRIx64 " current %" PRIx64,
	       node_type_name(type), absguids[type],
	       guids[type]);
	return 1;
}

static int parse_devid(int fd, char *line)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignemnt: missing '=' sign");
		return -1;
	}

	netdevid = strtol(s + 1, 0, 0);

	return 1;
}

static int parse_width(int fd, char *line)
{
	char *s;
	int width;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignemnt: missing '=' sign");
		return -1;
	}

	width = strtol(s + 1, 0, 0);
	if (!is_linkwidth_valid(width)) {
		IBPANIC("invalid enabled link width %d", width);
		return -1;
	}

	netwidth = width;
	return 1;
}

static int parse_speed(int fd, char *line)
{
	char *s;
	int speed;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignemnt: missing '=' sign");
		return -1;
	}

	speed = strtol(s + 1, 0, 0);
	if (!is_linkspeed_valid(speed)) {
		IBPANIC("invalid enabled link speed %d", speed);
		return -1;
	}

	netspeed = speed;
	return 1;
}

static int parse_netprefix(int fd, char *line)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignemnt: missing '=' sign");
		return -1;
	}

	if (!(s = parse_node_id(s + 1, NULL)))
		return -1;

	if (strlen(s) > NODEPREFIX) {
		IBWARN("prefix %s too long!", s);
		return -1;
	}

	strncpy(netprefix, s, NODEPREFIX);
	return 1;
}

static int parse_include(char *line, FILE * out)
{
	char *s = line, *fname;

	strsep(&s, "\"");
	if (s)
		fname = strsep(&s, "\"");
	if (!s) {
		IBWARN("bad include file name");
		return -1;
	}
	if (read_netconf(fname, out) < 0)
		return -1;
	return 1;		// only one line is consumed from parent file
}

static int set_var(char *line, int *var)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignemnt: missing '=' sign");
		return -1;
	}

	*var = strtol(s + 1, 0, 0);
	return 1;
}

static int parse_netconf(int fd, FILE * out)
{
	char line[MAXLINE], *s;
	int r = 1;
	int lineno = 0;

	do {
		lineno += r;
		if (!readline(fd, line, sizeof(line) - 1))
			return lineno;	// EOF - check errno?
		if ((s = strchr(line, '\n')))
			*s = 0;
		PDEBUG("> parse line: <%s>", line);
		if (!strncmp(line, "Switch", 6))
			r = parse_switch(fd, line);
		else if (!strncmp(line, "Hca", 3) || !strncmp(line, "Ca", 2))
			r = parse_endnode(fd, line, HCA_NODE);
		else if (!strncmp(line, "Rt", 2))
			r = parse_endnode(fd, line, ROUTER_NODE);
		else if (!strncmp(line, "switchguid", 10))
			r = parse_guidbase(fd, line, SWITCH_NODE);
		else if (!strncmp(line, "hcaguids", 8) ||
			 !strncmp(line, "caguid", 6))
			r = parse_guidbase(fd, line, HCA_NODE);
		else if (!strncmp(line, "rtguid", 6))
			r = parse_guidbase(fd, line, ROUTER_NODE);
		else if (!strncmp(line, "devid", 5))
			r = parse_devid(fd, line);
		else if (!strncmp(line, "width", 5))
			r = parse_width(fd, line);
		else if (!strncmp(line, "speed", 5))
			r = parse_speed(fd, line);
		else if (!strncmp(line, "module", 6))
			r = parse_netprefix(fd, line);
		else if (!strncmp(line, "include", 7))
			r = parse_include(line, out);
		else if (!strncmp(line, "pdebug", 6))
			r = set_var(line, &parsedebug);
		else if (!strncmp(line, "do", 2))
			r = do_cmd(line + 2, out) < 0 ? -1 : 1;
		// else line is ignored
		else
			r = 1;
		PDEBUG("> lines consumed = %d", r);
	} while (r > 0);

	return -lineno + r;
}

int read_netconf(char *name, FILE * out)
{
	int r, fd;

	incfiles[inclevel] = name;
	inclines[inclevel] = 0;

	fprintf(out, "parsing: %s\n", name);
	if ((fd = open(name, O_RDONLY)) < 0) {
		IBWARN("can't open net configuration file \"%s\": %m", name);
		return -1;
	}
	inclevel++;

	r = parse_netconf(fd, out);

	close(fd);
	inclevel--;

	if (r < 0) {
		int i;
		fprintf(out, "fatal: error at %s: line %d \n",
			name, inclines[inclevel]);
		for (i = inclevel - 1; i >= 0; i--)
			fprintf(out, "\tcalled from %s: line %d \n",
				incfiles[i], inclines[i]);
		IBPANIC("parsing failed");
	}
	fprintf(out, "%s: parsed %d lines\n", name, inclines[inclevel]);
	return r;
}

static int get_active_linkwidth(Port * lport, Port * rport)
{
	int width = lport->linkwidthena & rport->linkwidthena;

	if (width & LINKWIDTH_12x)
		return LINKWIDTH_12x;
	if (width & LINKWIDTH_8x)
		return LINKWIDTH_8x;
	if (width & LINKWIDTH_4x)
		return LINKWIDTH_4x;
	if (width & LINKWIDTH_1x)
		return LINKWIDTH_1x;

	IBPANIC("mismatched enabled width between %" PRIx64 " P#%d W=%d and %"
		PRIx64 " P#%d W=%d", lport->portguid, lport->portnum,
		lport->linkwidthena, rport->portguid, rport->portnum,
		rport->linkwidthena);
	return 0;
}

static int get_active_linkspeed(Port * lport, Port * rport)
{
	int speed = lport->linkspeedena & rport->linkspeedena;

	if (speed & LINKSPEED_QDR)
		return LINKSPEED_QDR;
	if (speed & LINKSPEED_DDR)
		return LINKSPEED_DDR;
	if (speed & LINKSPEED_SDR)
		return LINKSPEED_SDR;

	IBPANIC("mismatched enabled speed between %" PRIx64 " P#%d S=%d and %"
		PRIx64 " P#%d S=%d", lport->portguid, lport->portnum,
		lport->linkspeedena, rport->portguid, rport->portnum,
		rport->linkspeedena);
	return 0;
}

void update_portinfo(Port * p)
{
	uint8_t *pi = p->portinfo;

	mad_set_field(pi, 0, IB_PORT_LOCAL_PORT_F,
		      p->node->type == SWITCH_NODE ? 0 : p->portnum);
	mad_set_field(pi, 0, IB_PORT_LID_F, p->lid);
	mad_set_field(pi, 0, IB_PORT_SMLID_F, p->smlid);
	mad_set_field(pi, 0, IB_PORT_OPER_VLS_F, p->op_vls);
	mad_set_field(pi, 0, IB_PORT_LINK_WIDTH_ENABLED_F, p->linkwidthena);
	mad_set_field(pi, 0, IB_PORT_LINK_WIDTH_SUPPORTED_F,
		      LINKWIDTH_1x_4x_12x);
	mad_set_field(pi, 0, IB_PORT_LINK_WIDTH_ACTIVE_F, p->linkwidth);
	mad_set_field(pi, 0, IB_PORT_LINK_SPEED_ENABLED_F, p->linkspeedena);
	mad_set_field(pi, 0, IB_PORT_LINK_SPEED_SUPPORTED_F, LINKSPEED_SDR_DDR);
	mad_set_field(pi, 0, IB_PORT_LINK_SPEED_ACTIVE_F, p->linkspeed);
	mad_set_field(pi, 0, IB_PORT_LMC_F, p->lmc);
	mad_set_field(pi, 0, IB_PORT_HOQ_LIFE_F, p->hoqlife);
	mad_set_field(pi, 0, IB_PORT_PHYS_STATE_F, p->physstate);
	mad_set_field(pi, 0, IB_PORT_STATE_F, p->state);
}

static void set_portinfo(Port * p, const uint8_t portinfo[])
{
	memcpy(p->portinfo, portinfo, sizeof(p->portinfo));
	if (!p->op_vls)
		p->op_vls = mad_get_field(p->portinfo, 0, IB_PORT_VL_CAP_F);
}

int link_ports(Node * lnode, Port * lport, Node * rnode, Port * rport)
{
	Port *endport;

	if (lport->remotenode || rport->remotenode)
		return -1;

	lport->remotenode = rnode;
	lport->remoteport = rport->portnum;
	set_portinfo(lport, lnode->type == SWITCH_NODE ? swport : hcaport);
	memcpy(lport->remotenodeid, rnode->nodeid, NODEIDLEN);

	rport->remotenode = lnode;
	rport->remoteport = lport->portnum;
	set_portinfo(rport, rnode->type == SWITCH_NODE ? swport : hcaport);
	memcpy(rport->remotenodeid, lnode->nodeid, NODEIDLEN);
	lport->state = rport->state = 2;	// Initialilze
	lport->physstate = rport->physstate = 5;	// LinkUP
	if (lnode->sw)
		lnode->sw->portchange = 1;
	if (rnode->sw)
		rnode->sw->portchange = 1;

	lport->linkwidth = rport->linkwidth =
	    get_active_linkwidth(lport, rport);
	lport->linkspeed = rport->linkspeed =
	    get_active_linkspeed(lport, rport);

	if (lnode->type == SWITCH_NODE) {
		endport = node_get_port(lnode, 0);
		send_trap(endport, TRAP_128);
	}

	if (rnode->type == SWITCH_NODE) {
		endport = node_get_port(rnode, 0);
		send_trap(endport, TRAP_128);
	}

	return 0;
}

int connect_ports(void)
{
	Port *port, *e, *remoteport;
	Node *remote;
	int pconnected = 0;
	int type;

	for (port = ports, e = port + netports; port < e; port++) {
		PDEBUG
		    ("process port idx %zu: nodeid \"%s\" remotenodeid \"%s\" remoteport %d",
		     port - ports, port->node ? port->node->nodeid : "",
		     port->remotenodeid, port->remoteport);
		PDEBUG("from node 0x%016" PRIx64 " port 0x%016" PRIx64 " .",
		       port->node->nodeguid, port->portguid);
		if (port->remotenode)
			continue;

		type = port->node->type;
		if (port->node->type == SWITCH_NODE && port->portnum == 0) {	// SMA
			set_portinfo(port, smaport);
			port->state = 4;	// Active
			port->physstate = 5;	// LinkUP
			continue;
		}
		if (!port->remoteport) {	// unconnected port -> down
			set_portinfo(port, type == SWITCH_NODE ?
				     swport_down : hcaport_down);
			port->state = 1;	// Down
			port->physstate = 2;	// Polling
			continue;
		}

		if (!(remote = find_node(port->remotenodeid))) {
			IBWARN
			    ("can't find remote node \"%s\" connected to node \"%s\" port %d",
			     port->remotenodeid, port->node->nodeid,
			     port->portnum);
			return -1;
		}

		if (port->remoteport > remote->numports) {
			IBWARN("bad remote port %d in node \"%s\" connected to "
			       "node \"%s\" port %d",
			       port->remoteport, port->remotenodeid,
			       port->node->nodeid, port->portnum);
			return -1;
		}
		remoteport = ports + remote->portsbase + port->remoteport;
		if (remote->type != SWITCH_NODE)
			remoteport--;	// hca first port is 1

		if (port->remotealias[0]) {
			if (strcmp(port->remotealias, remoteport->alias) ||
			    remoteport->remoteport) {
				IBWARN("remote alias %s is not %s",
				       port->remotealias, remoteport->alias);
				return -1;
			}
		} else if (remoteport->remoteport != port->portnum ||
			   strncmp(remoteport->remotenodeid, port->node->nodeid,
				   NODEIDLEN)) {
			IBWARN
			    ("remote port %d in node \"%s\" is not connected to "
			     "node \"%s\" port %d (\"%s\" %d)",
			     port->remoteport, port->remotenodeid,
			     port->node->nodeid, port->portnum,
			     remoteport->remotenodeid, remoteport->remoteport);
			return -1;
		}

		link_ports(port->node, port, remoteport->node, remoteport);
		pconnected += 2;
	}

	DEBUG("%d ports connected", pconnected);
	return 0;
}

void reset_port(Port * port)
{
	int type = port->node->type;

	if (type == SWITCH_NODE && port->portnum == 0) {	// SMA
		set_portinfo(port, smaport);
		port->state = 4;	// Active
		port->physstate = 5;	// LinkUP
	} else {
		set_portinfo(port, type == SWITCH_NODE ?
			     swport_down : hcaport_down);
		port->state = 1;	// Down
		port->physstate = 2;	// Polling
	}

	port->lid = 0;
	port->lmc = 0;
	port->smlid = 0;
}

int readline(int fd, char *buf, int sz)
{
	int i;

	buf[0] = 0;

	for (i = 0; i < sz; i++, buf++)
		if (read(fd, buf, 1) != 1 || *buf == '\n')
			break;

	if (*buf == '\n' && sz - i > 0) {
		buf[1] = 0;
		i++;
	} else
		*buf = 0;
	inclines[inclevel > 0 ? inclevel - 1 : 0]++;
	return i;
}

Node *find_node(char *desc)
{
	Node *nd, *e;

	if (!desc)
		return 0;

	for (nd = nodes, e = nodes + netnodes; nd < e; nd++)
		if (!strcmp(desc, nd->nodeid))
			return nd;

	return 0;
}

Node *find_node_by_guid(uint64_t guid)
{
	Node *nd, *e;

	if (ignoreduplicate)
		return 0;

	for (nd = nodes, e = nodes + netnodes; nd < e; nd++)
		if (nd->nodeguid == guid)
			return nd;

	return 0;
}

Port *node_get_port(Node * node, int portnum)
{
	Port *port = ports + node->portsbase + portnum;

	if (node->type != SWITCH_NODE && portnum > 0)
		port--;

	return port;
}

int set_def(char *nodeid)
{
	Node *node = 0;

	if (!netports)
		return -1;	// no ports are defined in net

	if (nodeid && !(node = find_node(nodeid)))
		IBWARN("node %s not found - use default port!", nodeid);

	if (!node) {
		defport = ports;
		return 0;
	}

	defport = node_get_port(node, 0);
	return 0;
}

int alloc_core(void)
{
	if (!(nodes = calloc(maxnetnodes, sizeof(*nodes))))
		return -1;
	if (!(switchs = calloc(maxnetswitchs, sizeof(*switchs))))
		return -1;
	if (!(ports = calloc(maxnetports, sizeof(*ports))))
		return -1;
	if (!(lids = calloc(maxlinearcap, sizeof(*lids))))
		return -1;
	if (!(aliases = calloc(maxnetaliases, sizeof(*aliases))))
		return -1;
	return 0;
}
