/*
 * Copyright (c) 2004-2008 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2011 Mellanox Technologies LTD. All rights reserved.
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
#include <regex.h>
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

#define LINKSPEED_STR_SDR "SDR"
#define LINKSPEED_STR_DDR "DDR"
#define LINKSPEED_STR_QDR "QDR"
#define LINKSPEED_STR_FDR "FDR"
#define LINKSPEED_STR_EDR "EDR"
#define LINKSPEED_STR_HDR "HDR"
#define LINKSPEED_STR_NDR "NDR"
#define LINKSPEED_STR_FDR10 "FDR10"

static int inclines[MAX_INCLUDE];
static char *incfiles[MAX_INCLUDE];
static int inclevel;

Port *default_port;

static const uint8_t smaport[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xC0, 0x48,
	0x00, 0x00, 0x0F, 0xF9, 0x00, 0x03, 0x03, 0x01,
	0x14, 0x52, 0x00, 0x11, 0x10, 0x40, 0x00, 0x08,
	0x08, 0x03, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x1F, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x30, 0x00, 0x00,
};

static const uint8_t swport[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x02,
	0x12, 0x52, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x01 /* 0x11 */, 0x01,
};

static const uint8_t swport_down[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x01,
	0x11, 0x22, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xE9, 0x40, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 /* 0x11 */, 0x01,
};

static const uint8_t hcaport[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x00, 0x40, 0xC0, 0x48,
	0x00, 0x00, 0x0F, 0xF9, 0x01, 0x03, 0x03, 0x02,
	0x12, 0x52, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x20, 0x1F, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x30, 0x01 /* 0x11 */, 0x01,
};

static const uint8_t hcaport_down[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x00, 0x10, 0xC0, 0x48,
	0x00, 0x00, 0x0F, 0xF9, 0x01, 0x03, 0x03, 0x01,
	0x11, 0x22, 0x00, 0x11, 0x40, 0x40, 0x00, 0x08,
	0x08, 0x04, 0xE9, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x20, 0x1F, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x30, 0x01 /* 0x11 */, 0x01,
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

int maxnetnodes = MAXNETNODES;
int maxnetswitches = MAXNETSWITCHS;
int maxnetports = MAXNETPORTS;
int maxlinearcap = MAXLINEARCAP;
int maxmcastcap = MAXMCASTCAP;
int maxnetaliases = MAXNETALIASES;
int ignoreduplicate = 0;

Node *nodes;
Switch *switches;
Port *ports;
Port **lids;
static char (*aliases)[NODEIDLEN + NODEPREFIX + 1];	// aliases map format: "%s@%s"

int netnodes, netswitches, netports;
static int netaliases;

static uint64_t absguids[NODE_TYPES] = { ~0, 0x100000, 0x200000 };
static uint64_t guids[NODE_TYPES] = { ~0, 0x100000, 0x200000 };
static char netprefix[NODEPREFIX + 1];
static int netvendid;
static int netdevid;
static uint64_t netsysimgguid;
static int netwidth = DEFAULT_LINKWIDTH;
static int netspeed = DEFAULT_LINKSPEED;
static int netspeedext = DEFAULT_LINKSPEEDEXT;
static int mlnx_netspeed = DEFAULT_LINKSPEEDEXT;

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

static Switch *new_switch(Node * nd, int set_esp0)
{
	Switch *sw;

	if (netswitches >= maxnetswitches) {
		IBPANIC("no more switches (max %d)", maxnetswitches);
		return NULL;
	}

	sw = switches + netswitches++;

	sw->node = nd;
	sw->linearcap = maxlinearcap;	// assume identical val for all switches
	sw->multicastcap = maxmcastcap;	// assume identical val for all switches
	sw->numportmask = (nd->numports + MCASTMASKSIZE) / MCASTMASKSIZE;
	memcpy(sw->switchinfo, switchinfo, sizeof(sw->switchinfo));
	mad_set_field(sw->switchinfo, 0, IB_SW_LINEAR_FDB_CAP_F, sw->linearcap);
	mad_set_field(sw->switchinfo, 0, IB_SW_MCAST_FDB_CAP_F,
		      sw->multicastcap);
	if (set_esp0)
		mad_set_field(sw->switchinfo, 0, IB_SW_ENHANCED_PORT0_F,
			      set_esp0 > 0);
	sw->fdb = malloc(maxlinearcap*sizeof(sw->fdb[0]));
	sw->mfdb = malloc(maxmcastcap * sw->numportmask * sizeof(uint16_t));
	if (!sw->fdb || !sw->mfdb) {
		IBPANIC("new_switch: no mem: %m");
		return NULL;
	}
	memset(sw->fdb, 0xff, maxlinearcap*sizeof(sw->fdb[0]));
	memset(sw->mfdb, 0, maxmcastcap * sw->numportmask * sizeof(uint16_t));

	return sw;
}

static int build_nodeid(char *nodeid, size_t len, char *base)
{
	if (strchr(base, '#') || strchr(base, '@')) {
		IBWARN("bad nodeid \"%s\": '#' & '@' characters are reserved",
		       base);
		return -1;
	}

	snprintf(nodeid, len, "%s%s%s", netprefix, *netprefix ? "#" : "", base);

	return 0;
}

static Node *new_node(int type, char *nodename, char *nodedesc, int nodeports)
{
	int firstport = 1;
	char nodeid[NODEIDLEN];
	Node *nd;

	if (build_nodeid(nodeid, sizeof(nodeid), nodename) < 0)
		return NULL;

	if (find_node(nodeid)) {
		IBWARN("node id %s already exists", nodeid);
		return NULL;
	}

	if (netnodes >= maxnetnodes) {
		IBPANIC("no more nodes (max %d)", maxnetnodes);
		return NULL;
	}

	if (find_node_by_guid(guids[type])) {
		IBWARN("node %s guid %" PRIx64 " already exists",
		       node_type_name(type), guids[type]);
		return NULL;
	}

	nd = nodes + netnodes++;

	nd->type = type;
	nd->numports = nodeports;
	strncpy(nd->nodeid, nodeid, sizeof(nd->nodeid) - 1);
	strncpy(nd->nodedesc, nodedesc && *nodedesc ? nodedesc : nodeid,
		sizeof(nd->nodedesc) - 1);
	nd->sysguid = nd->nodeguid = guids[type];
	if (type == SWITCH_NODE) {
		nodeports++;	// port 0 is SMA
		firstport = 0;
		memcpy(nd->nodeinfo, swnodeinfo, sizeof(nd->nodeinfo));
		guids[type]++;	// reserve single guid;
	} else {
		memcpy(nd->nodeinfo, hcanodeinfo, sizeof(nd->nodeinfo));
		if (type == ROUTER_NODE)
			mad_set_field(nd->nodeinfo, 0, IB_NODE_TYPE_F, ROUTER_NODE);
		guids[type] += nodeports + 1;	// reserve guids;
	}

	mad_set_field(nd->nodeinfo, 0, IB_NODE_NPORTS_F, nd->numports);
	mad_set_field(nd->nodeinfo, 0, IB_NODE_VENDORID_F, netvendid);
	mad_set_field(nd->nodeinfo, 0, IB_NODE_DEVID_F, netdevid);

	mad_encode_field(nd->nodeinfo, IB_NODE_GUID_F, &nd->nodeguid);
	mad_encode_field(nd->nodeinfo, IB_NODE_PORT_GUID_F, &nd->nodeguid);
	mad_encode_field(nd->nodeinfo, IB_NODE_SYSTEM_GUID_F,
			 netsysimgguid ? &netsysimgguid : &nd->nodeguid);

	if ((nd->portsbase = new_ports(nd, nodeports, firstport)) < 0) {
		IBWARN("can't alloc %d ports for node %s", nodeports,
		       nd->nodeid);
		return NULL;
	}

	netvendid = 0;
	netsysimgguid = 0;

	return nd;
}

static int parse_node_ports(char *buf)
{
	while (*buf && !isdigit(*buf))
		buf++;
	return strtoul(buf, NULL, 0);
}

static char *parse_node_id(char *buf, char **rest_buf)
{
	char *s, *e = NULL;

	if (!(s = strchr(buf, '"')) || !(e = strchr(s + 1, '"'))) {
		IBWARN("can't find valid id in <%s>", buf);
		return NULL;
	}
	*e = 0;
	if (rest_buf)
		*rest_buf = e + 1;
	return s + 1;
}

static char *parse_node_desc(char *s, char **rest_buf)
{
	char *e = NULL;

	*rest_buf = s;
	s = strchr(s, '#');
	if (!s)
		return NULL;
	while (isspace(*++s))
		;
	if (*s == '\"') {
		s++;
		if ((e = strchr(s, '\"')))
			*e++ = '\0';
	} else if ((e = strstr(s, " enhanced port ")) ||
	    (e = strstr(s, " base port ")) ||
	    (e = strstr(s, " lid ")) ||
	    (e = strstr(s, " lmc ")))
		*e++ = '\0';
	*rest_buf = e;
	return s;
}

static int is_linkwidth_valid(int width)
{
	/* width is 1x 4x 8x 12x 2x */
	if (width < 1 || width > 31) {
		IBWARN("bad enabled width %d - should be between 1 to 31",
		       width);
		return 0;
	}
	return 1;
}

static int is_linkspeed_valid(int speed)
{
	/* speed is 2.5G, 5.0G, or 10.0G */
	if (speed < 1 || speed > 7) {
		IBWARN("bad speed %d - should be between 1 to 7", speed);
		return 0;
	}
	return 1;
}

static int is_linkspeedext_valid(int speed)
{
	/* extended speed is none, FDR, EDR, HDR, NDR, or some combination */
	if (speed < 0 || speed > 15) {
		IBWARN("bad extended speed %d = should be between 0 to 15", speed);
		return 0;
	}
	return 1;
}

static int parse_switch_esp0(char *line)
{
	if (strstr(line, "enhanced port 0"))
		return 1;
	else if (strstr(line, "base port 0"))
		return -1;
	else
		return 0;
}

static int parse_port_lid_and_lmc(Port * port, char *line)
{
	char *s;

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

static int parse_port_link_width_and_speed(Port * port, char *line)
{
	int rlid = 0;
	int width = 0;
	char speed[10];
	speed[0] = '\0';

	if (3 != sscanf(line, "lid %d %dx%9s", &rlid, &width, speed)) {
		IBWARN("failed parsing port connection type");
		return 0;
	}

	/* update port width */
	if (width == 12)
		port->linkwidthena = LINKWIDTH_1x_4x_12x;
	else if (width == 8)
		port->linkwidthena = LINKWIDTH_8x;
	else if (width == 4)
		port->linkwidthena = LINKWIDTH_1x_4x;
	else if (width == 1)
		port->linkwidthena = LINKWIDTH_1x;
	else if (width == 2)
		port->linkwidthena = LINKWIDTH_2x;
	else {
		IBWARN("cannot parse width / invalid width");
	}

	/* parse connection rate */
	if (!strncmp(speed, LINKSPEED_STR_SDR, strlen(speed))) {
		port->linkspeedena = LINKSPEED_SDR;
	} else if (!strncmp(speed, LINKSPEED_STR_DDR, strlen(speed))) {
		port->linkspeedena = LINKSPEED_SDR | LINKSPEED_DDR;
	} else if (!strncmp(speed, LINKSPEED_STR_QDR, strlen(speed))) {
		port->linkspeedena = LINKSPEED_QDR | LINKSPEED_SDR | LINKSPEED_DDR;
	} else if (!strncmp(speed, LINKSPEED_STR_FDR, strlen(speed))) {
		port->linkspeedextena = LINKSPEEDEXT_FDR;
		port->linkspeedena = LINKSPEED_QDR | LINKSPEED_SDR | LINKSPEED_DDR;
		port->mlnx_linkspeedena = MLNXLINKSPEED_FDR10;
	} else if (!strncmp(speed, LINKSPEED_STR_EDR, strlen(speed))) {
		port->linkspeedextena = LINKSPEEDEXT_FDR_EDR;
		port->linkspeedena = LINKSPEED_QDR | LINKSPEED_SDR | LINKSPEED_DDR;
		port->mlnx_linkspeedena = MLNXLINKSPEED_FDR10;
	} else if (!strncmp(speed, LINKSPEED_STR_HDR, strlen(speed))) {
		port->linkspeedextena = LINKSPEEDEXT_HDR_EDR_FDR;
		port->linkspeedena = LINKSPEED_QDR | LINKSPEED_SDR | LINKSPEED_DDR;
		port->mlnx_linkspeedena = MLNXLINKSPEED_FDR10;
	} else if (!strncmp(speed, LINKSPEED_STR_NDR, strlen(speed))) {
		port->linkspeedextena = LINKSPEEDEXT_NDR_HDR_EDR_FDR;
		port->linkspeedena = LINKSPEED_QDR | LINKSPEED_SDR | LINKSPEED_DDR;
		port->mlnx_linkspeedena = MLNXLINKSPEED_FDR10;
	} else if (!strncmp(speed, LINKSPEED_STR_FDR10, strlen(speed))){
		port->linkspeedena = LINKSPEED_QDR | LINKSPEED_SDR | LINKSPEED_DDR;
		port->mlnx_linkspeedena = MLNXLINKSPEED_FDR10;
	} else {
		IBWARN("cannot parse speed / invalid speed");
	}

	return 0;
}

static int parse_port_connection_data(Port * port, int type, char *line)
{
	int rc;
	char *line_connection_type = line;
	regex_t regex;
	regmatch_t regmatch[1];

	if (line == NULL) {
		IBWARN("cannot parse empty line");
		return -1;
	}

	regcomp(&regex,"lid[^\"]*$", 0);
	rc = regexec(&regex, line, 1, regmatch, 0);

	if (rc) {
		IBWARN("cannot parse remote lid and connection type");
		regfree(&regex);
		return 0;
	}

	line_connection_type = line + regmatch[0].rm_so;
	regfree(&regex);

	if (type == SWITCH_NODE) {
		/* expecting line with the following format:
		 * [1]	"H-000123456789ABCD"[2](123456789ABCE) 		# "description" lid 1 4xQDR ...
		 */
		if (parse_port_link_width_and_speed(port, line_connection_type))
			return -1;
	}
	if (type == HCA_NODE) {
		/* expecting line with the following format:
		 * [1](123456789ABCDE) 	"S-000123456789ABCDF"[2]		# lid 2 lmc 0 "description" lid 1 4xQDR ...
		 */
		if (parse_port_lid_and_lmc(port, line) ||
		    parse_port_link_width_and_speed(port, line_connection_type))
			return -1;
	}

	return 0;
}

static int parse_port_opt(Port * port, char *opt, char *val)
{
	int v;

	switch (*opt) {
	case 'w':
		v = strtoul(val, NULL, 0);
		if (!is_linkwidth_valid(v))
			return -1;

		port->linkwidthena = v;
		DEBUG("port %p linkwidth enabled set to %d", port,
		      port->linkwidthena);
		break;
	case 's':
		v = strtoul(val, NULL, 0);
		if (v && !is_linkspeed_valid(v))
			return -1;

		/* If 0, assume QDR */
		v = v ? v : LINKSPEED_QDR;

		port->linkspeedena = v;
		DEBUG("port %p linkspeed enabled set to %d", port,
		      port->linkspeedena);
		break;
	case 'e':
		v = strtoul(val, NULL, 0);
		if (!is_linkspeedext_valid(v))
			return -1;

		port->linkspeedextena = v;
		DEBUG("port %p linkspeedext enabled set to %d", port,
		      port->linkspeedextena);
		break;
	default:
		break;
	}
	return 0;
}

static void init_ports(Node * node, int type, int maxports)
{
	Port *port;
	unsigned ca_pkey_size, sw_pkey_size, size;
	unsigned i, j;

	ca_pkey_size = mad_get_field(node->nodeinfo, 0,
				     IB_NODE_PARTITION_CAP_F);
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
		port->linkspeedextena = netspeedext;
		port->linkspeedext = DEFAULT_LINKSPEEDEXT;
		port->mlnx_linkspeedena = mlnx_netspeed;
		port->mlnx_linkspeed = DEFAULT_MLNXLINKSPEED;

		size = (type == SWITCH_NODE && i) ? sw_pkey_size : ca_pkey_size;
		if (size) {
			port->pkey_tbl = calloc(size, sizeof(uint16_t));
			if (!port->pkey_tbl)
				IBPANIC("cannot alloc port's pkey table\n");
			port->pkey_tbl[0] = 0xffff;
		}

		size = node->sw ? maxports + 1 : 1;
		port->sl2vl = calloc(size, 8 * sizeof(uint8_t));
		if (!port->sl2vl) {
			IBPANIC("cannot alloc port's sl2vl table\n");
		}
		for (j = 0; j < size; j++)
			memcpy(port->sl2vl + 8 * j, default_sl2vl, 8);

		memcpy(port->vlarb_high, default_vlarb_high,
		       sizeof(default_vlarb_high));
		memcpy(port->vlarb_low, default_vlarb_low,
		       sizeof(default_vlarb_low));
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

static char *map_alias(char *alias)
{
	int i;
	int len = strlen(alias);

	for (i = 0; i < netaliases; i++) {
		if (strncmp(alias, aliases[i], len))
			continue;
		if (aliases[i][len] == '#')
			return aliases[i] + len + 1;
	}
	return NULL;
}

char *expand_name(char *base, char *name, char **portstr)
{
	char *s;

	if (!base)
		return NULL;

	if (!strchr(base, '@')) {
		if (netprefix[0] != 0 && !strchr(base, '#'))
			snprintf(name, NODEIDLEN, "%s#%s", netprefix, base);
		else
			strncpy(name, base, NODEIDLEN - 1);
		if (portstr)
			*portstr = NULL;
		PDEBUG("name %s port %s", name, portstr ? *portstr : NULL);
		return name;
	}

	snprintf(name, NODEIDLEN, "%s%s", base[0] == '@' ? netprefix : "", base);
	PDEBUG("alias %s", name);

	if (!(s = map_alias(name)))
		return NULL;

	strncpy(name, s, NODEIDLEN - 1);

	if (portstr) {
		*portstr = name;
		strsep(portstr, "[");
	}
	PDEBUG("name %s port %s", name, portstr ? *portstr : NULL);
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
	char remotenodeid[NODEIDLEN], *sp = NULL;
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
	PDEBUG("remotenodeid %s s %s sp %s", remotenodeid, s, sp);

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
	}
	if ((type == HCA_NODE || type == SWITCH_NODE) &&
	    line && parse_port_connection_data(port, type, line) < 0) {
		IBWARN("cannot parse port data");
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
	char *nodedesc;
	int ports, r;

	if (!(ports = parse_node_ports(line + 3)) ||
	    !(nodeid = parse_node_id(line, &line)))
		return 0;

	nodedesc = parse_node_desc(line, &line);

	if (!(nd = new_node(type, nodeid, nodedesc, ports)))
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
	char *nodedesc;
	int nports, r, esp0 = 0;

	if (!(nports = parse_node_ports(line + 6)) ||
	    !(nodeid = parse_node_id(line, &line)))
		return 0;

	nodedesc = parse_node_desc(line, &line);

	if (!(nd = new_node(SWITCH_NODE, nodeid, nodedesc, nports)))
		return 0;

	if (line)
		esp0 = parse_switch_esp0(line);

	if (!(sw = new_switch(nd, esp0)))
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
		IBWARN("bad assignment: missing '=|+' sign");
		return -1;
	}

	if (*s == '+')
		relative = 1;

	guidbase = strtoull(s + 1, NULL, 0);

	if (!relative) {
		absguids[type] = guidbase;
		guidbase = 0;
	}
	guids[type] = absguids[type] + guidbase;
	PDEBUG("new guidbase for %s: base 0x%" PRIx64 " current 0x%" PRIx64,
	       node_type_name(type), absguids[type],
	       guids[type]);
	return 1;
}

static int parse_vendid(int fd, char *line)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	netvendid = strtol(s + 1, NULL, 0);

	return 1;
}

static int parse_devid(int fd, char *line)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	netdevid = strtol(s + 1, NULL, 0);

	return 1;
}

static uint64_t parse_sysimgguid(int fd, char *line)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	netsysimgguid = strtoull(s + 1, NULL, 0);

	return 1;
}

static int parse_width(int fd, char *line)
{
	char *s;
	int width;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	width = strtol(s + 1, NULL, 0);
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
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	speed = strtol(s + 1, NULL, 0);
	if (!is_linkspeed_valid(speed)) {
		IBPANIC("invalid enabled link speed %d", speed);
		return -1;
	}

	netspeed = speed;
	return 1;
}

static int parse_speedext(int fd, char *line)
{
	char *s;
	int speed;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	speed = strtol(s + 1, NULL, 0);
	if (!is_linkspeedext_valid(speed)) {
		IBPANIC("invalid enabled link speed extended %d", speed);
		return -1;
	}

	netspeedext = speed;
	return 1;
}

static int parse_netprefix(int fd, char *line)
{
	char *s;

	if (!(s = strchr(line, '='))) {
		IBWARN("bad assignment: missing '=' sign");
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
		IBWARN("bad assignment: missing '=' sign");
		return -1;
	}

	*var = strtol(s + 1, NULL, 0);
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
		else if (!strncmp(line, "vendid", 6))
			r = parse_vendid(fd, line);
		else if (!strncmp(line, "devid", 5))
			r = parse_devid(fd, line);
		else if (!strncmp(line, "sysimgguid", 10))
			r = parse_sysimgguid(fd, line);
		else if (!strncmp(line, "width", 5))
			r = parse_width(fd, line);
		else if (!strncmp(line, "speed", 5))
			r = parse_speed(fd, line);
		else if (!strncmp(line, "extspeed", 8))
			r = parse_speedext(fd, line);
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
	if (width & LINKWIDTH_2x)
		return LINKWIDTH_2x;
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

static int get_active_linkspeedext(Port * lport, Port * rport)
{
	int speed = lport->linkspeedextena & rport->linkspeedextena;

	if (speed & LINKSPEEDEXT_NDR)
		return LINKSPEEDEXT_NDR;
	if (speed & LINKSPEEDEXT_HDR)
		return LINKSPEEDEXT_HDR;
	if (speed & LINKSPEEDEXT_EDR)
		return LINKSPEEDEXT_EDR;
	if (speed & LINKSPEEDEXT_FDR)
		return LINKSPEEDEXT_FDR;
	if (speed == LINKSPEEDEXT_NONE)
		return LINKSPEEDEXT_NONE;	// same as 0

	IBPANIC("mismatched enabled speedext between %" PRIx64 " P#%d S=%d and %"
		PRIx64 " P#%d S=%d", lport->portguid, lport->portnum,
		lport->linkspeedextena, rport->portguid, rport->portnum,
		rport->linkspeedextena);
	return 0;
}

static int get_active_mlnx_linkspeed(Port * lport, Port * rport)
{
	int speed = lport->mlnx_linkspeedena & rport->mlnx_linkspeedena;

	if (speed & MLNXLINKSPEED_FDR10)
		return MLNXLINKSPEED_FDR10;
	if (speed == MLNXLINKSPEED_NONE)
		return MLNXLINKSPEED_NONE; // same as 0

	IBPANIC("mismatched enabled mlnx speedext between %" PRIx64 " P#%d S=%d and %"
		PRIx64 " P#%d S=%d", lport->portguid, lport->portnum,
		lport->mlnx_linkspeedena, rport->portguid, rport->portnum,
		rport->mlnx_linkspeedena);
	return 0;
}

void update_portinfo(Port * p)
{
	uint8_t *pi = p->portinfo;

	mad_set_field(pi, 0, IB_PORT_LOCAL_PORT_F,
		      p->node->type == SWITCH_NODE ? 0 : p->portnum);
	mad_set_field64(pi, 0, IB_PORT_GID_PREFIX_F, p->subnet_prefix);
	mad_set_field(pi, 0, IB_PORT_LID_F, p->lid);
	mad_set_field(pi, 0, IB_PORT_SMLID_F, p->smlid);
	mad_set_field(pi, 0, IB_PORT_OPER_VLS_F, p->op_vls);
	mad_set_field(pi, 0, IB_PORT_LINK_WIDTH_ENABLED_F, p->linkwidthena);
	mad_set_field(pi, 0, IB_PORT_LINK_WIDTH_SUPPORTED_F, LINKWIDTH_1x_2x_4x_8x_12x);
	mad_set_field(pi, 0, IB_PORT_LINK_WIDTH_ACTIVE_F, p->linkwidth);
	mad_set_field(pi, 0, IB_PORT_LINK_SPEED_ENABLED_F, p->linkspeedena);
	mad_set_field(pi, 0, IB_PORT_LINK_SPEED_SUPPORTED_F, LINKSPEED_SDR_DDR_QDR);
	mad_set_field(pi, 0, IB_PORT_LINK_SPEED_ACTIVE_F, p->linkspeed);

	mad_set_field(pi, 0, IB_PORT_LMC_F, p->lmc);
	mad_set_field(pi, 0, IB_PORT_HOQ_LIFE_F, p->hoqlife);
	mad_set_field(pi, 0, IB_PORT_PHYS_STATE_F, p->physstate);
	mad_set_field(pi, 0, IB_PORT_STATE_F, p->state);

	if (p->linkspeedext) {
		mad_set_field(pi, 0, IB_PORT_LINK_SPEED_EXT_ENABLED_F, p->linkspeedextena);
		mad_set_field(pi, 0, IB_PORT_LINK_SPEED_EXT_SUPPORTED_F, LINKSPEEDEXT_NDR_HDR_EDR_FDR);
		mad_set_field(pi, 0, IB_PORT_LINK_SPEED_EXT_ACTIVE_F, p->linkspeedext);
	} else {
		mad_set_field(pi, 0, IB_PORT_LINK_SPEED_EXT_ENABLED_F, 0);
		mad_set_field(pi, 0, IB_PORT_LINK_SPEED_EXT_SUPPORTED_F, 0);
		mad_set_field(pi, 0, IB_PORT_LINK_SPEED_EXT_ACTIVE_F, 0);

		/* FDR10 support */
		if (p->mlnx_linkspeed) {
			mad_set_field(p->extportinfo, 0, IB_MLNX_EXT_PORT_LINK_SPEED_ENABLED_F, p->mlnx_linkspeedena);
			mad_set_field(p->extportinfo, 0, IB_MLNX_EXT_PORT_LINK_SPEED_SUPPORTED_F, p->mlnx_linkspeedena);
			mad_set_field(p->extportinfo, 0, IB_MLNX_EXT_PORT_LINK_SPEED_ACTIVE_F, p->mlnx_linkspeed);
		}
	}
}

static void set_portinfo(Port * p, const uint8_t portinfo[])
{
	memcpy(p->portinfo, portinfo, sizeof(p->portinfo));
	if (!p->op_vls)
		p->op_vls = mad_get_field(p->portinfo, 0, IB_PORT_VL_CAP_F);
}

int link_ports(Port * lport, Port * rport)
{
	Node *lnode = lport->node;
	Node *rnode = rport->node;
	Port *endport;

	if (lport->remotenode || rport->remotenode)
		return -1;

	lport->remotenode = rnode;
	lport->remoteport = rport->portnum;
	set_portinfo(lport, lnode->type == SWITCH_NODE ? swport : hcaport);
	memcpy(lport->remotenodeid, rnode->nodeid, sizeof(lport->remotenodeid));

	rport->remotenode = lnode;
	rport->remoteport = lport->portnum;
	set_portinfo(rport, rnode->type == SWITCH_NODE ? swport : hcaport);
	memcpy(rport->remotenodeid, lnode->nodeid, sizeof(rport->remotenodeid));
	lport->state = rport->state = 2;	// Initialize
	lport->physstate = rport->physstate = 5;	// LinkUP
	if (lnode->sw)
		lnode->sw->portchange = 1;
	if (rnode->sw)
		rnode->sw->portchange = 1;

	lport->linkwidth = rport->linkwidth =
	    get_active_linkwidth(lport, rport);
	lport->linkspeed = rport->linkspeed =
	    get_active_linkspeed(lport, rport);
	lport->mlnx_linkspeed = rport->mlnx_linkspeed =
	    get_active_mlnx_linkspeed(lport, rport);
	lport->linkspeedext = rport->linkspeedext =
	    get_active_linkspeedext(lport, rport);

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
				   sizeof(remoteport->remotenodeid))) {
			IBWARN
			    ("remote port %d in node \"%s\" is not connected to "
			     "node \"%s\" port %d (\"%s\" %d)",
			     port->remoteport, port->remotenodeid,
			     port->node->nodeid, port->portnum,
			     remoteport->remotenodeid, remoteport->remoteport);
			return -1;
		}

		link_ports(port, remoteport);
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
	if (i)
		inclines[inclevel > 0 ? inclevel - 1 : 0]++;
	return i;
}

Node *find_node(char *desc)
{
	Node *nd, *e;

	if (!desc)
		return NULL;

	for (nd = nodes, e = nodes + netnodes; nd < e; nd++)
		if (!strcmp(desc, nd->nodeid))
			return nd;

	return NULL;
}

Node *find_node_by_desc(char *desc)
{
	Node *nd, *e;

	if (!desc)
		return NULL;

	for (nd = nodes, e = nodes + netnodes; nd < e; nd++)
		if (!strcmp(desc, nd->nodedesc))
			return nd;

	return NULL;
}

Node *find_node_by_guid(uint64_t guid)
{
	Node *nd, *e;

	if (ignoreduplicate)
		return NULL;

	for (nd = nodes, e = nodes + netnodes; nd < e; nd++)
		if (nd->nodeguid == guid)
			return nd;

	return NULL;
}

Port *node_get_port(Node * node, int portnum)
{
	Port *port = ports + node->portsbase + portnum;

	if (node->type != SWITCH_NODE && portnum > 0)
		port--;

	return port;
}

int set_default_port(char *nodeid)
{
	Node *node = NULL;

	if (!netports)
		return -1;	// no ports are defined in net

	if (nodeid && !(node = find_node(nodeid)))
		IBWARN("node %s not found - use default port!", nodeid);

	default_port = node ? node_get_port(node, 0) : ports;

	return 0;
}

int alloc_core(void)
{
	if (!(nodes = calloc(maxnetnodes, sizeof(*nodes))))
		return -1;
	if (!(switches = calloc(maxnetswitches, sizeof(*switches))))
		return -1;
	if (!(ports = calloc(maxnetports, sizeof(*ports))))
		return -1;
	if (!(lids = calloc(maxlinearcap, sizeof(*lids))))
		return -1;
	if (!(aliases = calloc(maxnetaliases, sizeof(*aliases))))
		return -1;
	return 0;
}

void free_core(void)
{
	unsigned i;
	free(aliases);
	free(lids);
	for (i = 0; i < maxnetports ; i++) {
		if (ports[i].pkey_tbl)
			free(ports[i].pkey_tbl);
		if (ports[i].sl2vl)
			free(ports[i].sl2vl);
	}
	free(ports);
	for (i = 0; i < maxnetswitches ; i++) {
		if (switches[i].fdb)
			free(switches[i].fdb);
		if (switches[i].mfdb)
			free(switches[i].mfdb);
	}
	free(switches);
	free(nodes);
}
