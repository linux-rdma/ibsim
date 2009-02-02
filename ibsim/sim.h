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

#ifndef __SIM_H__
#define __SIM_H__

#include <infiniband/mad.h>

#define MAXNETNODES	2048
#define MAXNETSWITCHS	256
#define MAXNETPORTS	(MAXNETSWITCHS*36+MAXNETNODES*2)
#define MAXNETALIASES	MAXNETPORTS

#define MAXLINEARCAP	(30*1024)
#define MAXMCASTCAP	1024
#define LASTBLOCK32	(MAXMCASTCAP/32-1)
// NUMBEROFPORTMASK means that 32port switches could only be build
#define	NUMBEROFPORTMASK 2
#define LASTPORTMASK	(NUMBEROFPORTMASK-1)
// linkwidth == 4X - must be one width only 1,2 or 8
#define LINKWIDTH_1x        1
#define LINKWIDTH_4x        2
#define LINKWIDTH_8x        4
#define LINKWIDTH_12x       8
#define LINKWIDTH_1x_4x     3
#define LINKWIDTH_1x_4x_12x 11

#define LINKSPEED_SDR       1
#define LINKSPEED_DDR       2
#define LINKSPEED_QDR       4
#define LINKSPEED_SDR_DDR   3

#define	DEFAULT_LINKWIDTH	LINKWIDTH_4x
#define DEFAULT_LINKSPEED	LINKSPEED_SDR

#define NODEPREFIX	20
#define NODEIDLEN	65
#define ALIASLEN 	40

#define MAXHOPS 16

enum NODE_TYPES {
	NO_NODE = 0,
	HCA_NODE,
	SWITCH_NODE,
	ROUTER_NODE,

	NODE_TYPES
};

enum TRAP_TYPE_ID {
	TRAP_128,
	TRAP_144,

	TRAP_NUM_LAST
};

/* some PortInfo capmask fields */
enum PORTINFO_CAPMASK {
	CAPMASK_ISSM = (1<<1),
	CAPMASK_ISNOTICE = (1<<2),
	CAPMASK_ISTRAP = (1<<3),
	CAPMASK_ISCAPMASKTRAP = (1<<22),
};

enum GS_PERF_COUNTER_SELECT_MASK {
	GS_PERF_ERR_SYM_MASK = (1UL << 0),	// SYMBOL_ERROR_COUNTER
	GS_PERF_LINK_RECOVERS_MASK = (1UL << 1),	// LINK_ERROR_RECOVERY_COUNTER
	GS_PERF_LINK_DOWNED_MASK = (1UL << 2),	// LINK_DOWNED_COUNTER
	GS_PERF_ERR_RCV_MASK = (1UL << 3),	// PORT_RCV_ERRORS
	GS_PERF_ERR_PHYSRCV_MASK = (1UL << 4),	// PORT_RCV_REMOTE_PHYSICAL_ERRORS
	GS_PERF_ERR_SWITCH_REL_MASK = (1UL << 5),	// PORT_RCV_SWITCH_RELAY_ERRORS
	GS_PERF_XMT_DISCARDS_MASK = (1UL << 6),	// PORT_XMIT_DISCARDS
	GS_PERF_ERR_XMTCONSTR_MASK = (1UL << 7),	// PORT_XMIT_CONSTRAINT_ERRORS
	GS_PERF_ERR_RCVCONSTR_MASK = (1UL << 8),	// PORT_RCV_CONSTRAINT_ERRORS
	GS_PERF_ERR_LOCALINTEG_MASK = (1UL << 9),	// LOCAL_LINK_INTEGRITY_ERRORS
	GS_PERF_ERR_EXCESS_OVR_MASK = (1UL << 10),	// EXCESSIVE_BUFFER_OVERRUN_ERRORS
	GS_PERF_VL15_DROPPED_MASK = (1UL << 11),
	GS_PERF_XMT_BYTES_MASK = (1UL << 12),	// PORT_XMIT_DATA
	GS_PERF_RCV_BYTES_MASK = (1UL << 13),	// PORT_RCV_DATA
	GS_PERF_XMT_PKTS_MASK = (1UL << 14),	// PORT_XMIT_PKTS
	GS_PERF_RCV_PKTS_MASK = (1UL << 15),	// PORT_RCV_PKTS
};

enum GS_PC_EXT_SELECT_MASK {
	GS_PC_EXT_XMIT_DATA = 1 << 0,
	GS_PC_EXT_RECV_DATA = 1 << 1,
	GS_PC_EXT_XMIT_PKTS = 1 << 2,
	GS_PC_EXT_RECV_PKTS = 1 << 3,
	GS_PC_EXT_UCAST_XMIT = 1 << 4,
	GS_PC_EXT_UCAST_RECV = 1 << 5,
	GS_PC_EXT_MCAST_XMIT = 1 << 6,
	GS_PC_EXT_MCAST_RECV = 1 << 7,
};

enum GS_PERF_COUNTER_SELECT_LIMIT {
	GS_PERF_ERR_SYM_LIMIT = 0xffff,
	GS_PERF_LINK_RECOVERS_LIMIT = 0xff,
	GS_PERF_LINK_DOWNED_LIMIT = 0xff,
	GS_PERF_ERR_RCV_LIMIT = 0xffff,
	GS_PERF_ERR_PHYSRCV_LIMIT = 0xffff,
	GS_PERF_ERR_SWITCH_REL_LIMIT = 0xffff,
	GS_PERF_XMT_DISCARDS_LIMIT = 0xffff,
	GS_PERF_ERR_XMTCONSTR_LIMIT = 0xff,
	GS_PERF_ERR_RCVCONSTR_LIMIT = 0xff,
	GS_PERF_ERR_LOCALINTEG_LIMIT = 0xf,
	GS_PERF_ERR_EXCESS_OVR_LIMIT = 0xf,
	GS_PERF_VL15_DROPPED_LIMIT = 0xffff,
	GS_PERF_XMT_BYTES_LIMIT = 0xffffffff,
	GS_PERF_RCV_BYTES_LIMIT = 0xffffffff,
	GS_PERF_XMT_PKTS_LIMIT = 0xffffffff,
	GS_PERF_RCV_PKTS_LIMIT = 0xffffffff,
};

typedef struct Port Port;
typedef struct Portinfo Portinfo;
typedef struct Switch Switch;
typedef struct Nodeinfo Nodeinfo;
typedef struct Node Node;
typedef struct Client Client;
typedef struct Portcounters Portcounters;

struct Portinfo {
	int localport;
	int linkwidthen;
	int linkspeeden;
};

struct Portcounters {
	uint64_t ext_xmit_data;
	uint64_t ext_recv_data;
	uint64_t ext_xmit_pkts;
	uint64_t ext_recv_pkts;
	uint64_t ext_ucast_xmit;
	uint64_t ext_ucast_recv;
	uint64_t ext_mcast_xmit;
	uint64_t ext_mcast_recv;
	uint32_t flow_xmt_pkts;
	uint32_t flow_xmt_bytes;
	uint32_t flow_rcv_pkts;
	uint32_t flow_rcv_bytes;
	uint16_t xmitdiscards;
	uint16_t vl15dropped;
	uint16_t linkrecovers;
	uint8_t linkdowned;
	uint16_t errs_rcv;
	uint16_t errs_sym;
	uint8_t errs_localinteg;
	uint16_t errs_remphysrcv;
	uint8_t errs_xmtconstraint;
	uint8_t errs_rcvconstraint;
	uint16_t errs_rcvswitchrelay;
	uint8_t errs_excessbufovrrun;
};

struct Port {
	uint64_t portguid;
	int portnum;
	int lid;
	int smlid;
	int linkwidth;
	int linkwidthena;
	int linkspeed;
	int linkspeedena;
	int state;
	int physstate;
	int lmc;
	int hoqlife;
	uint8_t op_vls;
	uint8_t portinfo[64];

	char remotenodeid[NODEIDLEN];
	char remotealias[ALIASLEN + 1];
	char alias[ALIASLEN + 1];
	Node *remotenode;
	int remoteport;
	Node *previous_remotenode;
	int previous_remoteport;
	int errrate;
	uint16_t errattr;
	Node *node;
	Portcounters portcounters;
	uint16_t *pkey_tbl;
	uint8_t *sl2vl;
	struct vlarb {
		uint8_t vl;
		uint8_t weight;
	} vlarb_high[64], vlarb_low[64];
};

struct Switch {
	int linearcap;
//      int randomcap;
	int multicastcap;
	int linearFDBtop;
	int portchange;
	int lifetime;
	uint8_t switchinfo[64];
	Node *node;
	uint8_t *fdb;
	uint8_t *mfdb;
};

struct Node {
	int type;
	int numports;
	uint64_t sysguid;
	uint64_t nodeguid;	// also portguid
	int portsbase;		// in port table
	char nodeid[NODEIDLEN];	// contain nodeid[NODEIDLEN]
	uint8_t nodeinfo[64];
	char nodedesc[64];
	Switch *sw;
	Client *clist;		// client list
};

struct Nodeinfo {
	int localport;
};

struct Client {
	int id;
	int pid;
	Port *port;
	int qp;
	int issm;
	int fd;
};

// ibsim.c
int list_connections(FILE * out);
Client *find_client(Port * port, int response, int qp, uint64_t trid);
int disconnect_client(int id);

// sim_net.c
Node *find_node(char *desc);
Node *find_node_by_desc(char *desc);
Node *find_node_by_guid(uint64_t guid);
const char *node_type_name(unsigned type);
Port *node_get_port(Node * node, int portnum);
void reset_port(Port * port);
int link_ports(Port * lport, Port * rport);
void update_portinfo(Port * p);
int build_net(char *netconf);
int connect_ports(void);
char *expand_name(char *base, char *name, char **portstr);
int read_netconf(char *name, FILE * out);
int set_default_port(char *nodeid);
int readline(int fd, char *buf, int sz);

// sim_cmd.c
int do_cmd(char *buf, FILE *f);
int sim_cmd_file(FILE * file, char *line);
void *sim_cmd_thread(void *file);

// sim_mad.c
int process_packet(Client * cl, void *p, int size, Client ** dcl);
int send_trap(Port * port, int trapnum);

extern Port *default_port;
extern int simverb, modified;
extern int netstarted;

#endif				/* __SIM_H__ */
