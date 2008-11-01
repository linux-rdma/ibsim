/*
 * Copyright (c) 2006-2008 Voltaire, Inc. All rights reserved.
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

#ifndef _IBSIM_H_
#define _IBSIM_H_

#include <stdint.h>

#include <sys/un.h>
#include <netinet/in.h>


struct sim_vendor {
	uint32_t vendor_id;	/* Vendor ID */
	uint32_t vendor_part_id;	/* Vendor Part ID */
	uint32_t hw_ver;	/* Hardware Version */
	uint64_t fw_ver;	/* Device's firmware version (device specific) */
};

struct sim_port {
	uint16_t lid;		/* Base IB_LID */
	uint8_t state;		/* Port state */
};

#define IBSIM_MAX_CLIENTS 10

#define IBSIM_DEFAULT_SERVER_PORT 7070
#define SIM_BASENAME	"sim"

#define SIM_MAGIC	0xdeadbeef
#define SIM_CTL_MAX_DATA	64

struct sim_request {
	uint32_t dlid;
	uint32_t slid;
	uint32_t dqp;
	uint32_t sqp;
	uint32_t status;
	uint64_t length;
	char mad[256];
};

enum SIM_CTL_TYPES {
	SIM_CTL_ERROR,		/* reply type */
	SIM_CTL_CONNECT,
	SIM_CTL_DISCONNECT,
	SIM_CTL_GET_PORT,
	SIM_CTL_GET_VENDOR,
	SIM_CTL_GET_GID,
	SIM_CTL_GET_GUID,
	SIM_CTL_GET_NODEINFO,
	SIM_CTL_GET_PORTINFO,
	SIM_CTL_SET_ISSM,
	SIM_CTL_GET_PKEYS,

	SIM_CTL_LAST
};

struct sim_ctl {
	uint32_t magic;
	uint32_t clientid;
	uint32_t type;
	uint32_t len;
	char data[SIM_CTL_MAX_DATA];
};

struct sim_client_info {
	uint32_t id;		/* conn id in call, client id in return */
	uint32_t qp;
	uint32_t issm;		/* accept request for qp 0 & 1 */
	char nodeid[32];
};

union name_t {
	struct sockaddr name;
	struct sockaddr_un name_u;
	struct sockaddr_in name_i;
};

#endif				/* _IBSIM_H_ */
