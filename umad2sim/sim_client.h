/*
 * Copyright (c) 2006,2007 Voltaire, Inc. All rights reserved.
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

#ifndef _SIM_CLIENT_H_
#define _SIM_CLIENT_H_

#include <ibsim.h>

struct sim_client {
	int clientid;
	int fd_pktin, fd_pktout, fd_ctl;
	struct sim_vendor vendor;
	uint8_t nodeinfo[64];
	uint8_t portinfo[64];
	uint8_t extportinfo[64];
	uint16_t pkeys[SIM_CTL_MAX_DATA/sizeof(uint16_t)];
};

extern int sim_client_set_sm(struct sim_client *sc, unsigned issm);
extern int sim_client_init(struct sim_client *sc);
extern void sim_client_exit(struct sim_client *sc);

#endif				/* _SIM_CLIENT_H_ */
