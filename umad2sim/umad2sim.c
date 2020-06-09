/*
 * Copyright (c) 2006-2008 Voltaire, Inc. All rights reserved.
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

#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <infiniband/umad.h>
#include <infiniband/mad.h>

#include <sim_client.h>

#ifdef UMAD2SIM_NOISY_DEBUG
#undef DEBUG
#define DEBUG(fmt...) fprintf(stderr, fmt)
#else
#define DEBUG(fmt...)
#endif
#define ERROR(fmt...) fprintf(stderr, "ERR: " fmt)

#define arrsize(a) (sizeof(a)/sizeof(a[0]))

#define EVENT_NO_TIMEOUT	0xFFFFFFFF
#define FD_TIMEOUT	12

#define IB_PORT_EXT_SPEED_SUPPORTED_MASK (1<<14)

struct umad_buf_t {
	ssize_t size;
	char *umad;
};

struct list_elem_t {
	struct umad_buf_t *data;
	struct list_elem_t *next;
};

struct msg_queue_t {
	struct list_elem_t *tail;
	struct  list_elem_t *head;
	ssize_t queue_size;
};

struct fd_event_t {
	pthread_cond_t condvar;
	pthread_mutex_t mutex;
};

struct fd_data_t {
	struct fd_event_t fd_event;
	struct msg_queue_t *mqueue;
} fd_data_t;


struct ib_user_mad_reg_req {
	uint32_t id;
	uint32_t method_mask[4];
	uint8_t qpn;
	uint8_t mgmt_class;
	uint8_t mgmt_class_version;
	uint8_t oui[3];
	uint8_t rmpp_version;
};

#define FD_PER_DEVICE 8

struct umad2sim_dev {
	pthread_t thread_id;
	unsigned num;
	char name[32];
	uint8_t port;
	struct sim_client sim_client;
	unsigned agent_idx[256];
	unsigned agent_fds[256];
	struct ib_user_mad_reg_req agents[32];
	char umad_path[256];
	char issm_path[256];
	struct fd_data_t *fds[FD_PER_DEVICE];
 };

static int (*real_open) (const char *path, int flags, ...);
static int (*real_close) (int fd);
static ssize_t(*real_read) (int fd, void *buf, size_t count);
static ssize_t(*real_write) (int fd, const void *buf, size_t count);
static int (*real_poll) (struct pollfd * pfds, nfds_t nfds, int timeout);
static int (*real_ioctl) (int d, int request, ...);
static DIR *(*real_opendir) (const char *dir);
#if __GLIBC_PREREQ(2,10)
static int (*real_scandir) (const char *dir, struct dirent *** namelist,
			    int (*filter) (const struct dirent *),
			    int (*compar) (const struct dirent **,
					   const struct dirent **));
#else
static int (*real_scandir) (const char *dir, struct dirent *** namelist,
			    int (*filter) (const struct dirent *),
			    int (*compar) (const void *, const void *));
#endif

static char sysfs_infiniband_dir[] = SYS_INFINIBAND;
static char sysfs_infiniband_mad_dir[] = IB_UMAD_ABI_DIR;
static char umad_dev_dir[] = "/dev/infiniband";

static char umad2sim_sysfs_prefix[32];

static unsigned umad2sim_initialized;
static struct umad2sim_dev *devices[32];

static pthread_mutex_t global_devices_mutex;

static ssize_t fd_data_mqueue_size(struct fd_data_t *fd_data);

static int fd_event_init(struct fd_event_t * const p_event)
{
	pthread_cond_init(&p_event->condvar, NULL);
	pthread_mutex_init(&p_event->mutex, NULL);

	return 0;
}

static void fd_event_destroy(struct fd_event_t * const p_event)
{
	pthread_cond_broadcast(&p_event->condvar);
	pthread_cond_destroy(&p_event->condvar);
	pthread_mutex_destroy(&p_event->mutex);
}

static void fd_event_signal(struct fd_event_t * const p_event)
{

	pthread_mutex_lock(&p_event->mutex);
	pthread_cond_signal(&p_event->condvar);
	pthread_mutex_unlock(&p_event->mutex);
}

static int fd_event_wait_on(struct fd_data_t * const fd_data,
			    const uint32_t wait_us)
{
	int status = -1;
	int wait_ret;
	struct timespec timeout;
	struct timeval curtime;
	struct fd_event_t *p_event = &fd_data->fd_event;
	ssize_t size;

	pthread_mutex_lock(&global_devices_mutex);
	size = fd_data_mqueue_size(fd_data);
	pthread_mutex_unlock(&global_devices_mutex);

	if (size)
		return 0;

	if (wait_us == 0)
		return FD_TIMEOUT;

	pthread_mutex_lock(&p_event->mutex);
	if (wait_us == EVENT_NO_TIMEOUT) {
		/* Wait for condition variable to be signaled */
		if (!pthread_cond_wait(&p_event->condvar, &p_event->mutex))
			status = 0;
		pthread_mutex_unlock(&p_event->mutex);
		return status;
	}

	if (gettimeofday(&curtime, NULL) == 0) {
		unsigned long long n_sec =
			curtime.tv_usec*1000 + ((wait_us % 1000000)) * 1000;
			timeout.tv_sec = curtime.tv_sec + (wait_us / 1000000)
			    + (n_sec / 1000000000);
			timeout.tv_nsec = n_sec % 1000000000;

			wait_ret = pthread_cond_timedwait(&p_event->condvar,
							  &p_event->mutex,
							  &timeout);
			pthread_mutex_unlock(&p_event->mutex);
			if (wait_ret == 0) {
				pthread_mutex_lock(&global_devices_mutex);
				size = fd_data_mqueue_size(fd_data);
				pthread_mutex_unlock(&global_devices_mutex);
				status = size ? 0 : -1;
			} else if (wait_ret == ETIMEDOUT)
					status = FD_TIMEOUT;
	}
	return status;
}

static struct umad_buf_t *alloc_umad_buf(ssize_t size)
{
	struct umad_buf_t *buf;

	buf = (struct umad_buf_t *) malloc(sizeof(struct umad_buf_t));
	if (!buf)
		return NULL;

	buf->umad = malloc(size);
	if (!buf->umad) {
		free(buf);
		return NULL;
	}

	buf->size = size;

	return buf;
}

static void free_umad_buf(struct umad_buf_t *buf)
{
	free(buf->umad);
	buf->size = 0;
	free(buf);
}

static struct msg_queue_t *mqueue_create(void)
{
	struct msg_queue_t *ptr;

	ptr = (struct msg_queue_t *) malloc(sizeof(struct msg_queue_t));
	if (!ptr)
		return NULL;

	ptr->head = NULL;
	ptr->tail = NULL;
	ptr->queue_size = 0;

	return ptr;
}

static struct list_elem_t *mqueue_add_tail(struct msg_queue_t *mqueue,
					   void *data)
{
	struct list_elem_t *ptr;

	ptr = (struct list_elem_t *) malloc(sizeof(struct list_elem_t));
	if (!ptr)
		return NULL;

	ptr->data = data;
	ptr->next = NULL;

	if (mqueue->head == NULL) {
		mqueue->tail = ptr;
		mqueue->head = mqueue->tail;
	} else {
		mqueue->tail->next = ptr;
		mqueue->tail = ptr;
	}
	mqueue->queue_size++;
	return ptr;
}

static ssize_t mqueue_get_size(struct msg_queue_t *mqueue)
{
	return mqueue->queue_size;
}

static struct list_elem_t *mqueue_remove_head(struct msg_queue_t *mqueue)
{
	struct list_elem_t *ptr;

	if (mqueue->head == NULL)
		return NULL;

	ptr = mqueue->head;
	if (mqueue->head == mqueue->tail) {
		mqueue->head = NULL;
		mqueue->tail = NULL;
	} else {
		mqueue->head = ptr->next;
	}

	mqueue->queue_size--;
	return ptr;
}

static void mqueue_destroy(struct msg_queue_t *mqueue)
{
	free(mqueue);
}

static struct fd_data_t *fd_data_create()
{
	struct fd_data_t *ptr;
	ptr = (struct fd_data_t *) malloc(sizeof(struct fd_data_t));
	if (!ptr)
		return NULL;

	ptr->mqueue = mqueue_create();
	if (!ptr->mqueue) {
		free(ptr);
		return NULL;
	}

	fd_event_init(&ptr->fd_event);

	return ptr;
}

/* should be called under global lock */
static struct umad_buf_t *fd_data_dequeue(struct fd_data_t *fd_data)
{
	struct list_elem_t *ptr;
	struct umad_buf_t *data_ptr = NULL;
	ptr = mqueue_remove_head(fd_data->mqueue);
	if (ptr) {
		data_ptr = ptr->data;
		free(ptr);
	}
	return data_ptr;
}
/* should be called under global lock */
static void fd_data_release(struct fd_data_t *fd_data)
{
	struct umad_buf_t *ptr;
	while ((ptr = fd_data_dequeue(fd_data)) != NULL) {
		free_umad_buf(ptr);
	}

	mqueue_destroy(fd_data->mqueue);
	fd_event_destroy(&fd_data->fd_event);
	free(fd_data);
}

/* should be called under global lock */
static int fd_data_enqueue(struct fd_data_t *fd_data, void *data)
{
	struct list_elem_t *ptr;
	int result = 0;

	ptr = mqueue_add_tail(fd_data->mqueue, data);
	if (!ptr)
		result = -1;
	return result;
}

/* should be called under global lock */
static struct fd_data_t *get_fd_data(struct umad2sim_dev *dev, unsigned fd)
{
	if (fd < 1024 && fd >= 2048)
		return NULL;

	if (!dev)
		return NULL;

	return dev->fds[(fd - 1024) % FD_PER_DEVICE];
}

/* should be called under global lock */
static ssize_t fd_data_mqueue_size(struct fd_data_t *fd_data)
{
	return mqueue_get_size(fd_data->mqueue);
}

/* Returns index into dev->fds where new fd_data_t pointer was stored */
static int get_new_fd(struct umad2sim_dev *dev)
{
	int i;
	for (i=0; i<FD_PER_DEVICE; i++) {
		if (dev->fds[i] != NULL)
			continue;
		dev->fds[i] = fd_data_create();
		return (dev->fds[i] == NULL) ? -1 : i;
	}
	/* all FDs allocated */
	return -1;
}

static struct umad2sim_dev *fd_to_dev(unsigned fd)
{
	if (fd >= 2048)
		return devices[fd - 2048];
	if (fd >= 1024)
		return devices[(fd - 1024) / FD_PER_DEVICE];

	return NULL;
}

static int close_fd(unsigned fd)
{
	struct umad2sim_dev *dev;
	int i,idx;
	struct fd_data_t * fd_data;

	if (fd < 1024)
		return 0;
	pthread_mutex_lock(&global_devices_mutex);
	if (!(dev = fd_to_dev(fd))) {
		pthread_mutex_unlock(&global_devices_mutex);
		return 0;
	}
	if (fd >= 2048) {
		sim_client_set_sm(&dev->sim_client, 0);
		pthread_mutex_unlock(&global_devices_mutex);
		return 0;
	}

	fd_data = get_fd_data(dev, fd);
	if (fd_data)
		fd_data_release(fd_data);

	for (i=0; i<256; i++) {
		if (dev->agent_fds[i] == fd) {
			dev->agent_fds[i]=-1;
			idx = dev->agent_idx[i];
			dev->agents[idx].id = (uint32_t)(-1);
			dev->agent_idx[i]=-1;
			break;
		}
	}
	dev->fds[(fd - 1024) % FD_PER_DEVICE] = NULL;
	pthread_mutex_unlock(&global_devices_mutex);
	return 0;
}

/*
 *  sysfs stuff
 *
 */

static int is_sysfs_file(const char *path)
{
	return !strncmp(path, sysfs_infiniband_dir,
			strlen(sysfs_infiniband_dir)) ||
	    !strncmp(path, sysfs_infiniband_mad_dir,
		     strlen(sysfs_infiniband_mad_dir));
}

static void convert_sysfs_path(char *new_path, unsigned size,
			       const char *old_path)
{
	snprintf(new_path, size, "%s/%s", umad2sim_sysfs_prefix, old_path);
}

static void make_path(char *path)
{
	char dir[1024];
	char *p;

	convert_sysfs_path(dir, sizeof(dir), path);
	p = dir;
	do {
		p = strchr(p, '/');
		if (p)
			*p = '\0';
		if (mkdir(dir, 0755) && errno != EEXIST)
			IBPANIC("Failed to make directory <%s>", dir);
		if (p) {
			*p = '/';
			p++;
		}
	} while (p && p[0]);
}

static int file_printf(char *path, char *name, const char *fmt, ...)
{
	char file_name[1024];
	va_list args;
	FILE *f;
	int ret;

	convert_sysfs_path(file_name, sizeof(file_name), path);
	strncat(file_name, "/", sizeof(file_name) - strlen(file_name) - 1);
	strncat(file_name, name, sizeof(file_name) - strlen(file_name) - 1);
	unlink(file_name);
	f = fopen(file_name, "w");
	if (!f) {
		perror("fopen");
		return -1;
	}
	va_start(args, fmt);
	ret = vfprintf(f, fmt, args);
	va_end(args);
	fclose(f);

	return ret;
}

static int dev_sysfs_create(struct umad2sim_dev *dev)
{
	char path[1024];
	uint64_t gid, guid;
	uint32_t val, speed;
	struct sim_client *sc = &dev->sim_client;
	char *str;
	uint8_t *portinfo;
	int i;

	/* /sys/class/infiniband_mad/abi_version */
	snprintf(path, sizeof(path), "%s", sysfs_infiniband_mad_dir);
	make_path(path);
	file_printf(path, IB_UMAD_ABI_FILE, "%u\n", IB_UMAD_ABI_VERSION);

	/* /sys/class/infiniband/mthca0/ */
	snprintf(path, sizeof(path), "%s/%s", sysfs_infiniband_dir, dev->name);
	make_path(path);

	/* /sys/class/infiniband/mthca0/node_type */
	val = mad_get_field(sc->nodeinfo, 0, IB_NODE_TYPE_F);
	if (val == 1)
		str = "CA";
	else if (val == 2)
		str = "SWITCH";
	else if (val == 3)
		str = "ROUTER";
	else
		str = "<unknown>";
	file_printf(path, SYS_NODE_TYPE, "%x: %s\n", val, str);

	/* /sys/class/infiniband/mthca0/fw_ver */
	file_printf(path, SYS_CA_FW_VERS, "%llx\n", sc->vendor.fw_ver);
	//file_printf(path, SYS_CA_FW_VERS, "3.2.2\n");

	/* /sys/class/infiniband/mthca0/hw_rev */
	file_printf(path, SYS_CA_HW_VERS, "%x\n", sc->vendor.hw_ver);

	/* /sys/class/infiniband/mthca0/hca_type */
	file_printf(path, SYS_CA_TYPE, "%s\n", "simulator");

	/* /sys/class/infiniband/mthca0/node_guid */
	guid = mad_get_field64(sc->nodeinfo, 0, IB_NODE_GUID_F);
	file_printf(path, SYS_CA_NODE_GUID, "%04x:%04x:%04x:%04x\n",
		    (uint16_t) ((guid >> 48) & 0xffff),
		    (uint16_t) ((guid >> 32) & 0xffff),
		    (uint16_t) ((guid >> 16) & 0xffff),
		    (uint16_t) ((guid >> 0) & 0xffff));

	/* /sys/class/infiniband/mthca0/sys_image_guid */
	guid = mad_get_field64(sc->nodeinfo, 0, IB_NODE_SYSTEM_GUID_F);
	file_printf(path, SYS_CA_SYS_GUID, "%04x:%04x:%04x:%04x\n",
		    (uint16_t) ((guid >> 48) & 0xffff),
		    (uint16_t) ((guid >> 32) & 0xffff),
		    (uint16_t) ((guid >> 16) & 0xffff),
		    (uint16_t) ((guid >> 0) & 0xffff));

	/* /sys/class/infiniband/mthca0/ports/ */
	strncat(path, "/ports", sizeof(path) - strlen(path) - 1);
	make_path(path);

	portinfo = sc->portinfo;

	/* /sys/class/infiniband/mthca0/ports/1/ */
	val = mad_get_field(portinfo, 0, IB_PORT_LOCAL_PORT_F);
	snprintf(path + strlen(path), sizeof(path) - strlen(path), "/%u", val);
	make_path(path);

	/* /sys/class/infiniband/mthca0/ports/1/lid_mask_count */
	val = mad_get_field(portinfo, 0, IB_PORT_LMC_F);
	file_printf(path, SYS_PORT_LMC, "%d", val);

	/* /sys/class/infiniband/mthca0/ports/1/sm_lid */
	val = mad_get_field(portinfo, 0, IB_PORT_SMLID_F);
	file_printf(path, SYS_PORT_SMLID, "0x%x", val);

	/* /sys/class/infiniband/mthca0/ports/1/sm_sl */
	val = mad_get_field(portinfo, 0, IB_PORT_SMSL_F);
	file_printf(path, SYS_PORT_SMSL, "%d", val);

	/* /sys/class/infiniband/mthca0/ports/1/lid */
	val = mad_get_field(portinfo, 0, IB_PORT_LID_F);
	file_printf(path, SYS_PORT_LID, "0x%x", val);

	/* /sys/class/infiniband/mthca0/ports/1/state */
	val = mad_get_field(portinfo, 0, IB_PORT_STATE_F);
	if (val == 0)
		str = "NOP";
	else if (val == 1)
		str = "DOWN";
	else if (val == 2)
		str = "INIT";
	else if (val == 3)
		str = "ARMED";
	else if (val == 4)
		str = "ACTIVE";
	else if (val == 5)
		str = "ACTIVE_DEFER";
	else
		str = "<unknown>";
	file_printf(path, SYS_PORT_STATE, "%d: %s\n", val, str);

	/* /sys/class/infiniband/mthca0/ports/1/phys_state */
	val = mad_get_field(portinfo, 0, IB_PORT_PHYS_STATE_F);
	if (val == 1)
		str = "Sleep";
	else if (val == 2)
		str = "Polling";
	else if (val == 3)
		str = "Disabled";
	else if (val == 4)
		str = "PortConfigurationTraining";
	else if (val == 5)
		str = "LinkUp";
	else if (val == 6)
		str = "LinkErrorRecovery";
	else if (val == 7)
		str = "Phy Test";
	else
		str = "<unknown>";
	file_printf(path, SYS_PORT_PHY_STATE, "%d: %s\n", val, str);

	/* /sys/class/infiniband/mthca0/ports/1/rate */
	val = mad_get_field(portinfo, 0, IB_PORT_CAPMASK_F);
	if (val & IB_PORT_EXT_SPEED_SUPPORTED_MASK)
		speed = mad_get_field(portinfo, 0,
				      IB_PORT_LINK_SPEED_EXT_ACTIVE_F);
	else
		speed = 0;
	val = mad_get_field(portinfo, 0, IB_PORT_LINK_WIDTH_ACTIVE_F);
	if (val == 1)
		val = 1;
	else if (val == 2)
		val = 4;
	else if (val == 4)
		val = 8;
	else if (val == 8)
		val = 12;
	else
		val = 0;
	if (!speed) {
		speed = mad_get_field(portinfo, 0, IB_PORT_LINK_SPEED_ACTIVE_F);
		if (speed == 2)
			str = " DDR";
		else if (speed == 4)
			str = " QDR";
		else
			str = "";
		file_printf(path, SYS_PORT_RATE, "%d%s Gb/sec (%dX%s)\n",
			    (val * speed * 25) / 10,
			    (val * speed * 25) % 10 ? ".5" : "", val, str);
	} else {
		if (speed == 1)
			str = " FDR";
		else if (speed == 2)
			str = " EDR";
		else if (speed == 4)
			str = " HDR";
		else
			str = "";
		file_printf(path, SYS_PORT_RATE, "%d Gb/sec (%dX%s)\n",
			    (speed == 1) ? 14 * val : 26 * val, val, str);
	}

	/* /sys/class/infiniband/mthca0/ports/1/cap_mask */
	val = mad_get_field(portinfo, 0, IB_PORT_CAPMASK_F);
	file_printf(path, SYS_PORT_CAPMASK, "0x%08x", val);

	/* /sys/class/infiniband/mthca0/ports/1/gids/0 */
	str = path + strlen(path);
	strncat(path, "/gids", sizeof(path) - strlen(path) - 1);
	make_path(path);
	*str = '\0';
	gid = mad_get_field64(portinfo, 0, IB_PORT_GID_PREFIX_F);
	guid = mad_get_field64(sc->nodeinfo, 0, IB_NODE_GUID_F) +
	    mad_get_field(portinfo, 0, IB_PORT_LOCAL_PORT_F);
	file_printf(path, SYS_PORT_GID,
		    "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		    (uint16_t) ((gid >> 48) & 0xffff),
		    (uint16_t) ((gid >> 32) & 0xffff),
		    (uint16_t) ((gid >> 16) & 0xffff),
		    (uint16_t) ((gid >> 0) & 0xffff),
		    (uint16_t) ((guid >> 48) & 0xffff),
		    (uint16_t) ((guid >> 32) & 0xffff),
		    (uint16_t) ((guid >> 16) & 0xffff),
		    (uint16_t) ((guid >> 0) & 0xffff));

	/* /sys/class/infiniband/mthca0/ports/1/pkeys/0 */
	str = path + strlen(path);
	strncat(path, "/pkeys", sizeof(path) - strlen(path) - 1);
	make_path(path);
	for (i = 0; i < sizeof(sc->pkeys)/sizeof(sc->pkeys[0]); i++) {
		char name[8];
		snprintf(name, sizeof(name), "%u", i);
		file_printf(path, name, "0x%04x\n", ntohs(sc->pkeys[i]));
	}
	*str = '\0';

	/* /sys/class/infiniband_mad/umad0/ */
	snprintf(path, sizeof(path), "%s/umad%u", sysfs_infiniband_mad_dir,
		 dev->num);
	make_path(path);
	file_printf(path, SYS_IB_MAD_DEV, "%s\n", dev->name);
	file_printf(path, SYS_IB_MAD_PORT, "%d\n", dev->port);

	/* /sys/class/infiniband_mad/issm0/ */
	snprintf(path, sizeof(path), "%s/issm%u", sysfs_infiniband_mad_dir,
		 dev->num);
	make_path(path);
	file_printf(path, SYS_IB_MAD_DEV, "%s\n", dev->name);
	file_printf(path, SYS_IB_MAD_PORT, "%d\n", dev->port);

	return 0;
}

/*
 * umad2sim device
 *
 */

static ssize_t umad2sim_read(struct umad2sim_dev *dev, void *buf, size_t count)
{
	struct sim_request req;
	ib_user_mad_t *umad = (ib_user_mad_t *) buf;
	unsigned mgmt_class;
	int cnt;

	DEBUG("umad2sim_read: %zu...\n", count);

	cnt = real_read(dev->sim_client.fd_pktin, &req, sizeof(req));
	DEBUG("umad2sim_read: got %d...\n", cnt);
	if (cnt < sizeof(req)) {
		ERROR("umad2sim_read: partial request - skip.\n");
		umad->status = EAGAIN;
		return umad_size();
	}

	mgmt_class = mad_get_field(req.mad, 0, IB_MAD_MGMTCLASS_F);

	DEBUG("umad2sim_read: mad: method=%x, response=%x, mgmtclass=%x, "
	      "attrid=%x, attrmod=%x\n",
	      mad_get_field(req.mad, 0, IB_MAD_METHOD_F),
	      mad_get_field(req.mad, 0, IB_MAD_RESPONSE_F),
	      mgmt_class,
	      mad_get_field(req.mad, 0, IB_MAD_ATTRID_F),
	      mad_get_field(req.mad, 0, IB_MAD_ATTRMOD_F));

	if (mgmt_class >= arrsize(dev->agent_idx)) {
		ERROR("bad mgmt_class 0x%x\n", mgmt_class);
		mgmt_class = 0;
	}

	if (mad_get_field(req.mad, 0, IB_MAD_RESPONSE_F)) {
		uint64_t trid = mad_get_field64(req.mad, 0, IB_MAD_TRID_F);
		umad->agent_id = (trid >> 32) & 0xffff;
	} else
		umad->agent_id = dev->agent_idx[mgmt_class];

	umad->status = ntohl(req.status);
	umad->timeout_ms = 0;
	umad->retries = 0;
	umad->length = umad_size() + be64toh(req.length);

	umad->addr.qpn = req.sqp;
	umad->addr.qkey = 0;	// agent->qkey;
	umad->addr.lid = req.slid;
	umad->addr.sl = 0;	// agent->sl;
	umad->addr.path_bits = 0;
	umad->addr.grh_present = 0;

	cnt -= sizeof(req) - sizeof(req.mad);
	if (cnt > count - umad_size())
		cnt = count - umad_size();
	memcpy(umad_get_mad(umad), req.mad, cnt);

	return umad->length;
}

static ssize_t umad2sim_write(struct umad2sim_dev *dev,
			      const void *buf, size_t count)
{
	struct sim_request req;
	ib_user_mad_t *umad = (ib_user_mad_t *) buf;
	int cnt;

#ifdef SIMULATE_SEND_ERRORS
	{ static int err_count;
	if (++err_count == 15)
		return -1;
	if (mad_get_field(umad_get_mad(umad), 0, IB_MAD_METHOD_F) == IB_MAD_METHOD_TRAP_REPRESS) {
		printf("Dropping trap repress...\n");
		return  -1;
	}
	}
#endif

	DEBUG("umad2sim_write: %zu...\n", count);

	DEBUG("umad2sim_write: umad: agent_id=%u, retries=%u, "
	      "agent.class=%x, agent.qpn=%u, "
	      "addr.qpn=%u, addr.lid=%u\n",
	      umad->agent_id, umad->retries,
	      dev->agents[umad->agent_id].mgmt_class,
	      dev->agents[umad->agent_id].qpn,
	      htonl(umad->addr.qpn), htons(umad->addr.lid));
	DEBUG("umad2sim_write: mad: method=%x, response=%x, mgmtclass=%x, "
	      "attrid=%x, attrmod=%x\n",
	      mad_get_field(umad_get_mad(umad), 0, IB_MAD_METHOD_F),
	      mad_get_field(umad_get_mad(umad), 0, IB_MAD_RESPONSE_F),
	      mad_get_field(umad_get_mad(umad), 0, IB_MAD_MGMTCLASS_F),
	      mad_get_field(umad_get_mad(umad), 0, IB_MAD_ATTRID_F),
	      mad_get_field(umad_get_mad(umad), 0, IB_MAD_ATTRMOD_F));

	req.dlid = umad->addr.lid;
	req.slid = req.dlid == 0xffff ? 0xffff : 0;	/* 0 - means auto
							   (supported by ibsim) */ ;
	req.dqp = umad->addr.qpn;
	req.sqp = htonl(dev->agents[umad->agent_id].qpn);
	req.status = 0;

	cnt = count - umad_size();
	if (cnt > sizeof(req.mad))
		cnt = sizeof(req.mad);
	memcpy(req.mad, umad_get_mad(umad), cnt);

	req.length = htobe64(cnt);

	if (!mad_get_field(req.mad, 0, IB_MAD_RESPONSE_F)) {
		uint64_t trid = mad_get_field64(req.mad, 0, IB_MAD_TRID_F);
		trid = (trid&0xffff0000ffffffffULL)|(((uint64_t)umad->agent_id)<<32);
		mad_set_field64(req.mad, 0, IB_MAD_TRID_F, trid);
	}

	cnt = write(dev->sim_client.fd_pktout, (void *)&req, sizeof(req));
	if (cnt < 0) {
		ERROR("umad2sim_write: cannot write\n");
		return -1;
	}
	if (cnt < sizeof(req))
		ERROR("umad2sim_write: partial write\n");

	return count;
}

static int register_agent(struct umad2sim_dev *dev,
			  struct ib_user_mad_reg_req *req)
{
	unsigned i;
	DEBUG("register_agent: id = %u, qpn = %u, mgmt_class = %u,"
	      " mgmt_class_version = %u, rmpp_version = %u\n",
	      req->id, req->qpn, req->mgmt_class, req->mgmt_class_version,
	      req->rmpp_version);
	for (i = 0; i < arrsize(dev->agents); i++)
		if (dev->agents[i].id == (uint32_t)(-1)) {
			req->id = i;
			dev->agents[i] = *req;
			dev->agent_idx[req->mgmt_class] = i;
			DEBUG("agent registered: %d\n", i);
			return 0;
		}
	errno = ENOMEM;
	return -1;
}

static int unregister_agent(struct umad2sim_dev *dev, unsigned id)
{
	unsigned mgmt_class;
	if (id >= arrsize(dev->agents)) {
		errno = EINVAL;
		return -1;
	}
	mgmt_class = dev->agents[id].mgmt_class;
	dev->agents[id].id = (uint32_t)(-1);
	dev->agent_idx[mgmt_class] = -1;
	return 0;
}

static int umad2sim_ioctl(struct umad2sim_dev *dev, unsigned long request,
			  void *arg)
{
	DEBUG("umad2sim_ioctl: %lu, %p...\n", request, arg);
	switch (request) {
	case IB_USER_MAD_REGISTER_AGENT:
		return register_agent(dev, arg);
	case IB_USER_MAD_UNREGISTER_AGENT:
		return unregister_agent(dev, *((unsigned *)arg));
	case IB_USER_MAD_ENABLE_PKEY:
		return 0;
	default:
		errno = EINVAL;
	}
	return -1;
}

static struct umad2sim_dev *umad2sim_dev_create(unsigned num, const char *name)
{
	struct umad2sim_dev *dev;
	unsigned i;

	DEBUG("umad2sim_dev_create: %s...\n", name);

	dev = malloc(sizeof(*dev));
	if (!dev)
		return NULL;
	memset(dev, 0, sizeof(*dev));

	dev->num = num;
	strncpy(dev->name, name, sizeof(dev->name) - 1);

	if (sim_client_init(&dev->sim_client) < 0)
		goto _error;

	dev->port = mad_get_field(&dev->sim_client.portinfo, 0,
				  IB_PORT_LOCAL_PORT_F);
	for (i = 0; i < arrsize(dev->agents); i++)
		dev->agents[i].id = (uint32_t)(-1);
	for (i = 0; i < arrsize(dev->agent_idx); i++)
		dev->agent_idx[i] = (unsigned)(-1);

	dev_sysfs_create(dev);

	snprintf(dev->umad_path, sizeof(dev->umad_path), "%s/%s%u",
		 umad_dev_dir, "umad", num);
	snprintf(dev->issm_path, sizeof(dev->issm_path), "%s/%s%u",
		 umad_dev_dir, "issm", num);

	return dev;

  _error:
	free(dev);
	return NULL;
}

static void umad2sim_dev_delete(struct umad2sim_dev *dev)
{
	sim_client_exit(&dev->sim_client);
	free(dev);
}

static void unlink_dir(char path[], unsigned size)
{
	struct dirent *dent;
	DIR *dir;
	int len = strlen(path);

	dir = opendir(path);
	if (!dir) {
		fprintf(stderr, "cannot opendir %s: %s\n",
			path, strerror(errno));
		return;
	}

	while ((dent = readdir(dir)) != NULL) {
		struct stat st;
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;
		snprintf(path + len, size - len, "/%s", dent->d_name);
		if (stat(path, &st) < 0)
			fprintf(stderr, "cannot stat %s: %s\n",
				path, strerror(errno));
		else if (S_ISDIR(st.st_mode))
			unlink_dir(path, size);
		else if (unlink(path) < 0)
			fprintf(stderr, "cannot unlink %s: %s\n",
				path, strerror(errno));
		path[len] = '\0';
	}

	closedir(dir);
	if (rmdir(path) < 0)
		fprintf(stderr, "cannot rmdir %s: %s\n", path, strerror(errno));
}

static void umad2sim_cleanup(void)
{
	char path[1024];
	unsigned i;
	DEBUG("umad2sim_cleanup...\n");
	for (i = 0; i < arrsize(devices); i++)
		if (devices[i]) {
			umad2sim_dev_delete(devices[i]);
			devices[i] = NULL;
		}
	strncpy(path, umad2sim_sysfs_prefix, sizeof(path) - 1);
	unlink_dir(path, sizeof(path));
}

static void umad2sim_init(void)
{
	if (umad2sim_initialized)
		return;
	DEBUG("umad2sim_init...\n");
	snprintf(umad2sim_sysfs_prefix, sizeof(umad2sim_sysfs_prefix),
		 "./sys-%d", getpid());
	devices[0] = umad2sim_dev_create(0, "ibsim0");
	if (!devices[0]) {
		ERROR("cannot init umad2sim. Exit.\n");
		exit(-1);
	}
	atexit(umad2sim_cleanup);
	umad2sim_initialized = 1;
}

/*
 *  libc wrappers
 *
 */

static unsigned wrapper_initialized;

#define CHECK_INIT() if (!wrapper_initialized) wrapper_init()

static void wrapper_init()
{
	if (wrapper_initialized)
		return;
	real_open = dlsym(RTLD_NEXT, "open");
	real_close = dlsym(RTLD_NEXT, "close");
	real_read = dlsym(RTLD_NEXT, "read");
	real_write = dlsym(RTLD_NEXT, "write");
	real_poll = dlsym(RTLD_NEXT, "poll");
	real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	real_opendir = dlsym(RTLD_NEXT, "opendir");
	real_scandir = dlsym(RTLD_NEXT, "scandir");
	wrapper_initialized = 1;
}

DIR *opendir(const char *path)
{
	char new_path[1024];

	CHECK_INIT();
	DEBUG("libs_wrap: opendir: %s...\n", path);

	if (is_sysfs_file(path)) {
		convert_sysfs_path(new_path, sizeof(new_path), path);
		path = new_path;
	}

	return real_opendir(path);
}

#if __GLIBC_PREREQ(2,10)
int scandir(const char *path, struct dirent ***namelist,
	    int (*filter) (const struct dirent *),
	    int (*compar) (const struct dirent **, const struct dirent **))
#else
int scandir(const char *path, struct dirent ***namelist,
	    int (*filter) (const struct dirent *),
	    int (*compar) (const void *, const void *))
#endif
{
	char new_path[4096];

	CHECK_INIT();

	if (!umad2sim_initialized && (is_sysfs_file(path) ||
				      !strncmp(path, umad_dev_dir,
					       strlen(umad_dev_dir))))
		umad2sim_init();

	DEBUG("libs_wrap: scandir: %s...\n", path);

	if (is_sysfs_file(path)) {
		convert_sysfs_path(new_path, sizeof(new_path), path);
		path = new_path;
	}

	return real_scandir(path, namelist, filter, compar);
}

int open(const char *path, int flags, ...)
{
	struct umad2sim_dev *dev;
	va_list args;
	mode_t mode = 0;
	unsigned i;

	CHECK_INIT();

	if (!umad2sim_initialized && (is_sysfs_file(path) ||
				      !strncmp(path, umad_dev_dir,
					       strlen(umad_dev_dir))))
		umad2sim_init();

	DEBUG("libs_wrap: open: %s...\n", path);

	if (flags & O_CREAT) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	if (is_sysfs_file(path)) {
		char new_path[1024];
		convert_sysfs_path(new_path, sizeof(new_path), path);
		return real_open(new_path, flags, mode);
	}

	for (i = 0; i < arrsize(devices); i++) {
		if (!(dev = devices[i]))
			continue;
		if (!strncmp(path, dev->umad_path, sizeof(dev->umad_path))) {
			return 1024 + i;
		}
		if (!strncmp(path, dev->issm_path, sizeof(dev->issm_path))) {
			sim_client_set_sm(&dev->sim_client, 1);
			return 2048 + i;
		}
	}

	return real_open(path, flags, mode);
}

int close(int fd)
{
	struct umad2sim_dev *dev;

	DEBUG("libs_wrap: close %d...\n", fd);
	CHECK_INIT();

	if (fd >= 2048) {
		dev = devices[fd - 2048];
		sim_client_set_sm(&dev->sim_client, 0);
		return 0;
	} else if (fd >= 1024) {
		return 0;
	} else
		return real_close(fd);
}

ssize_t read(int fd, void *buf, size_t count)
{
	CHECK_INIT();

	if (fd >= 2048)
		return -1;
	else if (fd >= 1024)
		return umad2sim_read(devices[fd - 1024], buf, count);
	else
		return real_read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	CHECK_INIT();

	if (fd >= 2048)
		return -1;
	else if (fd >= 1024)
		return umad2sim_write(devices[fd - 1024], buf, count);
	else
		return real_write(fd, buf, count);
}

int ioctl(int fd, unsigned long request, ...)
{
	va_list args;
	void *arg;

	CHECK_INIT();
	va_start(args, request);
	arg = va_arg(args, void *);
	va_end(args);

	if (fd >= 2048)
		return -1;
	else if (fd >= 1024)
		return umad2sim_ioctl(devices[fd - 1024], request, arg);
	else
		return real_ioctl(fd, request, arg);
}

int poll(struct pollfd *pfds, nfds_t nfds, int timeout)
{
	int saved_fds[nfds];
	unsigned i;
	int ret;

	CHECK_INIT();

	for (i = 0; i < nfds; i++) {
		if (pfds[i].fd >= 1024 && pfds[i].fd < 2048) {
			struct umad2sim_dev *dev = devices[pfds[i].fd - 1024];
			saved_fds[i] = pfds[i].fd;
			pfds[i].fd = dev->sim_client.fd_pktin;
		} else
			saved_fds[i] = 0;
	}

	ret = real_poll(pfds, nfds, timeout);

	for (i = 0; i < nfds; i++)
		if (saved_fds[i])
			pfds[i].fd = saved_fds[i];

	return ret;
}
