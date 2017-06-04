/*
 * © Copyright 2017 The BiOpenly Community
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/ioctl.h>

#include <mali-ioctl.h>
#include "panwrap.h"

static pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;

#define LOCK()   pthread_mutex_lock(&l)
#define UNLOCK() pthread_mutex_unlock(&l)

#define LOG_PRE(format, ...) \
	LOG("%s" format, "PRE  ", ## __VA_ARGS__)
#define LOG_POST(format, ...) \
	LOG("%s" format, "POST ", ## __VA_ARGS__)

struct device_info {
	const char *name;
	struct {
		const char *name;
	} ioctl_info[_IOC_NR(0xffffffff) + MALI_IOCTL_TYPE_MAX_OFFSET];
};

/* Every type of ioctl has a unique nr except for GET_VERSION. While
 * GET_VERSION has a different dir then all of the other ioctl's, it
 * unfortunately shares the same nr as MEM_ALLOC. So in order to ensure that
 * we can have multiple ioctl's with the same nr so long as their dirs differ,
 * we combine the type of the ioctl with the nr and map each ioctl with that
 * instead
 */
#define IOCTL_MAP(request) (_IOC_NR(request) + (_IOC_TYPE(request) - \
						MALI_IOCTL_TYPE_BASE))

#define IOCTL_INFO(n) \
		[IOCTL_MAP(MALI_IOCTL_##n)] = { .name = #n }
static struct device_info mali_info = {
	.name = "mali",
	.ioctl_info = {
		IOCTL_INFO(GET_VERSION),
		IOCTL_INFO(MEM_ALLOC),
		IOCTL_INFO(MEM_IMPORT),
		IOCTL_INFO(MEM_COMMIT),
		IOCTL_INFO(MEM_QUERY),
		IOCTL_INFO(MEM_FREE),
		IOCTL_INFO(MEM_FLAGS_CHANGE),
		IOCTL_INFO(MEM_ALIAS),
		IOCTL_INFO(SYNC),
		IOCTL_INFO(POST_TERM),
		IOCTL_INFO(HWCNT_SETUP),
		IOCTL_INFO(HWCNT_DUMP),
		IOCTL_INFO(HWCNT_CLEAR),
		IOCTL_INFO(GPU_PROPS_REG_DUMP),
		IOCTL_INFO(FIND_CPU_OFFSET),
		IOCTL_INFO(GET_VERSION_NEW),
		IOCTL_INFO(SET_FLAGS),
		IOCTL_INFO(SET_TEST_DATA),
		IOCTL_INFO(INJECT_ERROR),
		IOCTL_INFO(MODEL_CONTROL),
		IOCTL_INFO(KEEP_GPU_POWERED),
		IOCTL_INFO(FENCE_VALIDATE),
		IOCTL_INFO(STREAM_CREATE),
		IOCTL_INFO(GET_PROFILING_CONTROLS),
		IOCTL_INFO(SET_PROFILING_CONTROLS),
		IOCTL_INFO(DEBUGFS_MEM_PROFILE_ADD),
		IOCTL_INFO(JOB_SUBMIT),
		IOCTL_INFO(DISJOINT_QUERY),
		IOCTL_INFO(GET_CONTEXT_ID),
		IOCTL_INFO(TLSTREAM_ACQUIRE_V10_4),
		IOCTL_INFO(TLSTREAM_TEST),
		IOCTL_INFO(TLSTREAM_STATS),
		IOCTL_INFO(TLSTREAM_FLUSH),
		IOCTL_INFO(HWCNT_READER_SETUP),
		IOCTL_INFO(SET_PRFCNT_VALUES),
		IOCTL_INFO(SOFT_EVENT_UPDATE),
		IOCTL_INFO(MEM_JIT_INIT),
		IOCTL_INFO(TLSTREAM_ACQUIRE),
	},
};
#undef IOCTL_INFO

static int mali_fd = 0;

static inline const char *
ioctl_get_name(unsigned long int request)
{
	const char *name = mali_info.ioctl_info[IOCTL_MAP(request)].name;

	if (name)
		return name;
	else
		return "???";
}

static void
ioctl_decode_pre_set_flags(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_set_flags *args = ptr;

	LOG_PRE("\tcreate_flags = %08x\n", args->create_flags);
}

static void
ioctl_decode_pre(unsigned long int request, void *ptr)
{
	switch (IOCTL_MAP(request)) {
	case IOCTL_MAP(MALI_IOCTL_SET_FLAGS):
		ioctl_decode_pre_set_flags(request, ptr);
		break;
	default:
		break;
	}
}

static void
ioctl_decode_post_get_version(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_get_version *args = ptr;

	LOG_POST("\tmajor = %3d\n", args->major);
	LOG_POST("\tminor = %3d\n", args->minor);
}

static void
ioctl_decode_post(unsigned long int request, void *ptr)
{
	switch (IOCTL_MAP(request)) {
	case IOCTL_MAP(MALI_IOCTL_GET_VERSION):
	case IOCTL_MAP(MALI_IOCTL_GET_VERSION_NEW):
		ioctl_decode_post_get_version(request, ptr);
		break;
	default:
		break;
	}
}

/**
 * Overriden libc functions start here
 */
int
open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	int ret;
	PROLOG(open);

	if (flags & O_CREAT) {
		va_list args;

		va_start(args, flags);
		mode = (mode_t) va_arg(args, int);
		va_end(args);

		ret = orig_open(path, flags, mode);
	} else {
		ret = orig_open(path, flags);
	}

	LOCK();
	if (ret != -1) {
		if (strcmp(path, "/dev/mali0") == 0) {
			LOG("/dev/mali0 fd == %d\n", ret);
			mali_fd = ret;
		} else if (strstr(path, "/dev/")) {
			LOG("Unknown device %s opened at fd %d\n",
			    path, ret);
		}
	}
	UNLOCK();

	return ret;
}

int
close(int fd)
{
	PROLOG(close);

	LOCK();
	if (fd > 0 && fd == mali_fd) {
		LOG("/dev/mali0 closed\n");
		mali_fd = 0;
	}
	UNLOCK();

	return orig_close(fd);
}

/* XXX: Android has a messed up ioctl signature */
int ioctl(int fd, int request, ...)
{
	const char *name;
	union mali_ioctl_header *header;
	PROLOG(ioctl);
	int ioc_size = _IOC_SIZE(request);
	int ret;
	uint32_t func;
	void *ptr;

	if (ioc_size) {
		va_list args;

		va_start(args, request);
		ptr = va_arg(args, void *);
		va_end(args);
	} else {
		ptr = NULL;
	}

	if (fd && fd != mali_fd)
		return orig_ioctl(fd, request, ptr);

	LOCK();
	name = ioctl_get_name(request);
	header = ptr;

	if (!ptr) { /* All valid mali ioctl's should have a specified arg */
		LOG_PRE("<%-20s> (%02d) (%08x), has no arguments? Cannot decode :(\n",
			name, _IOC_NR(request), request);

		ret = orig_ioctl(fd, request, ptr);

		LOG_POST("<%-20s> (%02d) (%08x) == %02d\n",
			 name, _IOC_NR(request), request, ret);
		goto out;
	}

	func = header->id;
	LOG_PRE("<%-20s> (%02d) (%08x) (%04d) (%03d)\n",
		name, _IOC_NR(request), request, _IOC_SIZE(request), func);
	ioctl_decode_pre(request, ptr);

	ret = orig_ioctl(fd, request, ptr);

	LOG_POST("<%-20s> (%02d) (%08x) (%04d) (%03d) == %02d, %02d\n",
		 name, _IOC_NR(request), request, _IOC_SIZE(request), func, ret,
		 header->rc);
	ioctl_decode_post(request, ptr);

out:
	UNLOCK();
	return ret;
}
