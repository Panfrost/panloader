/*
 * © Copyright 2017 The BiOpenly Community
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU license.
 *
 * A copy of the licence is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */

/**
 * Definitions for all of the ioctls for the original open source bifrost GPU
 * kernel driver, written by ARM.
 */

#ifndef __MALI_IOCTL_H__
#define __MALI_IOCTL_H__

#include <inttypes.h>
#include <panloader-util.h>

enum mali_func_id {
	MALI_FUNC_GET_VERSION = 0,
};

/**
 * Since these structs are passed to and from the kernel we need to make sure
 * that we get the size of each struct to match exactly what the kernel is
 * expecting. So, when editing this file make sure to add static asserts that
 * check each struct's size against the arg length you see in strace.
 */

/**
 * Header used by all ioctls
 */
union mali_ioctl_func_header {
	/* [in] The ID of the UK function being called */
	enum mali_func_id id :32;
	/* [out] The return value of the UK function that was called */
	uint32_t rc :32;

	uint64_t :64;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(union mali_ioctl_func_header, 8);

struct mali_ioctl_get_version {
	union mali_ioctl_func_header header;
	uint16_t major; /* [out] */
	uint16_t minor; /* [out] */
	uint32_t :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_get_version, 16);

#endif /* __MALI_IOCTL_H__ */
