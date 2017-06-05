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

/**
 * Since these structs are passed to and from the kernel we need to make sure
 * that we get the size of each struct to match exactly what the kernel is
 * expecting. So, when editing this file make sure to add static asserts that
 * check each struct's size against the arg length you see in strace.
 */

/**
 * Header used by all ioctls
 */
union mali_ioctl_header {
	/* [in] The ID of the UK function being called */
	uint32_t id :32;
	/* [out] The return value of the UK function that was called */
	uint32_t rc :32;

	uint64_t :64;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(union mali_ioctl_header, 8);

struct mali_ioctl_get_version {
	union mali_ioctl_header header;
	uint16_t major; /* [out] */
	uint16_t minor; /* [out] */
	uint32_t :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_get_version, 16);

struct mali_ioctl_mem_alloc {
	union mali_ioctl_header header;
	/* [in] */
	uint64_t va_pages;
	uint64_t commit_pages;
	uint64_t extent;
	/* [in/out] */
	uint64_t flags;
	/* [out] */
	uint64_t gpu_va;
	uint16_t va_alignment;

	uint32_t :32;
	uint16_t :16;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_alloc, 56);

struct mali_ioctl_mem_import {
	union mali_ioctl_header header;
	/* [in] */
	uint64_t phandle;
	uint32_t type;
	uint32_t :32;
	/* [in/out] */
	uint64_t flags;
	/* [out] */
	uint64_t gpu_va;
	uint64_t va_pages;
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_commit {
	union mali_ioctl_header header;
	/* [in] */
	uint64_t gpu_addr;
	uint64_t pages;
	/* [out] */
	uint32_t result_subcode;
	uint32_t :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_commit, 32);

struct mali_ioctl_mem_query {
	union mali_ioctl_header header;
	/* [in] */
	uint64_t gpu_addr;
	enum {
		MALI_MEM_QUERY_COMMIT_SIZE = 1,
		MALI_MEM_QUERY_VA_SIZE     = 2,
		MALI_MEM_QUERY_FLAGS       = 3
	} query :32;
	uint32_t :32;
	/* [out] */
	uint64_t value;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_query, 32);

struct mali_ioctl_mem_free {
	union mali_ioctl_header header;
	uint64_t gpu_addr; /* [in] */
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_flags_change {
	union mali_ioctl_header header;
	/* [in] */
	uint64_t gpu_va;
	uint64_t flags;
	uint64_t mask;
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_alias {
	union mali_ioctl_header header;
	/* [in/out] */
	uint64_t flags;
	/* [in] */
	uint64_t stride;
	uint64_t nents;
	uint64_t ai;
	/* [out] */
	uint64_t gpu_va;
	uint64_t va_pages;
} __attribute__((packed));

struct mali_ioctl_set_flags {
	union mali_ioctl_header header;
	uint32_t create_flags; /* [in] */
	uint32_t :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_set_flags, 16);

/* For ioctl's we haven't written decoding stuff for yet */
typedef struct {
	union mali_ioctl_header header;
} __ioctl_placeholder;

#define MALI_IOCTL_TYPE_BASE       0x80
#define MALI_IOCTL_TYPE_MAX        0x82
#define MALI_IOCTL_TYPE_MAX_OFFSET (MALI_IOCTL_TYPE_MAX - MALI_IOCTL_TYPE_BASE)

#define MALI_IOCTL_GET_VERSION             (_IOWR(0x80,  0, struct mali_ioctl_get_version))
#define MALI_IOCTL_MEM_ALLOC               (_IOWR(0x82,  0, struct mali_ioctl_mem_alloc))
#define MALI_IOCTL_MEM_IMPORT              (_IOWR(0x82,  1, struct mali_ioctl_mem_import))
#define MALI_IOCTL_MEM_COMMIT              (_IOWR(0x82,  2, struct mali_ioctl_mem_commit))
#define MALI_IOCTL_MEM_QUERY               (_IOWR(0x82,  3, struct mali_ioctl_mem_query))
#define MALI_IOCTL_MEM_FREE                (_IOWR(0x82,  4, struct mali_ioctl_mem_free))
#define MALI_IOCTL_MEM_FLAGS_CHANGE        (_IOWR(0x82,  5, struct mali_ioctl_mem_flags_change))
#define MALI_IOCTL_MEM_ALIAS               (_IOWR(0x82,  6, struct mali_ioctl_mem_alias))
#define MALI_IOCTL_SYNC                    (_IOWR(0x82,  8, __ioctl_placeholder))
#define MALI_IOCTL_POST_TERM               (_IOWR(0x82,  9, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_SETUP             (_IOWR(0x82, 10, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_DUMP              (_IOWR(0x82, 11, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_CLEAR             (_IOWR(0x82, 12, __ioctl_placeholder))
#define MALI_IOCTL_GPU_PROPS_REG_DUMP      (_IOWR(0x82, 14, __ioctl_placeholder))
#define MALI_IOCTL_FIND_CPU_OFFSET         (_IOWR(0x82, 15, __ioctl_placeholder))
#define MALI_IOCTL_GET_VERSION_NEW         (_IOWR(0x82, 16, struct mali_ioctl_get_version))
#define MALI_IOCTL_SET_FLAGS               (_IOWR(0x82, 18, struct mali_ioctl_set_flags))
#define MALI_IOCTL_SET_TEST_DATA           (_IOWR(0x82, 19, __ioctl_placeholder))
#define MALI_IOCTL_INJECT_ERROR            (_IOWR(0x82, 20, __ioctl_placeholder))
#define MALI_IOCTL_MODEL_CONTROL           (_IOWR(0x82, 21, __ioctl_placeholder))
#define MALI_IOCTL_KEEP_GPU_POWERED        (_IOWR(0x82, 22, __ioctl_placeholder))
#define MALI_IOCTL_FENCE_VALIDATE          (_IOWR(0x82, 23, __ioctl_placeholder))
#define MALI_IOCTL_STREAM_CREATE           (_IOWR(0x82, 24, __ioctl_placeholder))
#define MALI_IOCTL_GET_PROFILING_CONTROLS  (_IOWR(0x82, 25, __ioctl_placeholder))
#define MALI_IOCTL_SET_PROFILING_CONTROLS  (_IOWR(0x82, 26, __ioctl_placeholder))
#define MALI_IOCTL_DEBUGFS_MEM_PROFILE_ADD (_IOWR(0x82, 27, __ioctl_placeholder))
#define MALI_IOCTL_JOB_SUBMIT              (_IOWR(0x82, 28, __ioctl_placeholder))
#define MALI_IOCTL_DISJOINT_QUERY          (_IOWR(0x82, 29, __ioctl_placeholder))
#define MALI_IOCTL_GET_CONTEXT_ID          (_IOWR(0x82, 31, __ioctl_placeholder))
#define MALI_IOCTL_TLSTREAM_ACQUIRE_V10_4  (_IOWR(0x82, 32, __ioctl_placeholder))
#define MALI_IOCTL_TLSTREAM_TEST           (_IOWR(0x82, 33, __ioctl_placeholder))
#define MALI_IOCTL_TLSTREAM_STATS          (_IOWR(0x82, 34, __ioctl_placeholder))
#define MALI_IOCTL_TLSTREAM_FLUSH          (_IOWR(0x82, 35, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_READER_SETUP      (_IOWR(0x82, 36, __ioctl_placeholder))
#define MALI_IOCTL_SET_PRFCNT_VALUES       (_IOWR(0x82, 37, __ioctl_placeholder))
#define MALI_IOCTL_SOFT_EVENT_UPDATE       (_IOWR(0x82, 38, __ioctl_placeholder))
#define MALI_IOCTL_MEM_JIT_INIT            (_IOWR(0x82, 39, __ioctl_placeholder))
#define MALI_IOCTL_TLSTREAM_ACQUIRE        (_IOWR(0x82, 40, __ioctl_placeholder))

#endif /* __MALI_IOCTL_H__ */
