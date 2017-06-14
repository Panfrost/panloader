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

#include <panloader-util.h>

#define MALI_GPU_NUM_TEXTURE_FEATURES_REGISTERS 3
#define MALI_GPU_MAX_JOB_SLOTS 16
#define MALI_MAX_COHERENT_GROUPS 16

/**
 * Since these structs are passed to and from the kernel we need to make sure
 * that we get the size of each struct to match exactly what the kernel is
 * expecting. So, when editing this file make sure to add static asserts that
 * check each struct's size against the arg length you see in strace.
 */

enum mali_ioctl_mem_flags {
	/* IN */
	MALI_MEM_PROT_CPU_RD = (1U << 0),      /**< Read access CPU side */
	MALI_MEM_PROT_CPU_WR = (1U << 1),      /**< Write access CPU side */
	MALI_MEM_PROT_GPU_RD = (1U << 2),      /**< Read access GPU side */
	MALI_MEM_PROT_GPU_WR = (1U << 3),      /**< Write access GPU side */
	MALI_MEM_PROT_GPU_EX = (1U << 4),      /**< Execute allowed on the GPU
						    side */

	MALI_MEM_GROW_ON_GPF = (1U << 9),      /**< Grow backing store on GPU
						    Page Fault */

	MALI_MEM_COHERENT_SYSTEM = (1U << 10), /**< Page coherence Outer
						    shareable, if available */
	MALI_MEM_COHERENT_LOCAL = (1U << 11),  /**< Page coherence Inner
						    shareable */
	MALI_MEM_CACHED_CPU = (1U << 12),      /**< Should be cached on the
						    CPU */

	/* IN/OUT */
	MALI_MEM_SAME_VA = (1U << 13), /**< Must have same VA on both the GPU
					    and the CPU */
	/* OUT */
	MALI_MEM_NEED_MMAP = (1U << 14), /**< Must call mmap to acquire a GPU
					     address for the alloc */
	/* IN */
	MALI_MEM_COHERENT_SYSTEM_REQUIRED = (1U << 15), /**< Page coherence
					     Outer shareable, required. */
	MALI_MEM_SECURE = (1U << 16),          /**< Secure memory */
	MALI_MEM_DONT_NEED = (1U << 17),       /**< Not needed physical
						    memory */
	MALI_MEM_IMPORT_SHARED = (1U << 18),   /**< Must use shared CPU/GPU zone
						    (SAME_VA zone) but doesn't
						    require the addresses to
						    be the same */
};

enum mali_ioctl_coherency_mode {
	COHERENCY_ACE_LITE = 0,
	COHERENCY_ACE      = 1,
	COHERENCY_NONE     = 31
};

struct mali_gpu_core_props {
	/**
	 * Product specific value.
	 */
	u32 product_id;

	/**
	 * Status of the GPU release.
	 * No defined values, but starts at 0 and increases by one for each
	 * release status (alpha, beta, EAC, etc.).
	 * 4 bit values (0-15).
	 */
	u16 version_status;

	/**
	 * Minor release number of the GPU. "P" part of an "RnPn" release
	 * number.
	 * 8 bit values (0-255).
	 */
	u16 minor_revision;

	/**
	 * Major release number of the GPU. "R" part of an "RnPn" release
	 * number.
	 * 4 bit values (0-15).
	 */
	u16 major_revision;

	u16 :16;

	/**
	 * @usecase GPU clock speed is not specified in the Midgard
	 * Architecture, but is <b>necessary for OpenCL's clGetDeviceInfo()
	 * function</b>.
	 */
	u32 gpu_speed_mhz;

	/**
	 * @usecase GPU clock max/min speed is required for computing
	 * best/worst case in tasks as job scheduling ant irq_throttling. (It
	 * is not specified in the Midgard Architecture).
	 */
	u32 gpu_freq_khz_max;
	u32 gpu_freq_khz_min;

	/**
	 * Size of the shader program counter, in bits.
	 */
	u32 log2_program_counter_size;

	/**
	 * TEXTURE_FEATURES_x registers, as exposed by the GPU. This is a
	 * bitpattern where a set bit indicates that the format is supported.
	 *
	 * Before using a texture format, it is recommended that the
	 * corresponding bit be checked.
	 */
	u32 texture_features[MALI_GPU_NUM_TEXTURE_FEATURES_REGISTERS];

	/**
	 * Theoretical maximum memory available to the GPU. It is unlikely
	 * that a client will be able to allocate all of this memory for their
	 * own purposes, but this at least provides an upper bound on the
	 * memory available to the GPU.
	 *
	 * This is required for OpenCL's clGetDeviceInfo() call when
	 * CL_DEVICE_GLOBAL_MEM_SIZE is requested, for OpenCL GPU devices. The
	 * client will not be expecting to allocate anywhere near this value.
	 */
	u64 gpu_available_memory_size;
};

struct mali_gpu_l2_cache_props {
	u8 log2_line_size;
	u8 log2_cache_size;
	u8 num_l2_slices; /* Number of L2C slices. 1 or higher */
	u64 :40;
};

struct mali_gpu_tiler_props {
	u32 bin_size_bytes;	/* Max is 4*2^15 */
	u32 max_active_levels;	/* Max is 2^15 */
};

struct mali_gpu_thread_props {
	u32 max_threads;            /* Max. number of threads per core */
	u32 max_workgroup_size;     /* Max. number of threads per workgroup */
	u32 max_barrier_size;       /* Max. number of threads that can
				       synchronize on a simple barrier */
	u16 max_registers;          /* Total size [1..65535] of the register
				       file available per core. */
	u8  max_task_queue;         /* Max. tasks [1..255] which may be sent
				       to a core before it becomes blocked. */
	u8  max_thread_group_split; /* Max. allowed value [1..15] of the
				       Thread Group Split field. */
	enum {
		MALI_GPU_IMPLEMENTATION_UNKNOWN = 0,
		MALI_GPU_IMPLEMENTATION_SILICON = 1,
		MALI_GPU_IMPLEMENTATION_FPGA    = 2,
		MALI_GPU_IMPLEMENTATION_SW      = 3,
	} impl_tech :8;
	u64 :56;
};

/**
 * @brief descriptor for a coherent group
 *
 * \c core_mask exposes all cores in that coherent group, and \c num_cores
 * provides a cached population-count for that mask.
 *
 * @note Whilst all cores are exposed in the mask, not all may be available to
 * the application, depending on the Kernel Power policy.
 *
 * @note if u64s must be 8-byte aligned, then this structure has 32-bits of
 * wastage.
 */
struct mali_ioctl_gpu_coherent_group {
	u64 core_mask;	       /**< Core restriction mask required for the
				 group */
	u16 num_cores;	       /**< Number of cores in the group */
	u64 :48;
};

/**
 * @brief Coherency group information
 *
 * Note that the sizes of the members could be reduced. However, the \c group
 * member might be 8-byte aligned to ensure the u64 core_mask is 8-byte
 * aligned, thus leading to wastage if the other members sizes were reduced.
 *
 * The groups are sorted by core mask. The core masks are non-repeating and do
 * not intersect.
 */
struct mali_gpu_coherent_group_info {
	u32 num_groups;

	/**
	 * Number of core groups (coherent or not) in the GPU. Equivalent to
	 * the number of L2 Caches.
	 *
	 * The GPU Counter dumping writes 2048 bytes per core group,
	 * regardless of whether the core groups are coherent or not. Hence
	 * this member is needed to calculate how much memory is required for
	 * dumping.
	 *
	 * @note Do not use it to work out how many valid elements are in the
	 * group[] member. Use num_groups instead.
	 */
	u32 num_core_groups;

	/**
	 * Coherency features of the memory, accessed by @ref gpu_mem_features
	 * methods
	 */
	u32 coherency;

	u32 :32;

	/**
	 * Descriptors of coherent groups
	 */
	struct mali_ioctl_gpu_coherent_group group[MALI_MAX_COHERENT_GROUPS];
};

/**
 * A complete description of the GPU's Hardware Configuration Discovery
 * registers.
 *
 * The information is presented inefficiently for access. For frequent access,
 * the values should be better expressed in an unpacked form in the
 * base_gpu_props structure.
 *
 * @usecase The raw properties in @ref gpu_raw_gpu_props are necessary to
 * allow a user of the Mali Tools (e.g. PAT) to determine "Why is this device
 * behaving differently?". In this case, all information about the
 * configuration is potentially useful, but it <b>does not need to be processed
 * by the driver</b>. Instead, the raw registers can be processed by the Mali
 * Tools software on the host PC.
 *
 */
struct mali_gpu_raw_props {
	u64 shader_present;
	u64 tiler_present;
	u64 l2_present;
	u64 stack_present;

	u32 l2_features;
	u32 suspend_size; /* API 8.2+ */
	u32 mem_features;
	u32 mmu_features;

	u32 as_present;

	u32 js_present;
	u32 js_features[MALI_GPU_MAX_JOB_SLOTS];
	u32 tiler_features;
	u32 texture_features[3];

	u32 gpu_id;

	u32 thread_max_threads;
	u32 thread_max_workgroup_size;
	u32 thread_max_barrier_size;
	u32 thread_features;

	/*
	 * Note: This is the _selected_ coherency mode rather than the
	 * available modes as exposed in the coherency_features register.
	 */
	u32 coherency_mode;
};

/**
 * Header used by all ioctls
 */
union mali_ioctl_header {
	/* [in] The ID of the UK function being called */
	u32 id :32;
	/* [out] The return value of the UK function that was called */
	u32 rc :32;

	u64 :64;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(union mali_ioctl_header, 8);

struct mali_ioctl_get_version {
	union mali_ioctl_header header;
	u16 major; /* [out] */
	u16 minor; /* [out] */
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_get_version, 16);

struct mali_ioctl_mem_alloc {
	union mali_ioctl_header header;
	/* [in] */
	u64 va_pages;
	u64 commit_pages;
	u64 extent;
	/* [in/out] */
	u64 flags;
	/* [out] */
	u64 gpu_va;
	u16 va_alignment;

	u32 :32;
	u16 :16;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_alloc, 56);

struct mali_ioctl_mem_import {
	union mali_ioctl_header header;
	/* [in] */
	u64 phandle;
	enum {
		MALI_MEM_IMPORT_TYPE_INVALID = 0,
		MALI_MEM_IMPORT_TYPE_UMP = 1,
		MALI_MEM_IMPORT_TYPE_UMM = 2,
		MALI_MEM_IMPORT_TYPE_USER_BUFFER = 3,
	} type :32;
	u32 :32;
	/* [in/out] */
	u64 flags;
	/* [out] */
	u64 gpu_va;
	u64 va_pages;
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_commit {
	union mali_ioctl_header header;
	/* [in] */
	u64 gpu_addr;
	u64 pages;
	/* [out] */
	u32 result_subcode;
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_commit, 32);

struct mali_ioctl_mem_query {
	union mali_ioctl_header header;
	/* [in] */
	u64 gpu_addr;
	enum {
		MALI_MEM_QUERY_COMMIT_SIZE = 1,
		MALI_MEM_QUERY_VA_SIZE     = 2,
		MALI_MEM_QUERY_FLAGS       = 3
	} query :32;
	u32 :32;
	/* [out] */
	u64 value;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_query, 32);

struct mali_ioctl_mem_free {
	union mali_ioctl_header header;
	u64 gpu_addr; /* [in] */
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_flags_change {
	union mali_ioctl_header header;
	/* [in] */
	u64 gpu_va;
	u64 flags;
	u64 mask;
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_alias {
	union mali_ioctl_header header;
	/* [in/out] */
	u64 flags;
	/* [in] */
	u64 stride;
	u64 nents;
	u64 ai;
	/* [out] */
	u64 gpu_va;
	u64 va_pages;
} __attribute__((packed));

struct mali_ioctl_sync {
	union mali_ioctl_header header;
	u64 handle;
	u64 user_addr;
	u64 size;
	enum {
		MALI_SYNC_TO_DEVICE = 0,
		MALI_SYNC_TO_CPU = 1,
	} type :8;
	u64 :56;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_sync, 40);

struct mali_ioctl_gpu_props_reg_dump {
	union mali_ioctl_header header;
	struct mali_gpu_core_props core;
	struct mali_gpu_l2_cache_props l2;
	u64 :64;
	struct mali_gpu_tiler_props tiler;
	struct mali_gpu_thread_props thread;

	struct mali_gpu_raw_props raw;

	/** This must be last member of the structure */
	struct mali_gpu_coherent_group_info coherency_info;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_gpu_props_reg_dump, 536);

struct mali_ioctl_set_flags {
	union mali_ioctl_header header;
	u32 create_flags; /* [in] */
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_set_flags, 16);

/* For ioctl's we haven't written decoding stuff for yet */
typedef struct {
	union mali_ioctl_header header;
} __ioctl_placeholder;

#define MALI_IOCTL_TYPE_BASE  0x80
#define MALI_IOCTL_TYPE_MAX   0x82
#define MALI_IOCTL_TYPE_COUNT (MALI_IOCTL_TYPE_MAX - MALI_IOCTL_TYPE_BASE + 1)

#define MALI_IOCTL_GET_VERSION             (_IOWR(0x80,  0, struct mali_ioctl_get_version))
#define MALI_IOCTL_MEM_ALLOC               (_IOWR(0x82,  0, struct mali_ioctl_mem_alloc))
#define MALI_IOCTL_MEM_IMPORT              (_IOWR(0x82,  1, struct mali_ioctl_mem_import))
#define MALI_IOCTL_MEM_COMMIT              (_IOWR(0x82,  2, struct mali_ioctl_mem_commit))
#define MALI_IOCTL_MEM_QUERY               (_IOWR(0x82,  3, struct mali_ioctl_mem_query))
#define MALI_IOCTL_MEM_FREE                (_IOWR(0x82,  4, struct mali_ioctl_mem_free))
#define MALI_IOCTL_MEM_FLAGS_CHANGE        (_IOWR(0x82,  5, struct mali_ioctl_mem_flags_change))
#define MALI_IOCTL_MEM_ALIAS               (_IOWR(0x82,  6, struct mali_ioctl_mem_alias))
#define MALI_IOCTL_SYNC                    (_IOWR(0x82,  8, struct mali_ioctl_sync))
#define MALI_IOCTL_POST_TERM               (_IOWR(0x82,  9, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_SETUP             (_IOWR(0x82, 10, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_DUMP              (_IOWR(0x82, 11, __ioctl_placeholder))
#define MALI_IOCTL_HWCNT_CLEAR             (_IOWR(0x82, 12, __ioctl_placeholder))
#define MALI_IOCTL_GPU_PROPS_REG_DUMP      (_IOWR(0x82, 14, struct mali_ioctl_gpu_props_reg_dump))
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
