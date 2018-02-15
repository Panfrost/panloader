/*
 * © Copyright 2017-2018 The BiOpenly Community
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
#include <config.h>

#define MALI_GPU_NUM_TEXTURE_FEATURES_REGISTERS 3
#define MALI_GPU_MAX_JOB_SLOTS 16
#define MALI_MAX_COHERENT_GROUPS 16

typedef u8 mali_atom_id;

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

#define MALI_IOCTL_MEM_FLAGS_IN_MASK                                          \
	(MALI_MEM_PROT_CPU_RD | MALI_MEM_PROT_CPU_WR |                        \
	 MALI_MEM_PROT_GPU_RD | MALI_MEM_PROT_GPU_WR | MALI_MEM_PROT_GPU_EX | \
	 MALI_MEM_GROW_ON_GPF |                                               \
	 MALI_MEM_COHERENT_SYSTEM | MALI_MEM_COHERENT_LOCAL |                 \
	 MALI_MEM_CACHED_CPU |                                                \
	 MALI_MEM_COHERENT_SYSTEM_REQUIRED | MALI_MEM_SECURE |                \
	 MALI_MEM_DONT_NEED | MALI_MEM_IMPORT_SHARED)
#define MALI_MEM_MAP_TRACKING_HANDLE (3ull << 12)

enum mali_ioctl_coherency_mode {
	COHERENCY_ACE_LITE = 0,
	COHERENCY_ACE      = 1,
	COHERENCY_NONE     = 31
};

/*
 * Mali Atom priority
 *
 * Only certain priority levels are actually implemented, as specified by the
 * MALI_JD_PRIO_<...> definitions below. It is undefined to use a priority
 * level that is not one of those defined below.
 *
 * Priority levels only affect scheduling between atoms of the same type within
 * a mali context, and only after the atoms have had dependencies resolved.
 * Fragment atoms does not affect non-frament atoms with lower priorities, and
 * the other way around. For example, a low priority atom that has had its
 * dependencies resolved might run before a higher priority atom that has not
 * had its dependencies resolved.
 *
 * The scheduling between mali contexts/processes and between atoms from
 * different mali contexts/processes is unaffected by atom priority.
 *
 * The atoms are scheduled as follows with respect to their priorities:
 * - Let atoms 'X' and 'Y' be for the same job slot who have dependencies
 *   resolved, and atom 'X' has a higher priority than atom 'Y'
 * - If atom 'Y' is currently running on the HW, then it is interrupted to
 *   allow atom 'X' to run soon after
 * - If instead neither atom 'Y' nor atom 'X' are running, then when choosing
 *   the next atom to run, atom 'X' will always be chosen instead of atom 'Y'
 * - Any two atoms that have the same priority could run in any order with
 *   respect to each other. That is, there is no ordering constraint between
 *   atoms of the same priority.
 */
typedef u8 mali_jd_prio;
#define MALI_JD_PRIO_MEDIUM  ((mali_jd_prio)0)
#define MALI_JD_PRIO_HIGH    ((mali_jd_prio)1)
#define MALI_JD_PRIO_LOW     ((mali_jd_prio)2)

/**
 * @brief Job dependency type.
 *
 * A flags field will be inserted into the atom structure to specify whether a
 * dependency is a data or ordering dependency (by putting it before/after
 * 'core_req' in the structure it should be possible to add without changing
 * the structure size).  When the flag is set for a particular dependency to
 * signal that it is an ordering only dependency then errors will not be
 * propagated.
 */
typedef u8 mali_jd_dep_type;
#define MALI_JD_DEP_TYPE_INVALID  (0)       /**< Invalid dependency */
#define MALI_JD_DEP_TYPE_DATA     (1U << 0) /**< Data dependency */
#define MALI_JD_DEP_TYPE_ORDER    (1U << 1) /**< Order dependency */

/**
 * @brief Job chain hardware requirements.
 *
 * A job chain must specify what GPU features it needs to allow the
 * driver to schedule the job correctly.  By not specifying the
 * correct settings can/will cause an early job termination.  Multiple
 * values can be ORed together to specify multiple requirements.
 * Special case is ::MALI_JD_REQ_DEP, which is used to express complex
 * dependencies, and that doesn't execute anything on the hardware.
 */
typedef u32 mali_jd_core_req;

/* Requirements that come from the HW */

/**
 * No requirement, dependency only
 */
#define MALI_JD_REQ_DEP ((mali_jd_core_req)0)

/**
 * Requires fragment shaders
 */
#define MALI_JD_REQ_FS  ((mali_jd_core_req)1 << 0)

/**
 * Requires compute shaders
 * This covers any of the following Midgard Job types:
 * - Vertex Shader Job
 * - Geometry Shader Job
 * - An actual Compute Shader Job
 *
 * Compare this with @ref MALI_JD_REQ_ONLY_COMPUTE, which specifies that the
 * job is specifically just the "Compute Shader" job type, and not the "Vertex
 * Shader" nor the "Geometry Shader" job type.
 */
#define MALI_JD_REQ_CS  ((mali_jd_core_req)1 << 1)
#define MALI_JD_REQ_T   ((mali_jd_core_req)1 << 2)   /**< Requires tiling */
#define MALI_JD_REQ_CF  ((mali_jd_core_req)1 << 3)   /**< Requires cache flushes */
#define MALI_JD_REQ_V   ((mali_jd_core_req)1 << 4)   /**< Requires value writeback */

/* SW-only requirements - the HW does not expose these as part of the job slot
 * capabilities */

/* Requires fragment job with AFBC encoding */
#define MALI_JD_REQ_FS_AFBC  ((mali_jd_core_req)1 << 13)

/**
 * SW-only requirement: coalesce completion events.
 * If this bit is set then completion of this atom will not cause an event to
 * be sent to userspace, whether successful or not; completion events will be
 * deferred until an atom completes which does not have this bit set.
 *
 * This bit may not be used in combination with MALI_JD_REQ_EXTERNAL_RESOURCES.
 */
#define MALI_JD_REQ_EVENT_COALESCE ((mali_jd_core_req)1 << 5)

/**
 * SW Only requirement: the job chain requires a coherent core group. We don't
 * mind which coherent core group is used.
 */
#define MALI_JD_REQ_COHERENT_GROUP  ((mali_jd_core_req)1 << 6)

/**
 * SW Only requirement: The performance counters should be enabled only when
 * they are needed, to reduce power consumption.
 */

#define MALI_JD_REQ_PERMON               ((mali_jd_core_req)1 << 7)

/**
 * SW Only requirement: External resources are referenced by this atom.  When
 * external resources are referenced no syncsets can be bundled with the atom
 * but should instead be part of a NULL jobs inserted into the dependency
 * tree.  The first pre_dep object must be configured for the external
 * resouces to use, the second pre_dep object can be used to create other
 * dependencies.
 *
 * This bit may not be used in combination with MALI_JD_REQ_EVENT_COALESCE.
 */
#define MALI_JD_REQ_EXTERNAL_RESOURCES   ((mali_jd_core_req)1 << 8)

/**
 * SW Only requirement: Software defined job. Jobs with this bit set will not
 * be submitted to the hardware but will cause some action to happen within
 * the driver
 */
#define MALI_JD_REQ_SOFT_JOB        ((mali_jd_core_req)1 << 9)

#define MALI_JD_REQ_SOFT_DUMP_CPU_GPU_TIME      (MALI_JD_REQ_SOFT_JOB | 0x1)
#define MALI_JD_REQ_SOFT_FENCE_TRIGGER          (MALI_JD_REQ_SOFT_JOB | 0x2)
#define MALI_JD_REQ_SOFT_FENCE_WAIT             (MALI_JD_REQ_SOFT_JOB | 0x3)

/**
 * SW Only requirement : Replay job.
 *
 * If the preceding job fails, the replay job will cause the jobs specified in
 * the list of mali_jd_replay_payload pointed to by the jc pointer to be
 * replayed.
 *
 * A replay job will only cause jobs to be replayed up to MALIP_JD_REPLAY_LIMIT
 * times. If a job fails more than MALIP_JD_REPLAY_LIMIT times then the replay
 * job is failed, as well as any following dependencies.
 *
 * The replayed jobs will require a number of atom IDs. If there are not enough
 * free atom IDs then the replay job will fail.
 *
 * If the preceding job does not fail, then the replay job is returned as
 * completed.
 *
 * The replayed jobs will never be returned to userspace. The preceding failed
 * job will be returned to userspace as failed; the status of this job should
 * be ignored. Completion should be determined by the status of the replay soft
 * job.
 *
 * In order for the jobs to be replayed, the job headers will have to be
 * modified. The Status field will be reset to NOT_STARTED. If the Job Type
 * field indicates a Vertex Shader Job then it will be changed to Null Job.
 *
 * The replayed jobs have the following assumptions :
 *
 * - No external resources. Any required external resources will be held by the
 *   replay atom.
 * - Pre-dependencies are created based on job order.
 * - Atom numbers are automatically assigned.
 * - device_nr is set to 0. This is not relevant as
 *   MALI_JD_REQ_SPECIFIC_COHERENT_GROUP should not be set.
 * - Priority is inherited from the replay job.
 */
#define MALI_JD_REQ_SOFT_REPLAY                 (MALI_JD_REQ_SOFT_JOB | 0x4)
/**
 * SW only requirement: event wait/trigger job.
 *
 * - MALI_JD_REQ_SOFT_EVENT_WAIT: this job will block until the event is set.
 * - MALI_JD_REQ_SOFT_EVENT_SET: this job sets the event, thus unblocks the
 *   other waiting jobs. It completes immediately.
 * - MALI_JD_REQ_SOFT_EVENT_RESET: this job resets the event, making it
 *   possible for other jobs to wait upon. It completes immediately.
 */
#define MALI_JD_REQ_SOFT_EVENT_WAIT             (MALI_JD_REQ_SOFT_JOB | 0x5)
#define MALI_JD_REQ_SOFT_EVENT_SET              (MALI_JD_REQ_SOFT_JOB | 0x6)
#define MALI_JD_REQ_SOFT_EVENT_RESET            (MALI_JD_REQ_SOFT_JOB | 0x7)

#define MALI_JD_REQ_SOFT_DEBUG_COPY             (MALI_JD_REQ_SOFT_JOB | 0x8)

/**
 * SW only requirement: Just In Time allocation
 *
 * This job requests a JIT allocation based on the request in the
 * @base_jit_alloc_info structure which is passed via the jc element of
 * the atom.
 *
 * It should be noted that the id entry in @base_jit_alloc_info must not
 * be reused until it has been released via @MALI_JD_REQ_SOFT_JIT_FREE.
 *
 * Should this soft job fail it is expected that a @MALI_JD_REQ_SOFT_JIT_FREE
 * soft job to free the JIT allocation is still made.
 *
 * The job will complete immediately.
 */
#define MALI_JD_REQ_SOFT_JIT_ALLOC              (MALI_JD_REQ_SOFT_JOB | 0x9)
/**
 * SW only requirement: Just In Time free
 *
 * This job requests a JIT allocation created by @MALI_JD_REQ_SOFT_JIT_ALLOC
 * to be freed. The ID of the JIT allocation is passed via the jc element of
 * the atom.
 *
 * The job will complete immediately.
 */
#define MALI_JD_REQ_SOFT_JIT_FREE               (MALI_JD_REQ_SOFT_JOB | 0xa)

/**
 * SW only requirement: Map external resource
 *
 * This job requests external resource(s) are mapped once the dependencies
 * of the job have been satisfied. The list of external resources are
 * passed via the jc element of the atom which is a pointer to a
 * @base_external_resource_list.
 */
#define MALI_JD_REQ_SOFT_EXT_RES_MAP            (MALI_JD_REQ_SOFT_JOB | 0xb)
/**
 * SW only requirement: Unmap external resource
 *
 * This job requests external resource(s) are unmapped once the dependencies
 * of the job has been satisfied. The list of external resources are
 * passed via the jc element of the atom which is a pointer to a
 * @base_external_resource_list.
 */
#define MALI_JD_REQ_SOFT_EXT_RES_UNMAP          (MALI_JD_REQ_SOFT_JOB | 0xc)

/**
 * HW Requirement: Requires Compute shaders (but not Vertex or Geometry Shaders)
 *
 * This indicates that the Job Chain contains Midgard Jobs of the 'Compute
 * Shaders' type.
 *
 * In contrast to @ref MALI_JD_REQ_CS, this does \b not indicate that the Job
 * Chain contains 'Geometry Shader' or 'Vertex Shader' jobs.
 */
#define MALI_JD_REQ_ONLY_COMPUTE    ((mali_jd_core_req)1 << 10)

/**
 * HW Requirement: Use the mali_jd_atom::device_nr field to specify a
 * particular core group
 *
 * If both @ref MALI_JD_REQ_COHERENT_GROUP and this flag are set, this flag
 * takes priority
 *
 * This is only guaranteed to work for @ref MALI_JD_REQ_ONLY_COMPUTE atoms.
 *
 * If the core availability policy is keeping the required core group turned
 * off, then the job will fail with a @ref MALI_JD_EVENT_PM_EVENT error code.
 */
#define MALI_JD_REQ_SPECIFIC_COHERENT_GROUP ((mali_jd_core_req)1 << 11)

/**
 * SW Flag: If this bit is set then the successful completion of this atom
 * will not cause an event to be sent to userspace
 */
#define MALI_JD_REQ_EVENT_ONLY_ON_FAILURE   ((mali_jd_core_req)1 << 12)

/**
 * SW Flag: If this bit is set then completion of this atom will not cause an
 * event to be sent to userspace, whether successful or not.
 */
#define MALI_JD_REQ_EVENT_NEVER ((mali_jd_core_req)1 << 14)

/**
 * SW Flag: Skip GPU cache clean and invalidation before starting a GPU job.
 *
 * If this bit is set then the GPU's cache will not be cleaned and invalidated
 * until a GPU job starts which does not have this bit set or a job completes
 * which does not have the @ref MALI_JD_REQ_SKIP_CACHE_END bit set. Do not use if
 * the CPU may have written to memory addressed by the job since the last job
 * without this bit set was submitted.
 */
#define MALI_JD_REQ_SKIP_CACHE_START ((mali_jd_core_req)1 << 15)

/**
 * SW Flag: Skip GPU cache clean and invalidation after a GPU job completes.
 *
 * If this bit is set then the GPU's cache will not be cleaned and invalidated
 * until a GPU job completes which does not have this bit set or a job starts
 * which does not have the @ref MALI_JD_REQ_SKIP_CACHE_START bti set. Do not
 * use if the CPU may read from or partially overwrite memory addressed by the
 * job before the next job without this bit set completes.
 */
#define MALI_JD_REQ_SKIP_CACHE_END ((mali_jd_core_req)1 << 16)

/**
 * These requirement bits are currently unused in mali_jd_core_req
 */
#define MALIP_JD_REQ_RESERVED \
	(~(MALI_JD_REQ_ATOM_TYPE | MALI_JD_REQ_EXTERNAL_RESOURCES | \
	MALI_JD_REQ_EVENT_ONLY_ON_FAILURE | MALIP_JD_REQ_EVENT_NEVER | \
	MALI_JD_REQ_EVENT_COALESCE | \
	MALI_JD_REQ_COHERENT_GROUP | MALI_JD_REQ_SPECIFIC_COHERENT_GROUP | \
	MALI_JD_REQ_FS_AFBC | MALI_JD_REQ_PERMON | \
	MALI_JD_REQ_SKIP_CACHE_START | MALI_JD_REQ_SKIP_CACHE_END))

/**
 * Mask of all bits in mali_jd_core_req that control the type of the atom.
 *
 * This allows dependency only atoms to have flags set
 */
#define MALI_JD_REQ_ATOM_TYPE \
	(MALI_JD_REQ_FS | MALI_JD_REQ_CS | MALI_JD_REQ_T | MALI_JD_REQ_CF | \
	MALI_JD_REQ_V | MALI_JD_REQ_SOFT_JOB | MALI_JD_REQ_ONLY_COMPUTE)

/**
 * Mask of all bits in mali_jd_core_req that control the type of a soft job.
 */
#define MALI_JD_REQ_SOFT_JOB_TYPE (MALI_JD_REQ_SOFT_JOB | 0x1f)

/*
 * Returns non-zero value if core requirements passed define a soft job or
 * a dependency only job.
 */
#define MALI_JD_REQ_SOFT_JOB_OR_DEP(core_req) \
	((core_req & MALI_JD_REQ_SOFT_JOB) || \
	(core_req & MALI_JD_REQ_ATOM_TYPE) == MALI_JD_REQ_DEP)

/* Capabilities of a job slot as reported by JS_FEATURES registers */

#define JS_FEATURE_NULL_JOB              (1u << 1)
#define JS_FEATURE_SET_VALUE_JOB         (1u << 2)
#define JS_FEATURE_CACHE_FLUSH_JOB       (1u << 3)
#define JS_FEATURE_COMPUTE_JOB           (1u << 4)
#define JS_FEATURE_VERTEX_JOB            (1u << 5)
#define JS_FEATURE_GEOMETRY_JOB          (1u << 6)
#define JS_FEATURE_TILER_JOB             (1u << 7)
#define JS_FEATURE_FUSED_JOB             (1u << 8)
#define JS_FEATURE_FRAGMENT_JOB          (1u << 9)

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


/*
 * The original mali driver from ARM has two different representations of
 * pointers depending on which kind of structure we're looking at:
 *
 * - "Padded pointers" (as I've taken to calling them), which will always take
 *   up at least 64 bits of space regardless of whether the system is 32 or 64
 *   bit. When the system is 32 bit, the other half of the data is just
 *   padding.
 * - Variable length pointers, the length of which is equivalent to the native
 *   length of a pointer on the host system.
 *
 * For normal ioctls, padded pointers are used. For actual job submissions,
 * variable length is used.
 */
#ifdef __LP64__
#define PAD_CPU_PTR(p) p
typedef u64 mali_ptr;
typedef u64 mali_short_ptr;
#define MALI_PTR_FMT "0x%lx"
#define MALI_SHORT_PTR_FMT "0x%lx"

#else

#define PAD_CPU_PTR(p) p; u32 :32;
typedef u64 mali_ptr;
typedef u32 mali_short_ptr;
#define MALI_PTR_FMT "0x%llx"
#define MALI_SHORT_PTR_FMT "0x%x"
#endif

/* FIXME: Again, they don't specify any of these as packed structs. However,
 * looking at these structs I'm worried that there is already spots where the
 * compiler is potentially sticking in padding...
 * Going to try something a little crazy, and just hope that our compiler
 * happens to add the same kind of offsets since we can't really compare sizes
 */

/*
 * Blob provided by the driver to store callback driver, not actually modified
 * by the driver itself
 */
struct mali_jd_udata {
	u64 blob[2];
};

struct mali_jd_dependency {
	mali_atom_id  atom_id;               /**< An atom number */
	mali_jd_dep_type dependency_type;    /**< Dependency type */
};

#define MALI_EXT_RES_MAX 10

/* The original header never explicitly defines any values for these. In C,
 * this -should- expand to SHARED == 0 and EXCLUSIVE == 1, so the only flag we
 * actually need to decode here is EXCLUSIVE
 */
enum mali_external_resource_access {
	MALI_EXT_RES_ACCESS_SHARED,
	MALI_EXT_RES_ACCESS_EXCLUSIVE,
};

/* An aligned address to the resource | mali_external_resource_access */
typedef u64 mali_external_resource;

struct mali_jd_atom_v2 {
	mali_ptr jc;           /**< job-chain GPU address */
	struct mali_jd_udata udata;	    /**< user data */
	PAD_CPU_PTR(mali_external_resource *ext_res_list); /**< list of external resources */
	u16 nr_ext_res;			    /**< nr of external resources */
	u16 compat_core_req;	            /**< core requirements which
					      correspond to the legacy support
					      for UK 10.2 */
	struct mali_jd_dependency pre_dep[2];  /**< pre-dependencies, one need to
					      use SETTER function to assign
					      this field, this is done in
					      order to reduce possibility of
					      improper assigment of a
					      dependency field */
	mali_atom_id atom_number;	    /**< unique number to identify the
					      atom */
	mali_jd_prio prio;                  /**< Atom priority. Refer to @ref
					      mali_jd_prio for more details */
	u8 device_nr;			    /**< coregroup when
					      BASE_JD_REQ_SPECIFIC_COHERENT_GROUP
					      specified */
	u8 :8;
	mali_jd_core_req core_req;          /**< core requirements */
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_jd_atom_v2, 48, 48);

/**
 * enum mali_error - Mali error codes shared with userspace
 *
 * This is subset of those common Mali errors that can be returned to userspace.
 * Values of matching user and kernel space enumerators MUST be the same.
 * MALI_ERROR_NONE is guaranteed to be 0.
 *
 * @MALI_ERROR_NONE: Success
 * @MALI_ERROR_OUT_OF_GPU_MEMORY: Not used in the kernel driver
 * @MALI_ERROR_OUT_OF_MEMORY: Memory allocation failure
 * @MALI_ERROR_FUNCTION_FAILED: Generic error code
 */
enum mali_error {
	MALI_ERROR_NONE = 0,
	MALI_ERROR_OUT_OF_GPU_MEMORY,
	MALI_ERROR_OUT_OF_MEMORY,
	MALI_ERROR_FUNCTION_FAILED,
};

/**
 * Header used by all ioctls
 */
union mali_ioctl_header {
	/* [in] The ID of the UK function being called */
	u32 id :32;
	/* [out] The return value of the UK function that was called */
	enum mali_error rc :32;

	u64 :64;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(union mali_ioctl_header, 8, 8);

struct mali_ioctl_get_version {
	union mali_ioctl_header header;
	u16 major; /* [out] */
	u16 minor; /* [out] */
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_get_version, 16, 16);

struct mali_ioctl_mem_alloc {
	union mali_ioctl_header header;
	/* [in] */
	u64 va_pages;
	u64 commit_pages;
	u64 extent;
	/* [in/out] */
	u64 flags;
	/* [out] */
#ifdef XXX_POINTER_VOODOO_XXX
	u64 gpu_va;
#else
	mali_ptr gpu_va;
#endif
	u16 va_alignment;

	u32 :32;
	u16 :16;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_alloc, 56, 56);

struct mali_mem_import_user_buffer {
	u64 ptr;
	u64 length;
};

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
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_import, 48, 48);

struct mali_ioctl_mem_commit {
	union mali_ioctl_header header;
	/* [in] */
	mali_ptr gpu_addr;
	u64 pages;
	/* [out] */
	u32 result_subcode;
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_commit, 32, 32);

enum mali_ioctl_mem_query_type {
	MALI_MEM_QUERY_COMMIT_SIZE = 1,
	MALI_MEM_QUERY_VA_SIZE     = 2,
	MALI_MEM_QUERY_FLAGS       = 3
};

struct mali_ioctl_mem_query {
	union mali_ioctl_header header;
	/* [in] */
	mali_ptr gpu_addr;
	enum mali_ioctl_mem_query_type query : 32;
	u32 :32;
	/* [out] */
	u64 value;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_mem_query, 32, 32);

struct mali_ioctl_mem_free {
	union mali_ioctl_header header;
	mali_ptr gpu_addr; /* [in] */
} __attribute__((packed));
/* FIXME: Size unconfirmed (haven't seen in a trace yet) */

struct mali_ioctl_mem_flags_change {
	union mali_ioctl_header header;
	/* [in] */
	mali_ptr gpu_va;
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
	mali_ptr gpu_va;
	u64 va_pages;
} __attribute__((packed));

struct mali_ioctl_sync {
	union mali_ioctl_header header;
	mali_ptr handle;
	PAD_CPU_PTR(void* user_addr);
	u64 size;
	enum {
		MALI_SYNC_TO_DEVICE = 1,
		MALI_SYNC_TO_CPU = 2,
	} type :8;
	u64 :56;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_sync, 40, 40);

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
ASSERT_SIZEOF_TYPE(struct mali_ioctl_gpu_props_reg_dump, 536, 536);

struct mali_ioctl_set_flags {
	union mali_ioctl_header header;
	u32 create_flags; /* [in] */
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_set_flags, 16, 16);

struct mali_ioctl_stream_create {
	union mali_ioctl_header header;
	/* [in] */
	char name[32];
	/* [out] */
	s32 fd;
	u32 :32;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_stream_create, 48, 48);

struct mali_ioctl_job_submit {
	union mali_ioctl_header header;
	/* [in] */
	PAD_CPU_PTR(struct mali_jd_atom_v2 *addr);
	u32 nr_atoms;
	u32 stride;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_job_submit, 24, 24);

struct mali_ioctl_get_context_id {
	union mali_ioctl_header header;
	/* [out] */
	s64 id;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_ioctl_get_context_id, 16, 16);

#undef PAD_PTR

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
#define MALI_IOCTL_STREAM_CREATE           (_IOWR(0x82, 24, struct mali_ioctl_stream_create))
#define MALI_IOCTL_GET_PROFILING_CONTROLS  (_IOWR(0x82, 25, __ioctl_placeholder))
#define MALI_IOCTL_SET_PROFILING_CONTROLS  (_IOWR(0x82, 26, __ioctl_placeholder))
#define MALI_IOCTL_DEBUGFS_MEM_PROFILE_ADD (_IOWR(0x82, 27, __ioctl_placeholder))
#define MALI_IOCTL_JOB_SUBMIT              (_IOWR(0x82, 28, struct mali_ioctl_job_submit))
#define MALI_IOCTL_DISJOINT_QUERY          (_IOWR(0x82, 29, __ioctl_placeholder))
#define MALI_IOCTL_GET_CONTEXT_ID          (_IOWR(0x82, 31, struct mali_ioctl_get_context_id))
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
