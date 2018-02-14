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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include <panloader-util.h>
#include <mali-ioctl.h>
#include <pandev.h>
#include <mali-job.h>

#include <sys/user.h>

/* From Linux arch/arm/include/asm/page.h */

#define PAGE_SHIFT	12
#define PAGE_SIZE 	(1 << PAGE_SHIFT)
#define PAGE_MASK 	(~(PAGE_SIZE - 1))

/* From the kernel module */

#define MALI_MEM_MAP_TRACKING_HANDLE (3ull << 12)
#define MALI_CONTEXT_CREATE_FLAG_NONE 0

#define MAKE_TILE_COORD(X, Y, flag) ((X) | ((Y) << 16) | (flag))

/* From who knows where */
#define JOB_32_BIT 0
#define JOB_64_BIT 1

#include <sys/user.h>

/* From Linux arch/arm/include/asm/page.h */

#define PAGE_SHIFT	12
#ifndef PAGE_SIZE
# define PAGE_SIZE 	(1 << PAGE_SHIFT)
#endif
#ifndef PAGE_MASK
# define PAGE_MASK 	(~(PAGE_SIZE - 1))
#endif

/* From the kernel module */

#define MALI_MEM_MAP_TRACKING_HANDLE (3ull << 12)
#define MALI_CONTEXT_CREATE_FLAG_NONE 0

int
pandev_ioctl(int fd, unsigned long request, void *args)
{
	union mali_ioctl_header *h = args;
	int rc;

	h->id = ((_IOC_TYPE(request) & 0xF) << 8) | _IOC_NR(request);

	rc = ioctl(fd, request, args);
	if (rc)
		return rc;

	switch (h->rc) {
	case MALI_ERROR_NONE:              return 0;
	case MALI_ERROR_FUNCTION_FAILED:   return -EINVAL;
	case MALI_ERROR_OUT_OF_MEMORY:     return -ENOMEM;
	case MALI_ERROR_OUT_OF_GPU_MEMORY: return -ENOSPC;
	default:			   return -EINVAL;
	}
}

static int
pandev_get_driver_version(int fd, unsigned *major, unsigned *minor)
{
	int rc;

	/* Report old version for legacy mmap handling */
	struct mali_ioctl_get_version args = {
		.major = 8,
		.minor = 2
	};

	/* So far this seems to be the only ioctl that uses 0x80 for dir */
	rc = pandev_ioctl(fd, MALI_IOCTL_GET_VERSION, &args);
	if (rc)
		return rc;

	*major = args.major;
	*minor = args.minor;

	return 0;
}

static int
pandev_set_flags(int fd)
{
	struct mali_ioctl_set_flags args = {
		.create_flags = MALI_CONTEXT_CREATE_FLAG_NONE
	};

	return pandev_ioctl(fd, MALI_IOCTL_SET_FLAGS, &args);
}

static int
pandev_create_stream(int fd, const char *name, int *out)
{
	struct mali_ioctl_stream_create args = {};
	int rc;

	memcpy(args.name, name, strlen(name));

	rc = pandev_ioctl(fd, MALI_IOCTL_STREAM_CREATE, &args);
	if (rc)
		return rc;

	*out = args.fd;
	return 0;
}

static int
pandev_allocate(int fd, int va_pages, int commit_pages, int extent, int flags, u64 *out)
{
	struct mali_ioctl_mem_alloc args = {
		.va_pages = va_pages,
		.commit_pages = commit_pages,
		.extent = extent,
		.flags = flags
	};

	int rc;

	rc = pandev_ioctl(fd, MALI_IOCTL_MEM_ALLOC, &args);
	if (rc)
		return rc;

	if (args.flags & MALI_MEM_SAME_VA) {
		u8 *buffer = mmap(NULL, va_pages << PAGE_SHIFT, PROT_READ |
				PROT_WRITE, MAP_SHARED, fd, args.gpu_va);

		if (buffer == MAP_FAILED)
			return -1;

		*out = (u64) (uintptr_t) buffer;
	} else {
		*out = args.gpu_va;
	}

	return 0;
}

int
pandev_query_mem(int fd, mali_ptr addr, enum mali_ioctl_mem_query_type attr,
		 u64 *out)
{
	struct mali_ioctl_mem_query args;
	int rc;

	args.gpu_addr = addr;
	args.query = attr;

	rc = pandev_ioctl(fd, MALI_IOCTL_MEM_QUERY, &args);
	if (rc)
		return rc;

	*out = args.value;
	return 0;
}

#define ATOM_QUEUE_SIZE 16

struct mali_jd_atom_v2 pandev_atom_queue[ATOM_QUEUE_SIZE];
int pandev_atom_queue_count = 0;

/**
 * Submit the queued jobs to the GPU, clearing the queue. Should be called
 * explicitly, although pandev_submit_job may call it itself to flush the queue
 */

static int
pandev_flush_jobs(int fd)
{
	struct mali_ioctl_job_submit submit = {
		.addr = pandev_atom_queue,
		.nr_atoms = pandev_atom_queue_count,
		.stride = sizeof(struct mali_jd_atom_v2)
	};

	pandev_atom_queue_count = 0;

	return pandev_ioctl(fd, MALI_IOCTL_JOB_SUBMIT, &submit);
}

/**
 * Submit a job to the job queue, flushing the queue if necessary. Unless the
 * queue is full, this routine does NOT do any I/O. Once jobs are queued
 * appropriately, pandev_flush_jobs must be called explicitly.
 */

static int
pandev_submit_job(int fd, struct mali_jd_atom_v2 atom)
{
	memcpy(&pandev_atom_queue[pandev_atom_queue_count++], &atom, sizeof(atom));

	if(pandev_atom_queue_count == ATOM_QUEUE_SIZE)
		return pandev_flush_jobs(fd);

	return 0;
}

/**
 * Sync data to/from the GPU explicitly.
 * CPU is a pointer to the CPU-side buffer (CPU address space).
 * GPU is the GPU address to the GPU mapping.
 * Direction is one of MALI_SYNC_TO_DEVICE or MALI_SYNC_FROM_DEVICE
 *
 * Apparently (?), syncs must be page aligned, so a little excess is synced.
 *
 * TODO: Figure out exactly what and when data needs to be synced.
 */

static int
pandev_sync_gpu(int fd, u8* cpu, u64 gpu, size_t sz, int direction)
{
	struct mali_ioctl_sync sync = {
		.handle = gpu & PAGE_MASK,
		.user_addr = cpu - (gpu & ~PAGE_MASK),
		.size = (gpu & ~PAGE_MASK) + sz,
		.type = direction
	};

	return pandev_ioctl(fd, MALI_IOCTL_SYNC, &sync);
}

/* TODO: Replace with an actual heap-based allocator */

static u8 *
pandev_malloc(int fd, size_t sz)
{
	u64 va;
	int rc;
	
	rc = pandev_allocate(fd, 1 + (sz >> PAGE_SHIFT), 1 + (sz >> PAGE_SHIFT), 0, MALI_MEM_PROT_CPU_RD | MALI_MEM_PROT_CPU_WR | MALI_MEM_PROT_GPU_RD | MALI_MEM_PROT_GPU_WR | MALI_MEM_SAME_VA, &va);

	if (rc)
		return NULL;

	return (u8*) (uintptr_t) va;
}

static void
pandev_fragment_job(int fd)
{
	void* packet = pandev_malloc(fd, sizeof(struct mali_job_descriptor_header)
			+ sizeof(struct mali_payload_fragment));

	struct mali_job_descriptor_header header = {
		.exception_status = JOB_NOT_STARTED,
		.job_descriptor_size = JOB_32_BIT, /* TODO: Bifrost compatibility */
		.job_type = JOB_TYPE_FRAGMENT,
		.job_index = 1, /* TODO: Allocate these correctly */
	};

	u64 fbd_meta = MALI_MFBD;

	struct mali_payload_fragment payload = {
		._min_tile_coord = MAKE_TILE_COORD(0, 0, 0),
		._max_tile_coord = MAKE_TILE_COORD(29, 45, 0),
		.fbd = fbd_meta
	};

	memcpy(packet, &header, sizeof(header));
	memcpy(packet + sizeof(header), &payload, sizeof(payload));

	struct mali_jd_dependency no_dependency = {
		.atom_id = 0,
		.dependency_type = MALI_JD_DEP_TYPE_INVALID
	};

	struct mali_jd_dependency depTiler = {
		.atom_id = 0, /* TODO: Handle dependencies correctly */
		.dependency_type = MALI_JD_DEP_TYPE_DATA
	};

	/*
	uint64_t* resource = calloc(sizeof(u64), 1);
	resource[0] = framebuffer | MALI_EXT_RES_ACCESS_EXCLUSIVE;
	*/

	struct mali_jd_atom_v2 job = {
		.jc = (uint32_t) packet,

		//.ext_res_list = (struct mali_external_resource*) resource /* TODO */,
		//.nr_ext_res = 1,
		
		.ext_res_list = NULL /* TODO */,
		.nr_ext_res = 0,


		.core_req = MALI_JD_REQ_EXTERNAL_RESOURCES | MALI_JD_REQ_FS,

		//.atom_number = ++atom_count,
		.atom_number = 0, /* TODO */


		.prio = MALI_JD_PRIO_MEDIUM,
		.device_nr = 0,
		.pre_dep = { depTiler, no_dependency }
	};

	pandev_submit_job(fd, job);
}

/**
 * Dump detailed GPU properties. The userspace driver *does not actually need*
 * the majority of this information. At the moment, we need precisely none of
 * it. That said, when coupled with panwrap, this enables a nicely formatted
 * property display, which works without needing the blob at all.
 */

int
pandev_dump_gpu_properties(int fd)
{
	struct mali_ioctl_gpu_props_reg_dump args = {};
	int rc;

	rc = pandev_ioctl(fd, MALI_IOCTL_GPU_PROPS_REG_DUMP, &args);
	if (rc)
		return rc;

	return 0;
}

/**
 * Low-level open call, used by the main pandev_open
 */

int
pandev_raw_open()
{
	return open("/dev/mali0", O_RDWR | O_NONBLOCK | O_CLOEXEC);
}

/* The Memmap Tracking Handle is necessary to be mapped for the kernel
 * driver to be happy. It is still unclear why this is mapped or what
 * we are supposed to dowith the mapped region. TODO
 */

u8*
pandev_map_mtp(int fd)
{
	return mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_SHARED, fd, MALI_MEM_MAP_TRACKING_HANDLE);
}


/**
 * Open the device file for communicating with the mali kernelspace driver,
 * and make sure it's a version of the kernel driver we're familiar with.
 *
 * Returns: fd on success, -1 on failure
 */
int
pandev_open()
{
	int fd = pandev_raw_open(),
	    rc;
	unsigned major, minor;

	if (fd < 0)
		return fd;

	rc = pandev_get_driver_version(fd, &major, &minor);
	if (rc)
		return rc;

	printf("Found kernel driver version v%d.%d at /dev/mali0\n",
	       major, minor);

	if (pandev_map_mtp(fd) == MAP_FAILED)
		return -1;

	rc = pandev_set_flags(fd);
	if (rc)
		return rc;

	rc = pandev_dump_gpu_properties(fd);
	if (rc)
		return rc;

	pandev_fragment_job(fd);
	pandev_flush_jobs(fd);

	int stream_fd;

	rc = pandev_create_stream(fd, "insert-queer-pun-here", &stream_fd);
	if (rc)
		return 0; /* This breaks, we know that, just not why */

	return fd;
}
