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
#include <math.h>

#include <mali-ioctl.h>
#include "panwrap.h"

static pthread_mutex_t l = PTHREAD_MUTEX_INITIALIZER;

#define LOCK()   pthread_mutex_lock(&l)
#define UNLOCK() pthread_mutex_unlock(&l)

#define LOG_PRE(format, ...) \
	LOG("%s" format, "PRE  ", ## __VA_ARGS__)
#define LOG_POST(format, ...) \
	LOG("%s" format, "POST ", ## __VA_ARGS__)

#define IOCTL_CASE(request) (_IOWR(_IOC_TYPE(request), _IOC_NR(request), \
				   _IOC_SIZE(request)))

struct ioctl_info {
	const char *name;
};

struct device_info {
	const char *name;
	const struct ioctl_info info[MALI_IOCTL_TYPE_COUNT][_IOC_NR(0xffffffff)];
};

#define IOCTL_TYPE(type) [type - MALI_IOCTL_TYPE_BASE] =
#define IOCTL_INFO(n) [_IOC_NR(MALI_IOCTL_##n)] = { .name = #n }

static struct device_info mali_info = {
	.name = "mali",
	.info = {
		IOCTL_TYPE(0x80) {
			IOCTL_INFO(GET_VERSION),
		},
		IOCTL_TYPE(0x82) {
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
	},
};
#undef IOCTL_INFO
#undef IOCTL_TYPE

static inline const struct ioctl_info *
ioctl_get_info(unsigned long int request)
{
	return &mali_info.info[_IOC_TYPE(request) - MALI_IOCTL_TYPE_BASE]
	                      [_IOC_NR(request)];
}

static int mali_fd = 0;

#define FLAG_INFO(flag) { MALI_MEM_##flag, #flag }
static const struct panwrap_flag_info mem_flag_info[] = {
	FLAG_INFO(PROT_CPU_RD),
	FLAG_INFO(PROT_CPU_WR),
	FLAG_INFO(PROT_GPU_RD),
	FLAG_INFO(PROT_GPU_WR),
	FLAG_INFO(PROT_GPU_EX),
	FLAG_INFO(GROW_ON_GPF),
	FLAG_INFO(COHERENT_SYSTEM),
	FLAG_INFO(COHERENT_LOCAL),
	FLAG_INFO(CACHED_CPU),
	FLAG_INFO(SAME_VA),
	FLAG_INFO(NEED_MMAP),
	FLAG_INFO(COHERENT_SYSTEM_REQUIRED),
	FLAG_INFO(SECURE),
	FLAG_INFO(DONT_NEED),
	FLAG_INFO(IMPORT_SHARED),
	{}
};
#undef FLAG_INFO

static inline const char *
ioctl_decode_coherency_mode(enum mali_ioctl_coherency_mode mode)
{
	switch (mode) {
	case COHERENCY_ACE_LITE: return "ACE_LITE";
	case COHERENCY_ACE:      return "ACE";
	case COHERENCY_NONE:     return "None";
	default:                 return "???";
	}
}

static void
ioctl_decode_pre_mem_alloc(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alloc *args = ptr;

	LOG_PRE("\tva_pages = %ld\n", args->va_pages);
	LOG_PRE("\tcommit_pages = %ld\n", args->commit_pages);
	LOG_PRE("\textent = 0x%lx\n", args->extent);

	LOG_PRE("\tflags = ");
	panwrap_print_decoded_flags(mem_flag_info, args->flags);
	printf("\n");
}

static void
ioctl_decode_pre_mem_import(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_import *args = ptr;
	const char *type;

	switch (args->type) {
	case MALI_MEM_IMPORT_TYPE_UMP:         type = "UMP"; break;
	case MALI_MEM_IMPORT_TYPE_UMM:         type = "UMM"; break;
	case MALI_MEM_IMPORT_TYPE_USER_BUFFER: type = "User buffer"; break;
	default:                               type = "Invalid"; break;
	}

	LOG_PRE("\tphandle = 0x%lx\n", args->phandle);
	LOG_PRE("\ttype = %d (%s)\n", args->type, type);

	LOG_PRE("\tflags = ");
	panwrap_print_decoded_flags(mem_flag_info, args->flags);
	printf("\n");
}

static void
ioctl_decode_pre_mem_commit(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_commit *args = ptr;

	LOG_PRE("\tgpu_addr = 0x%lx\n", args->gpu_addr);
	LOG_PRE("\tpages = %ld\n", args->pages);
}

static void
ioctl_decode_pre_mem_query(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_query *args = ptr;
	char *query_name;

	switch (args->query) {
	case MALI_MEM_QUERY_COMMIT_SIZE: query_name = "Commit size"; break;
	case MALI_MEM_QUERY_VA_SIZE:     query_name = "VA size"; break;
	case MALI_MEM_QUERY_FLAGS:       query_name = "Flags"; break;
	default:                         query_name = "???"; break;
	}

	LOG_PRE("\tgpu_addr = 0x%lx\n", args->gpu_addr);
	LOG_PRE("\tquery = %d (%s)\n", args->query, query_name);
}

static void
ioctl_decode_pre_mem_free(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_free *args = ptr;

	LOG_PRE("\tgpu_addr = 0x%lx\n", args->gpu_addr);
}

static void
ioctl_decode_pre_mem_flags_change(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_flags_change *args = ptr;

	LOG_PRE("\tgpu_va = 0x%lx\n", args->gpu_va);
	LOG_PRE("\tflags = ");
	panwrap_print_decoded_flags(mem_flag_info, args->flags);
	printf("\n");
	LOG_PRE("\tmask = 0x%lx\n", args->mask);
}

static void
ioctl_decode_pre_mem_alias(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alias *args = ptr;

	LOG_PRE("\tflags = ");
	panwrap_print_decoded_flags(mem_flag_info, args->flags);
	printf("\n");
	LOG_PRE("\tstride = %ld\n", args->stride);
	LOG_PRE("\tnents = %ld\n", args->nents);
	LOG_PRE("\tai = 0x%lx\n", args->ai);
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
	switch (IOCTL_CASE(request)) {
	case IOCTL_CASE(MALI_IOCTL_MEM_ALLOC):
		ioctl_decode_pre_mem_alloc(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_IMPORT):
		ioctl_decode_pre_mem_import(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_COMMIT):
		ioctl_decode_pre_mem_commit(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_QUERY):
		ioctl_decode_pre_mem_query(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_FREE):
		ioctl_decode_pre_mem_free(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_FLAGS_CHANGE):
		ioctl_decode_pre_mem_flags_change(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_ALIAS):
		ioctl_decode_pre_mem_alias(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_SET_FLAGS):
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
ioctl_decode_post_mem_alloc(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alloc *args = ptr;

	LOG_POST("\tgpu_va = 0x%lx\n", args->gpu_va);
	LOG_POST("\tva_alignment = %d\n", args->va_alignment);
}

static void
ioctl_decode_post_mem_import(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_import *args = ptr;

	LOG_POST("\tgpu_va = 0x%lx\n", args->gpu_va);
	LOG_POST("\tva_pages = %ld\n", args->va_pages);
	LOG_POST("\tflags = ");
	panwrap_print_decoded_flags(mem_flag_info, args->flags);
	printf("\n");
}

static void
ioctl_decode_post_mem_commit(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_commit *args = ptr;

	LOG_POST("\tresult_subcode = %d\n", args->result_subcode);
}

static void
ioctl_decode_post_mem_query(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_query *args = ptr;

	LOG_POST("\tvalue = 0x%lx\n", args->value);
}

static void
ioctl_decode_post_mem_alias(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alias *args = ptr;

	LOG_POST("\tgpu_va = 0x%lx\n", args->gpu_va);
	LOG_POST("\tva_pages = %ld\n", args->va_pages);
}

static void
ioctl_decode_post_gpu_props_reg_dump(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_gpu_props_reg_dump *args = ptr;
	const char *implementation;

	switch (args->thread.impl_tech) {
	case MALI_GPU_IMPLEMENTATION_UNKNOWN: implementation = "Unknown"; break;
	case MALI_GPU_IMPLEMENTATION_SILICON: implementation = "Silicon"; break;
	case MALI_GPU_IMPLEMENTATION_FPGA:    implementation = "FPGA"; break;
	case MALI_GPU_IMPLEMENTATION_SW:      implementation = "Software"; break;
	}

	LOG_POST("\tcore:\n");
	LOG_POST("\t\tProduct ID: %d\n", args->core.product_id);
	LOG_POST("\t\tVersion status: %d\n", args->core.version_status);
	LOG_POST("\t\tMinor revision: %d\n", args->core.minor_revision);
	LOG_POST("\t\tMajor revision: %d\n", args->core.major_revision);
	LOG_POST("\t\tGPU speed (?): %dMHz\n", args->core.gpu_speed_mhz);
	LOG_POST("\t\tGPU frequencies (?): %dKHz-%dKHz\n",
		 args->core.gpu_freq_khz_min, args->core.gpu_freq_khz_max);
	LOG_POST("\t\tShader program counter size: %.lf MB\n",
		 pow(2, args->core.log2_program_counter_size) / 1024 / 1024);

	LOG_POST("\t\tTexture features:\n");
	for (int i = 0; i < ARRAY_SIZE(args->core.texture_features); i++)
		LOG_POST("\t\t\t%010x\n", args->core.texture_features[i]);

	LOG_POST("\t\tAvailable memory: %ld bytes\n",
		 args->core.gpu_available_memory_size);

	LOG_POST("\tL2 cache:\n");
	LOG_POST("\t\tLine size: %.lf (bytes, words?)\n",
		 pow(2, args->l2.log2_line_size));
	LOG_POST("\t\tCache size: %.lf KB\n",
		 pow(2, args->l2.log2_cache_size) / 1024);
	LOG_POST("\t\tL2 slice count: %d\n", args->l2.num_l2_slices);

	LOG_POST("\tTiler:\n");
	LOG_POST("\t\tBinary size: %d bytes\n", args->tiler.bin_size_bytes);
	LOG_POST("\t\tMax active levels: %d\n", args->tiler.max_active_levels);

	LOG_POST("\tThreads:\n");
	LOG_POST("\t\tMax threads: %d\n", args->thread.max_threads);
	LOG_POST("\t\tMax threads per workgroup: %d\n",
		 args->thread.max_workgroup_size);
	LOG_POST("\t\tMax threads allowed for synchronizing on simple barrier: %d\n",
		 args->thread.max_barrier_size);
	LOG_POST("\t\tMax registers available per-core: %d\n",
		 args->thread.max_registers);
	LOG_POST("\t\tMax tasks that can be sent to a core before blocking: %d\n",
		 args->thread.max_task_queue);
	LOG_POST("\t\tMax allowed thread group split value: %d\n",
		 args->thread.max_thread_group_split);
	LOG_POST("\t\tImplementation type: %d (%s)\n",
		 args->thread.impl_tech, implementation);

	LOG_POST("\tRaw props:\n");
	LOG_POST("\t\tShader present? %s\n", YES_NO(args->raw.shader_present));
	LOG_POST("\t\tTiler present? %s\n", YES_NO(args->raw.tiler_present));
	LOG_POST("\t\tL2 present? %s\n", YES_NO(args->raw.l2_present));
	LOG_POST("\t\tStack present? %s\n", YES_NO(args->raw.stack_present));
	LOG_POST("\t\tL2 features: 0x%010x\n", args->raw.l2_features);
	LOG_POST("\t\tSuspend size: %d\n", args->raw.suspend_size);
	LOG_POST("\t\tMemory features: 0x%010x\n", args->raw.mem_features);
	LOG_POST("\t\tMMU features: 0x%010x\n", args->raw.mmu_features);
	LOG_POST("\t\tAS (what is this?) present? %s\n",
		 YES_NO(args->raw.as_present));

	LOG_POST("\t\tJS (what is this?) present? %s\n",
		 YES_NO(args->raw.js_present));
	LOG_POST("\t\tJS features:\n");
	for (int i = 0; i < ARRAY_SIZE(args->raw.js_features); i++)
		LOG_POST("\t\t\t%010x\n", args->raw.js_features[i]);

	LOG_POST("\t\tTiler features: %010x\n", args->raw.tiler_features);

	LOG_POST("\t\tGPU ID: 0x%x\n", args->raw.gpu_id);
	LOG_POST("\t\tThread features: 0x%x\n", args->raw.thread_features);
	LOG_POST("\t\tCoherency mode: 0x%x (%s)\n",
		 args->raw.coherency_mode,
		 ioctl_decode_coherency_mode(args->raw.coherency_mode));

	LOG_POST("\tCoherency info:\n");
	LOG_POST("\t\tNumber of groups: %d\n", args->coherency_info.num_groups);
	LOG_POST("\t\tNumber of core groups (coherent or not): %d\n",
		 args->coherency_info.num_core_groups);
	LOG_POST("\t\tFeatures: 0x%x\n", args->coherency_info.coherency);
	LOG_POST("\t\tGroups:\n");
	for (int i = 0; i < args->coherency_info.num_groups; i++) {
		LOG_POST("\t\t\t- Core mask: %010lx\n",
			 args->coherency_info.group[i].core_mask);
		LOG_POST("\t\t\t  Number of cores: %d\n",
			 args->coherency_info.group[i].num_cores);
	}
}

static void
ioctl_decode_post(unsigned long int request, void *ptr)
{
	switch (IOCTL_CASE(request)) {
	case IOCTL_CASE(MALI_IOCTL_GET_VERSION):
	case IOCTL_CASE(MALI_IOCTL_GET_VERSION_NEW):
		ioctl_decode_post_get_version(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_ALLOC):
		ioctl_decode_post_mem_alloc(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_IMPORT):
		ioctl_decode_post_mem_import(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_COMMIT):
		ioctl_decode_post_mem_commit(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_QUERY):
		ioctl_decode_post_mem_query(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_MEM_ALIAS):
		ioctl_decode_post_mem_alias(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_GPU_PROPS_REG_DUMP):
		ioctl_decode_post_gpu_props_reg_dump(request, ptr);
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
	name = ioctl_get_info(request)->name ?: "???";
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
