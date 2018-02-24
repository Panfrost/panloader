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
#include <stdbool.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/ioctl.h>
#include <math.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#include <mali-ioctl.h>
#include <list.h>
#include "panwrap.h"

static pthread_mutex_t l;
PANLOADER_CONSTRUCTOR {
	pthread_mutexattr_t mattr;

	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&l, &mattr);
	pthread_mutexattr_destroy(&mattr);
}

#define IOCTL_CASE(request) (_IOWR(_IOC_TYPE(request), _IOC_NR(request), \
				   _IOC_SIZE(request)))

struct ioctl_info {
	const char *name;
};

struct device_info {
	const char *name;
	const struct ioctl_info info[MALI_IOCTL_TYPE_COUNT][_IOC_NR(0xffffffff)];
};

typedef void* (mmap_func)(void *, size_t, int, int, int, loff_t);
typedef int (open_func)(const char *, int flags, ...);

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
static long context_id = 0;
static char debugfs_ctx_path[PATH_MAX] = {0};
static LIST_HEAD(allocations);
static LIST_HEAD(mmaps);

static bool step_mode;
static long log_delay;
const char* replace_fragment;
const char* replace_vertex;

static const char *dump_dir;
static int dump_dir_fd;
static int debugfs_fd;
PANLOADER_CONSTRUCTOR {
	log_delay = panwrap_parse_env_long("PANWRAP_LOG_DELAY", 0);
	replace_fragment = panwrap_parse_env_string("PANWRAP_REPLACE_FRAGMENT", "");
	replace_vertex = panwrap_parse_env_string("PANWRAP_REPLACE_VERTEX", "");
	dump_dir = panwrap_parse_env_string("PANWRAP_DUMP_DIR", NULL);
	step_mode = panwrap_parse_env_bool("PANWRAP_STEP", false);

	if (dump_dir != NULL) {
		mkdir(dump_dir, 0777);

		dump_dir_fd = open(dump_dir, O_DIRECTORY);
		if (dump_dir_fd < 0) {
			fprintf(stderr,
				"Failed to create/open %s: %s\n",
				dump_dir, strerror(errno));
			abort();
		}
	}
}

#define LOCK()   pthread_mutex_lock(&l);
#define UNLOCK() panwrap_log_flush(); pthread_mutex_unlock(&l)

#define FLAG_INFO(flag) { MALI_MEM_##flag, "MALI_MEM_" #flag }
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

#define FLAG_INFO(flag) { MALI_JD_REQ_##flag, "MALI_JD_REQ_" #flag }
static const struct panwrap_flag_info jd_req_flag_info[] = {
	FLAG_INFO(FS),
	FLAG_INFO(CS),
	FLAG_INFO(T),
	FLAG_INFO(CF),
	FLAG_INFO(V),
	FLAG_INFO(FS_AFBC),
	FLAG_INFO(EVENT_COALESCE),
	FLAG_INFO(COHERENT_GROUP),
	FLAG_INFO(PERMON),
	FLAG_INFO(EXTERNAL_RESOURCES),
	FLAG_INFO(ONLY_COMPUTE),
	FLAG_INFO(SPECIFIC_COHERENT_GROUP),
	FLAG_INFO(EVENT_ONLY_ON_FAILURE),
	FLAG_INFO(EVENT_NEVER),
	FLAG_INFO(SKIP_CACHE_START),
	FLAG_INFO(SKIP_CACHE_END),
	{}
};
#undef FLAG_INFO

#define FLAG_INFO(flag) { flag, #flag }
static const struct panwrap_flag_info external_resources_access_flag_info[] = {
	FLAG_INFO(MALI_EXT_RES_ACCESS_SHARED),
	FLAG_INFO(MALI_EXT_RES_ACCESS_EXCLUSIVE),
	{}
};

static const struct panwrap_flag_info mali_jd_dep_type_flag_info[] = {
	FLAG_INFO(MALI_JD_DEP_TYPE_DATA),
	FLAG_INFO(MALI_JD_DEP_TYPE_ORDER),
	{}
};
#undef FLAG_INFO

#define FLAG_INFO(flag) { JS_FEATURE_##flag, "JS_FEATURE_" #flag }
static const struct panwrap_flag_info js_feature_info[] = {
	FLAG_INFO(NULL_JOB),
	FLAG_INFO(SET_VALUE_JOB),
	FLAG_INFO(CACHE_FLUSH_JOB),
	FLAG_INFO(COMPUTE_JOB),
	FLAG_INFO(VERTEX_JOB),
	FLAG_INFO(GEOMETRY_JOB),
	FLAG_INFO(TILER_JOB),
	FLAG_INFO(FUSED_JOB),
	FLAG_INFO(FRAGMENT_JOB),
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

static inline const char *
ioctl_decode_jd_prio(mali_jd_prio prio)
{
	switch (prio) {
	case MALI_JD_PRIO_LOW:    return "Low";
	case MALI_JD_PRIO_MEDIUM: return "Medium";
	case MALI_JD_PRIO_HIGH:   return "High";
	default:                  return "???";
	}
}

/*
 * Decodes the jd_core_req flags and their real meanings
 * See mali_kbase_jd.c
 */
static inline const char *
ioctl_get_job_type_from_jd_core_req(mali_jd_core_req req)
{
	if (req & MALI_JD_REQ_SOFT_JOB)
		return "Soft job";
	if (req & MALI_JD_REQ_ONLY_COMPUTE)
		return "Compute Shader Job";

	switch (req & (MALI_JD_REQ_FS | MALI_JD_REQ_CS | MALI_JD_REQ_T)) {
	case MALI_JD_REQ_DEP:
		return "Dependency only job";
	case MALI_JD_REQ_FS:
		return "Fragment shader job";
	case MALI_JD_REQ_CS:
		return "Vertex/Geometry shader job";
	case MALI_JD_REQ_T:
		return "Tiler job";
	case (MALI_JD_REQ_FS | MALI_JD_REQ_CS):
		return "Fragment shader + vertex/geometry shader job";
	case (MALI_JD_REQ_FS | MALI_JD_REQ_T):
		return "Fragment shader + tiler job";
	case (MALI_JD_REQ_CS | MALI_JD_REQ_T):
		return "Vertex/geometry shader job + tiler job";
	case (MALI_JD_REQ_FS | MALI_JD_REQ_CS | MALI_JD_REQ_T):
		return "Fragment shader + vertex/geometry shader job + tiler job";
	}

	return "???";
}

#define SOFT_FLAG(flag)                                  \
	case MALI_JD_REQ_SOFT_##flag:                    \
		panwrap_log_cont("MALI_JD_REQ_%s", "SOFT_" #flag); \
		break
/* Decodes the actual jd_core_req flags, but not their meanings */
void
ioctl_log_decoded_jd_core_req(mali_jd_core_req req)
{
	if (req & MALI_JD_REQ_SOFT_JOB) {
		/* External resources are allowed in e.g. replay jobs */

		if (req & MALI_JD_REQ_EXTERNAL_RESOURCES) {
			panwrap_log_cont("MALI_JD_REQ_EXTERNAL_RESOURCES | ");
			req &= ~(MALI_JD_REQ_EXTERNAL_RESOURCES);
		}

		switch (req) {
		SOFT_FLAG(DUMP_CPU_GPU_TIME);
		SOFT_FLAG(FENCE_TRIGGER);
		SOFT_FLAG(FENCE_WAIT);
		SOFT_FLAG(REPLAY);
		SOFT_FLAG(EVENT_WAIT);
		SOFT_FLAG(EVENT_SET);
		SOFT_FLAG(EVENT_RESET);
		SOFT_FLAG(DEBUG_COPY);
		SOFT_FLAG(JIT_ALLOC);
		SOFT_FLAG(JIT_FREE);
		SOFT_FLAG(EXT_RES_MAP);
		SOFT_FLAG(EXT_RES_UNMAP);
		default: panwrap_log_cont("0x%010x", req); break;
		}
	} else {
		panwrap_log_decoded_flags(jd_req_flag_info, req);
	}
}
#undef SOFT_FLAG

static void
do_dump_file(const char *name, int in, int out)
{
	unsigned char buf[4096];
	ssize_t in_ret, out_ret;

	do {
		in_ret = read(in, buf, sizeof(buf));
		if (in_ret < 0 && errno != EAGAIN) {
			fprintf(stderr, "Failed to read %s: %s\n",
				name, strerror(errno));
			abort();
		}

		out_ret = write(out, buf, in_ret);
		if (out_ret && out_ret != in_ret) {
			fprintf(stderr, "Failed to write %s: %s\n",
				name, strerror(errno));
			abort();
		}
	} while (in_ret > 0);
}

static void
dump_debugfs(unsigned int request) {
	const struct ioctl_info *ioc_info;
	int outd_fd,
	    mem_view_fd, mem_view_out_fd,
	    mem_profile_fd, mem_profile_out_fd,
	    atoms_fd, atoms_out_fd;
	char outd_name[PATH_MAX];
	struct timespec tp;
	int ret;

	if (dump_dir == NULL)
		return;

	if (context_id == 0) {
		panwrap_msg("Error! dump_debugfs() called but no context_id?\n");
		return;
	}

	ioc_info = ioctl_get_info(request);

	/* Create outd */
	panwrap_timestamp(&tp);
	snprintf(outd_name, sizeof(outd_name),
		 "%ld.%ld-%s", tp.tv_sec, tp.tv_nsec, ioc_info->name);

	ret = mkdirat(dump_dir_fd, outd_name, 0777);
	if (ret < 0) {
		fprintf(stderr,
			"Error! Failed to create dump dir %s: %s\n",
			outd_name, strerror(errno));
		abort();
	}
	outd_fd = openat(dump_dir_fd, outd_name, O_DIRECTORY);
	if (outd_fd < 0) {
		fprintf(stderr,
			"Error! Failed to open dump dir %s: %s\n",
			outd_name, strerror(errno));
		abort();
	}

#define TRY_COPY(name)                                                \
	name ## _fd = openat(debugfs_fd, #name, O_RDONLY);            \
	if (name ## _fd < 0) {                                        \
		fprintf(stderr, "Error: Failed to open %s: %s\n",     \
                        #name, strerror(errno));                      \
		abort();                                              \
	}                                                             \
	name ## _out_fd = openat(outd_fd, #name, O_WRONLY | O_CREAT); \
	if (name ## _out_fd < 0) {                                    \
		fprintf(stderr, "Error: Failed to create %s: %s\n",   \
                        #name, strerror(errno));                      \
		abort();                                              \
	}                                                             \
                                                                      \
	do_dump_file(#name, name ## _fd, name ## _out_fd);            \
	close(name ## _fd);                                           \
	close(name ## _out_fd);

	TRY_COPY(mem_view);
	TRY_COPY(atoms);

	/* mem_profile doesn't always exist! */
	mem_profile_fd = openat(debugfs_fd, "mem_profile",
				O_RDONLY | O_NONBLOCK);
	if (mem_profile_fd > 0) {
		mem_profile_out_fd = openat(outd_fd,
					    "mem_profile",
					    O_WRONLY | O_NONBLOCK | O_CREAT);
		if (mem_profile_out_fd < 0) {
			fprintf(stderr, "Error: Failed to create mem_profile: %s\n",
				strerror(errno));
			abort();
		}

		do_dump_file("mem_profile", mem_profile_fd, mem_profile_out_fd);

		close(mem_profile_fd);
		close(mem_profile_out_fd);
	}

	close(outd_fd);
}

static inline void
ioctl_decode_pre_get_version(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_get_version *args = ptr;

	panwrap_prop("major = %3d", args->major);
	panwrap_prop("minor = %3d", args->minor);
}

static inline void
ioctl_decode_pre_mem_alloc(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alloc *args = ptr;

	panwrap_prop("va_pages = %" PRId64, args->va_pages);
	panwrap_prop("commit_pages = %" PRId64, args->commit_pages);
	panwrap_prop("extent = 0x%" PRIx64, args->extent);

	panwrap_log(".flags = ");
	panwrap_log_decoded_flags(mem_flag_info,
			do_replay ? args->flags & ~MALI_MEM_CACHED_CPU : args->flags);
	panwrap_log_cont(",\n");
}

static inline void
ioctl_decode_pre_mem_import(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_import *args = ptr;

	if (do_replay) {
		/* Imports afaik are just used for framebuffers, so we'll emit an allocation for that here */
		panwrap_prop("phandle = (uint64_t) (uintptr_t) &framebuffer_handle");
		panwrap_prop("type = MALI_MEM_IMPORT_TYPE_USER_BUFFER");
	} else {
		const char *type;

		panwrap_prop("phandle = 0x%" PRIx64, args->phandle);

		switch (args->type) {
		case MALI_MEM_IMPORT_TYPE_UMP:         type = "UMP"; break;
		case MALI_MEM_IMPORT_TYPE_UMM:         type = "UMM"; break;
		case MALI_MEM_IMPORT_TYPE_USER_BUFFER: type = "USER_BUFFER"; break;
		default:                               type = "Invalid"; break;
		}

		panwrap_prop("type = MALI_MEM_IMPORT_TYPE_%s", type);
	}


	panwrap_log(".flags = ");
	panwrap_log_decoded_flags(mem_flag_info, args->flags);
	panwrap_log_cont(",\n");
}

static inline void
ioctl_decode_pre_mem_commit(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_commit *args = ptr;

	panwrap_prop("gpu_addr = " MALI_PTR_FMT, args->gpu_addr);
	panwrap_prop("pages = %" PRId64, args->pages);
}

static inline void
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

	panwrap_prop("gpu_addr = " MALI_PTR_FMT, args->gpu_addr);
	panwrap_prop("query = %d (%s)", args->query, query_name);
}

static inline void
ioctl_decode_pre_mem_free(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_free *args = ptr;

	panwrap_prop("gpu_addr = " MALI_PTR_FMT, args->gpu_addr);
}

static inline void
ioctl_decode_pre_mem_flags_change(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_flags_change *args = ptr;

	panwrap_prop("gpu_va = " MALI_PTR_FMT, args->gpu_va);
	panwrap_log(".flags = ");
	panwrap_log_decoded_flags(mem_flag_info, args->flags);
	panwrap_log_cont("\n");
	panwrap_prop("mask = 0x%" PRIx64, args->mask);
}

static inline void
ioctl_decode_pre_mem_alias(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alias *args = ptr;

	panwrap_prop("flags = ");
	panwrap_log_decoded_flags(mem_flag_info, args->flags);
	panwrap_log_cont("\n");
	panwrap_prop("stride = %" PRId64, args->stride);
	panwrap_prop("nents = %" PRId64, args->nents);
	panwrap_prop("ai = 0x%" PRIx64, args->ai);
}

static inline void
ioctl_decode_pre_sync(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_sync *args = ptr;
	struct panwrap_mapped_memory *mem =
		panwrap_find_mapped_gpu_mem(args->handle);

	panwrap_prop("size = %" PRId64, args->size);

	if (!mem) {
		panwrap_msg("ERROR! Unknown handle specified\n");
		panwrap_prop("handle = " MALI_PTR_FMT, args->handle);
		panwrap_prop("user_addr = %p", args->user_addr);
		return;
	}

	if (do_replay) {
		/* Only fix up addresses if they are SAME_VA and therefore can be fixe d*/

		if (args->handle == (mali_ptr) (uintptr_t) mem->addr)
			panwrap_prop("handle = (mali_ptr) (void*) %s", mem->name);
		else
			panwrap_prop("handle = " MALI_PTR_FMT, args->handle);

		panwrap_prop("user_addr = %s + %d", mem->name, args->user_addr - mem->addr);

		panwrap_prop("type = %s", args->type == MALI_SYNC_TO_DEVICE ? "MALI_SYNC_TO_DEVICE" : "MALI_SYNC_TO_CPU");
	} else {
		const char *type;

		switch (args->type) {
		case MALI_SYNC_TO_DEVICE: type = "device <- CPU"; break;
		case MALI_SYNC_TO_CPU:    type = "device -> CPU"; break;
		default:                  type = "???"; break;
		}

		panwrap_prop("handle = " MALI_PTR_FMT " (end=" MALI_PTR_FMT ", len=%zu)",
			    args->handle,
			    (mali_ptr)(args->handle + mem->length - 1),
			    mem->length);
		panwrap_prop("user_addr = %p - %p (offset=%zu)",
			    args->user_addr, args->user_addr + args->size - 1,
			    args->user_addr - mem->addr);

		panwrap_prop("type = %d (%s)", args->type, type);

		if (args->type == MALI_SYNC_TO_DEVICE) {
			dump_debugfs(request);
			panwrap_msg("Dumping memory being synced to device:\n");
			panwrap_indent++;
			panwrap_log_hexdump(args->user_addr, args->size);
			panwrap_indent--;
		}
	}
}

static inline void
ioctl_decode_pre_set_flags(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_set_flags *args = ptr;

	panwrap_prop("create_flags = %08x", args->create_flags);
}

static int stream_count = 0;

static inline void
ioctl_decode_pre_stream_create(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_stream_create *args = ptr;

	/* Stream name is not semantic as far as I know, but the blob allocates
	 * them nondeterministically. Patch over this here for repro. */

	if (do_replay)
		panwrap_prop("name = \"stream_%d\"", stream_count++);
	else
		panwrap_prop("name = \"%s\"", args->name);
}

static int job_count = 0;

static void emit_atoms(void *ptr) {
	const struct mali_ioctl_job_submit *args = ptr;
	const struct mali_jd_atom_v2 *atoms = args->addr;

	int job_no = job_count++;

	for (int i = 0; i < args->nr_atoms; i++) {
		const struct mali_jd_atom_v2 *a = &atoms[i];

		if (a->jc) {
			/* We don't care about soft jobs, at least not yet */

			if (!(a->core_req & MALI_JD_REQ_SOFT_JOB))
				panwrap_replay_jc(a->jc);
			else if (a->core_req & MALI_JD_REQ_SOFT_REPLAY)
				panwrap_replay_soft_replay(a->jc);
		}
	}

	for (int i = 0; i < args->nr_atoms; i++) {
		const struct mali_jd_atom_v2 *a = &atoms[i];

		if (a->ext_res_list) {
			panwrap_log("mali_external_resource resources_%d_%d[] = {\n", job_no, i);
			panwrap_indent++;

			for (int j = 0; j < a->nr_ext_res; j++) {
				/* Substitute in our framebuffer (TODO: what about other kinds of extres?) */
				panwrap_log("framebuffer_va | MALI_EXT_RES_ACCESS_EXCLUSIVE,\n");
			}

			panwrap_indent--;
			panwrap_log("};\n\n");

		}
	}

	panwrap_log("struct mali_jd_atom_v2 atoms_%d[] = {\n", job_no);
	panwrap_indent++;

	for (int i = 0; i < args->nr_atoms; i++) {
		const struct mali_jd_atom_v2 *a = &atoms[i];

		panwrap_log("{\n");
		panwrap_indent++;

		struct panwrap_mapped_memory *mapped = panwrap_find_mapped_mem_containing((void *) (uintptr_t) a->jc);
		char *jc_name = pointer_as_memory_reference(a->jc);
		panwrap_prop("jc = %s", jc_name);
		free(jc_name);

		/* Don't passthrough udata; it's nondeterministic and for userspace use only */

		panwrap_prop("nr_ext_res = %d", a->nr_ext_res);

		if (a->ext_res_list)
			panwrap_prop("ext_res_list = resources_%d_%d", job_no, i);

		if (a->compat_core_req)
			panwrap_prop("compat_core_req = 0x%x", a->compat_core_req);

		panwrap_log(".pre_dep = {\n");
		panwrap_indent++;
		for (int j = 0; j < ARRAY_SIZE(a->pre_dep); j++) {
			if (a->pre_dep[i].dependency_type || a->pre_dep[i].atom_id)
				panwrap_log("{ .atom_id = %d, .dependency_type = %d },\n",
					    a->pre_dep[i].atom_id, a->pre_dep[i].dependency_type);
		}
		panwrap_indent--;
		panwrap_log("},\n");

		/* TODO: Compute atom numbers dynamically and correctly */
		panwrap_prop("atom_number = %d + %d*%s", a->atom_number, 3, "i");

		panwrap_prop("prio = %d", a->prio);
		panwrap_prop("device_nr = %d", a->device_nr);

		/* XXX This probably breaks replay on new kernels XXX */
		if (!a->compat_core_req) {
			panwrap_log(".compat_core_req = ");
			ioctl_log_decoded_jd_core_req(a->core_req);
			panwrap_log_cont("\n");
		}

		panwrap_indent--;
		panwrap_log("},\n");

	}

	panwrap_indent--;
	panwrap_log("};\n\n");
}

static void ioctl_pretty_print_job_submit(const struct mali_ioctl_job_submit *args, const struct mali_jd_atom_v2 *atoms)
{
	panwrap_msg("Atoms:\n");
	panwrap_indent++;
	for (int i = 0; i < args->nr_atoms; i++) {
		const struct mali_jd_atom_v2 *a = &atoms[i];

		panwrap_prop("jc = " MALI_PTR_FMT, a->jc);
		panwrap_indent++;

		panwrap_msg("Decoding job chain:\n");
		panwrap_indent++;
		panwrap_replay_jc(a->jc);
		panwrap_indent--;

		panwrap_prop("udata = [0x%" PRIx64 ", 0x%" PRIx64 "]",
			    a->udata.blob[0], a->udata.blob[1]);
		panwrap_prop("nr_ext_res = %d", a->nr_ext_res);

		if (a->ext_res_list) {
			panwrap_msg("External resources:\n");

			panwrap_indent++;
			for (int j = 0; j < a->nr_ext_res; j++)
			{
				panwrap_log(" ");
				panwrap_log_decoded_flags(
					external_resources_access_flag_info,
					a->ext_res_list[j]);
				panwrap_log_cont("\n");
			}
			panwrap_indent--;
		} else {
			panwrap_prop("<no external resources>");
		}

		panwrap_prop("compat_core_req = 0x%x", a->compat_core_req);

		panwrap_msg("Pre-dependencies:\n");
		panwrap_indent++;
		for (int j = 0; j < ARRAY_SIZE(a->pre_dep); j++) {
			panwrap_log("atom_id = %d flags == ",
				    a->pre_dep[i].atom_id);
			panwrap_log_decoded_flags(
			    mali_jd_dep_type_flag_info,
			    a->pre_dep[i].dependency_type);
			panwrap_log_cont("\n");
		}
		panwrap_indent--;

		panwrap_prop("atom_number = %d", a->atom_number);
		panwrap_prop("prio = %d (%s)",
			    a->prio, ioctl_decode_jd_prio(a->prio));
		panwrap_prop("device_nr = %d", a->device_nr);

		panwrap_msg("Job type = %s\n",
			    ioctl_get_job_type_from_jd_core_req(a->core_req));
		panwrap_log("core_req = ");
		ioctl_log_decoded_jd_core_req(a->core_req);
		panwrap_log_cont("\n");

		panwrap_indent--;
	}
	panwrap_indent--;
}

static inline void
ioctl_decode_pre_job_submit(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_job_submit *args = ptr;
	const struct mali_jd_atom_v2 *atoms = args->addr;

	dump_debugfs(request);

	if (do_replay)
		panwrap_prop("addr = atoms_%d", job_count - 1); /* XXX */
	else
		panwrap_prop("addr = %p", args->addr);

	panwrap_prop("nr_atoms = %d", args->nr_atoms);
	panwrap_prop("stride = %d", args->stride);

	/* The stride should be equivalent to the length of the structure,
	 * if it isn't then it's possible we're somehow tracing one of the
	 * legacy job formats
	 */
	if (args->stride != sizeof(*atoms)) {
		panwrap_msg("SIZE MISMATCH (stride should be %zd, was %d)\n",
			    sizeof(*atoms), args->stride);
		panwrap_msg("Cannot dump atoms :(, maybe it's a legacy job format?\n");
		return;
	}

	if (!do_replay)
		ioctl_pretty_print_job_submit(args, atoms);
}

static inline void
ioctl_decode_pre(unsigned long int request, void *ptr)
{
	switch (IOCTL_CASE(request)) {
	case IOCTL_CASE(MALI_IOCTL_GET_VERSION):
		ioctl_decode_pre_get_version(request, ptr);
		break;
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
	case IOCTL_CASE(MALI_IOCTL_SYNC):
		ioctl_decode_pre_sync(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_SET_FLAGS):
		ioctl_decode_pre_set_flags(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_STREAM_CREATE):
		ioctl_decode_pre_stream_create(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_JOB_SUBMIT):
		ioctl_decode_pre_job_submit(request, ptr);
		break;
	default:
		break;
	}
}

static inline void
ioctl_decode_post_get_version(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_get_version *args = ptr;

	panwrap_prop("major = %3d", args->major);
	panwrap_prop("minor = %3d", args->minor);
}

static inline void
ioctl_decode_post_mem_alloc(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alloc *args = ptr;

	panwrap_log("flags = ");
	panwrap_log_decoded_flags(
	    mem_flag_info, args->flags & ~MALI_IOCTL_MEM_FLAGS_IN_MASK);
	panwrap_log_cont("\n");

	panwrap_prop("gpu_va = " MALI_PTR_FMT, args->gpu_va);
	panwrap_prop("va_alignment = %d", args->va_alignment);
}

static inline void
ioctl_decode_post_mem_import(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_import *args = ptr;

	panwrap_prop("gpu_va = 0x%" PRIx64, args->gpu_va);
	panwrap_prop("va_pages = %" PRId64, args->va_pages);
	panwrap_log("flags = ");
	panwrap_log_decoded_flags(mem_flag_info, args->flags);
	panwrap_log_cont("\n");
}

static inline void
ioctl_decode_post_mem_commit(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_commit *args = ptr;

	panwrap_prop("result_subcode = %d", args->result_subcode);
}

static inline void
ioctl_decode_post_mem_query(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_query *args = ptr;

	panwrap_prop("value = 0x%" PRIx64, args->value);
}

static inline void
ioctl_decode_post_mem_alias(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_mem_alias *args = ptr;

	panwrap_prop("gpu_va = " MALI_PTR_FMT, args->gpu_va);
	panwrap_prop("va_pages = %" PRId64, args->va_pages);
}

static inline void
ioctl_decode_post_sync(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_sync *args = ptr;

	if (args->type != MALI_SYNC_TO_CPU)
		return;

	dump_debugfs(request);
	panwrap_prop("Dumping memory from device:");
	panwrap_indent++;
	panwrap_log_hexdump_trimmed(args->user_addr, args->size);
	panwrap_indent--;
}

#define PRINT_IF_NO(text, value) if (!value) panwrap_log("%s present? No\n", text);

static inline void
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

	panwrap_log("core:\n");
	panwrap_indent++;
	panwrap_log("Product ID: %d\n", args->core.product_id);
	panwrap_log("Version status: %d\n", args->core.version_status);
	panwrap_log("Minor revision: %d\n", args->core.minor_revision);
	panwrap_log("Major revision: %d\n", args->core.major_revision);
	panwrap_log("Current GPU clock rate: %dMHz\n", args->core.gpu_speed_mhz);
	panwrap_log("GPU clock range: %dKHz-%dKHz\n",
		    args->core.gpu_freq_khz_min, args->core.gpu_freq_khz_max);
	panwrap_log("Shader program counter size: %.lf MB\n",
		    pow(2, args->core.log2_program_counter_size) / 1024 / 1024);

	panwrap_log("Texture features:\n");
	panwrap_indent++;
	for (int i = 0; i < ARRAY_SIZE(args->core.texture_features); i++)
		panwrap_log("%010x\n", args->core.texture_features[i]);
	panwrap_indent--;

	panwrap_log("Available memory: %" PRId64 " bytes\n",
		    args->core.gpu_available_memory_size);
	panwrap_indent--;

	panwrap_log("L2 cache:\n");
	panwrap_indent++;
	panwrap_log("Line size: %.lf (bytes, words?)\n",
		    pow(2, args->l2.log2_line_size));
	panwrap_log("Cache size: %.lf KB\n",
		    pow(2, args->l2.log2_cache_size) / 1024);
	panwrap_log("Associativity: %d\n", (args->raw.l2_features & 0xFF00) >> 8);
	panwrap_log("External bus width: %d\n", (args->raw.l2_features & 0xFF000000) >> 24);
	panwrap_log("L2 slice count: %d\n", args->l2.num_l2_slices);
	panwrap_indent--;

	panwrap_log("Tiler:\n");
	panwrap_indent++;
	panwrap_log("Binary size: %d bytes\n",
		    args->tiler.bin_size_bytes);
	panwrap_log("Max active levels: %d\n",
		    args->tiler.max_active_levels);
	panwrap_indent--;

	panwrap_log("Threads:\n");
	panwrap_indent++;
	panwrap_log("Max threads: %d\n", args->thread.max_threads);
	panwrap_log("Max threads per workgroup: %d\n",
		    args->thread.max_workgroup_size);
	panwrap_log("Max threads allowed for synchronizing on simple barrier: %d\n",
		    args->thread.max_barrier_size);
	panwrap_log("Max registers available per-core: %d\n",
		    args->thread.max_registers);
	panwrap_log("Max tasks that can be sent to a core before blocking: %d\n",
		    args->thread.max_task_queue);
	panwrap_log("Max allowed thread group split value: %d\n",
		    args->thread.max_thread_group_split);
	panwrap_log("Implementation type: %d (%s)\n",
		    args->thread.impl_tech, implementation);
	panwrap_indent--;

	panwrap_log("Raw props:\n");

	panwrap_indent++;

	/* Generally, these should be present, so be optimistic */

	PRINT_IF_NO("Shader", args->raw.shader_present);
	PRINT_IF_NO("Tiler", args->raw.tiler_present);
	PRINT_IF_NO("L2", args->raw.l2_present);
	PRINT_IF_NO("Address spaces", args->raw.as_present);
	PRINT_IF_NO("Job slots", args->raw.js_present);
	PRINT_IF_NO("Stack", args->raw.stack_present);

	panwrap_log("Suspend size: %d\n", args->raw.suspend_size);

	/* As far as we know, these features are fully decoded, with the other
	 * bits being zeroes. Just in case, dump them if something non-zero
	 * comes up in the alleged "reserved" fields */

	if (args->raw.l2_features & (~0xFFFFFFFF))
		panwrap_log("L2 features (undecoded) : 0x%010x\n", args->raw.l2_features & (~0xFFFFFFFF));

	if (args->raw.thread_features & (~0xFFFFFFFF))
		panwrap_log("Thread features (undecoded): 0x%x\n", args->raw.thread_features);

	if (args->raw.mmu_features & ~(0xFFFF))
		panwrap_log("MMU features (undecoded): %d\n", args->raw.mmu_features & ~(0xFFFF));

	if (args->raw.mem_features & (~1) & (~(((1 << 5) - 1) << 8)))
		panwrap_log("Memory features: 0x%010x\n", args->raw.mem_features & (~1) & (~(((1 << 5) - 1) << 8)));

	panwrap_log("MMU features:\n");
	panwrap_indent++;
	panwrap_log("Virtual address bits: %d\n", args->raw.mmu_features & 0x00FF);
	panwrap_log("Physical address bits: %d\n", (args->raw.mmu_features & 0xFF00) >> 8);
	panwrap_indent--;

	panwrap_log("Job slot features:\n");

	panwrap_indent++;
	for (int i = 0; i < ARRAY_SIZE(args->raw.js_features); i++)
		if (args->raw.js_features[i]) {
			panwrap_log("Slot %d: ", i);
			panwrap_log_decoded_flags(js_feature_info, args->raw.js_features[i]);
			panwrap_log_cont("\n");
		}
	panwrap_indent--;

	/* Bit field -- the other values are extracted above */
	int leftover_tiler = args->raw.tiler_features & ~((1 << 7) - 1) & ~(((1 << 5) - 1) << 8);

	if (leftover_tiler)
		panwrap_log("Tiler features (undecoded): %010x\n", leftover_tiler);

	panwrap_log("GPU ID: 0x%x\n", args->raw.gpu_id);
	panwrap_log("Coherency mode: 0x%x (%s)\n",
		    args->raw.coherency_mode,
		    ioctl_decode_coherency_mode(args->raw.coherency_mode));

	panwrap_indent--;

	panwrap_log("Coherency info:\n");
	panwrap_indent++;
	panwrap_log("Number of groups: %d\n", args->coherency_info.num_groups);
	panwrap_log("Number of core groups (coherent or not): %d\n",
		    args->coherency_info.num_core_groups);
	panwrap_log("Features: 0x%x\n", args->coherency_info.coherency);
	panwrap_log("Groups:\n");
	panwrap_indent++;
	for (int i = 0; i < args->coherency_info.num_groups; i++) {
		panwrap_log("- Core mask: %010" PRIx64 "\n",
			    args->coherency_info.group[i].core_mask);
		panwrap_log("  Number of cores: %d\n",
			    args->coherency_info.group[i].num_cores);
	}
	panwrap_indent--;
	panwrap_indent--;
}

static inline void
ioctl_decode_post_stream_create(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_stream_create *args = ptr;

	panwrap_prop("fd = %d", args->fd);
}

static inline void
ioctl_decode_post_get_context_id(unsigned long int request, void *ptr)
{
	const struct mali_ioctl_get_context_id *args = ptr;

	panwrap_prop("id = 0x%" PRIx64, args->id);

	if (context_id != 0) {
		panwrap_log("Oh no, there's more then one context! I can't handle this yet\n");
		abort();
	}

	context_id = args->id;

	/* this seems to be how the kdriver determines debugfs paths... */
	snprintf(debugfs_ctx_path, sizeof(debugfs_ctx_path),
		 "/sys/kernel/debug/mali0/ctx/%d_%" PRId64,
		 getpid(), context_id & ~0x7f00000000);
	debugfs_fd = open(debugfs_ctx_path, O_RDONLY | O_DIRECTORY);
	if (debugfs_fd < 0) {
		fprintf(stderr, "Failed to open debugfs dir %s: %s\n",
			debugfs_ctx_path, strerror(errno));
	}
}

static inline void
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
	case IOCTL_CASE(MALI_IOCTL_SYNC):
		ioctl_decode_post_sync(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_GPU_PROPS_REG_DUMP):
		ioctl_decode_post_gpu_props_reg_dump(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_STREAM_CREATE):
		ioctl_decode_post_stream_create(request, ptr);
		break;
	case IOCTL_CASE(MALI_IOCTL_GET_CONTEXT_ID):
		ioctl_decode_post_get_context_id(request, ptr);
		break;
	default:
		break;
	}
}

/**
 * Overriden libc functions start here
 */
static inline int
panwrap_open_wrap(open_func *func, const char *path, int flags, va_list args)
{
	mode_t mode = 0;
	int ret;

	if (flags & O_CREAT) {
		mode = (mode_t) va_arg(args, int);
		ret = func(path, flags, mode);
	} else {
		ret = func(path, flags);
	}

	LOCK();
	msleep(log_delay);
	if (ret != -1) {
		if (strcmp(path, "/dev/mali0") == 0) {
			if (!do_replay) panwrap_msg("/dev/mali0 fd == %d\n", ret);
			mali_fd = ret;
		} else if (strstr(path, "/dev/")) {
			if (!do_replay) panwrap_msg("Unknown device %s opened at fd %d\n",
				    path, ret);
		}
	}
	UNLOCK();

	return ret;
}

#ifdef IS_OPEN64_SEPERATE_SYMBOL
int
open(const char *path, int flags, ...)
{
	PROLOG(open);
	va_list args;
	va_start(args, flags);
	int o = panwrap_open_wrap(orig_open, path, flags, args);
	va_end(args);
	return o;
}
#endif

int
open64(const char *path, int flags, ...)
{
	PROLOG(open64);
	va_list args;
	va_start(args, flags);
	int o = panwrap_open_wrap(orig_open64, path, flags, args);
	va_end(args);
	return o;
}

int
close(int fd)
{
	PROLOG(close);

        /* Intentionally racy: prevents us from trying to hold the global mutex
         * in calls from system libraries */
        if (fd <= 0 || !mali_fd || fd != mali_fd)
                return orig_close(fd);

	LOCK();
	msleep(log_delay);
	if (!fd || fd != mali_fd) {
		panwrap_log("/dev/mali0 closed\n");
		mali_fd = 0;
	}
	UNLOCK();

	return orig_close(fd);
}

static char *panwrap_lower_string(const char *str)
{
	char *out = (char *) malloc(strlen(str) + 1);

	for (int i = 0; i < strlen(str); ++i)
		out[i] = tolower(str[i]);

	out[strlen(str)] = 0;

	return out;
}

/* Global count of ioctls, for replay purposes */

static int ioctl_count = 0;

/* XXX: Android has a messed up ioctl signature */
int ioctl(int fd, int request, ...)
{
	const char *name;
	char *lname;
	int number;
	union mali_ioctl_header *header;
	PROLOG(ioctl);
	int ioc_size = _IOC_SIZE(request);
	int ret;
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
	msleep(log_delay);
	name = ioctl_get_info(request)->name ?: "???";
	header = ptr;

	if (!ptr) { /* All valid mali ioctl's should have a specified arg */
		panwrap_msg("<%-20s> (%02d) (%08x), has no arguments? Cannot decode :(\n",
			    name, _IOC_NR(request), request);

		ret = orig_ioctl(fd, request, ptr);

		panwrap_indent++;
		panwrap_msg("= %02d\n", ret);
		panwrap_indent--;
		goto out;
	}

	bool ignore = false;

	/* Race condition... */
	if (do_replay && !panwrap_indent)
		ignore = true;

	/* Queries are not interesting for replay */
	if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_MEM_QUERY))
		ignore = true;

	/* Neither is debugfs nonsense */
	if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_DEBUGFS_MEM_PROFILE_ADD))
		ignore = true;
	
	/* Syncs -are-, but we disable caching */
	if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_SYNC))
		ignore = true;
	
	if (do_replay) {
		lname = panwrap_lower_string(name);
		number = ioctl_count++;

		if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_JOB_SUBMIT)) {
			panwrap_log("for (int i = 0; i < 30; ++i) {\n");
			panwrap_indent++;
			emit_atoms(ptr);
			replay_memory();
		}

		/* TODO: Is there a better way to handle framebuffers in replay? */
		if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_MEM_IMPORT)) {
			panwrap_log("uint32_t *framebuffer;\n");
			panwrap_log("posix_memalign((void **) &framebuffer, CACHE_LINE_SIZE, 4096*4096*4);\n");
			panwrap_log("slowfb_init(framebuffer + %d, 400, 320);\n", 144); /* XXX: Magic experimentally determined offset */
			panwrap_log("struct mali_mem_import_user_buffer framebuffer_handle = { .ptr = (uint64_t) (uintptr_t) framebuffer, .length = 4096*4096*4 };\n");
		}

		/* For certain special cases of ioctls, we can use our own functions */
		if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_MEM_ALLOC)) {
			const struct mali_ioctl_mem_alloc *args = ptr;

			panwrap_log("u64 alloc_gpu_va_%d;\n", number);

			if (args->va_pages == args->commit_pages && !args->extent)
				panwrap_log("pandev_standard_allocate(fd, %" PRId64 ", ", args->va_pages);
			else
				panwrap_log("pandev_general_allocate(fd, %" PRId64 ", %" PRId64", %" PRId64 ", ", args->va_pages, args->commit_pages, args->extent);

			panwrap_log_decoded_flags(mem_flag_info, args->flags & ~MALI_MEM_CACHED_CPU);
			panwrap_log_cont(", &alloc_gpu_va_%d);\n", number);

			ignore = true;
		}

		if (!ignore)
			panwrap_log("struct mali_ioctl_%s %s_%d = {\n", lname, lname, number);
	} else {
		panwrap_msg("<%-20s> (%02d) (%08x) (%04d)\n",
			    name, _IOC_NR(request), request, _IOC_SIZE(request));
	}

	panwrap_indent++;
	if (!ignore)
		ioctl_decode_pre(request, ptr);

	ret = orig_ioctl(fd, request, ptr);

	/* If we're building up a replay, we don't care about the result; we
	 * have to assume it's correct! It can be seperately viewed for
	 * debugging, of course, in a seperate wrap. */

	if (!do_replay) {
		panwrap_msg("= %02d, %02d\n", ret, header->rc);
		ioctl_decode_post(request, ptr);
	}

	/* Track memory allocation if needed  */
	if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_MEM_ALLOC)) {
		const struct mali_ioctl_mem_alloc *args = ptr;

		panwrap_track_allocation(args->gpu_va, args->flags, number);
	}

	panwrap_indent--;

	if (do_replay) {
		if (!ignore) {
			panwrap_log("};\n\n");
			panwrap_log("rc = pandev_ioctl(fd, MALI_IOCTL_%s, &%s_%d);\n", name, lname, number);
			panwrap_log("if (rc) printf(\"Error %%d in %s_%d\\n\", rc);\n\n", name, number);
		}

		/* Setup framebuffer (part II) */
		if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_MEM_IMPORT)) {
			panwrap_log("uint64_t framebuffer_va = %s_%d.gpu_va;\n", lname, number);
		}

		/* Dump the framebuffer :D */
		if (IOCTL_CASE(request) == IOCTL_CASE(MALI_IOCTL_JOB_SUBMIT)) {
			panwrap_log("slowfb_update(framebuffer, 400, 320);\n");
			
			/* We have to acknowledge events from the kernel for
			 * atoms to be released correctly, or else we'll hang
			 * after a few seconds of drawing (255 atom max) */

			panwrap_log("uint8_t kernel_events[128];\n");
			panwrap_log("read(fd, kernel_events, 128);\n");

			panwrap_indent--;
			panwrap_log("}\n");
		}

		free(lname);
	}


	if (step_mode) {
		panwrap_log("Paused, hit enter to continue\n");
		panwrap_log_flush();
		getchar();
	}
out:
	UNLOCK();
	return ret;
}

static void inline *panwrap_mmap_wrap(mmap_func *func,
				      void *addr, size_t length, int prot,
				      int flags, int fd, loff_t offset)
{
	void *ret;

	if (!mali_fd || fd != mali_fd)
		return func(addr, length, prot, flags, fd, offset);

	LOCK();
	msleep(log_delay);
	ret = func(addr, length, prot, flags, fd, offset);

	switch (offset) { /* offset == gpu_va */
	case MALI_MEM_MAP_TRACKING_HANDLE:
		if (do_replay) {
			panwrap_log("pandev_map_mtp(fd);\n");
			panwrap_log("\n");
		} else {
			panwrap_msg("Memory map tracking handle ("MALI_PTR_FMT") mapped to %p\n",
				    (mali_ptr) offset, ret);
		}

		break;
	default:
		panwrap_track_mmap(offset, ret, length, prot, flags);
		break;
	}

	UNLOCK();
	return ret;
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd,
	     loff_t offset)
{
	PROLOG(mmap64);

	return panwrap_mmap_wrap(orig_mmap64, addr, length, prot, flags, fd,
				 offset);
}

#ifdef IS_MMAP64_SEPERATE_SYMBOL
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
#ifdef __LP64__
	PROLOG(mmap);

	return panwrap_mmap_wrap(orig_mmap, addr, length, prot, flags, fd,
				 offset);
#else
	return mmap64(addr, length, prot, flags, fd, (loff_t) offset);
#endif
}
#endif

int munmap(void *addr, size_t length)
{
	int ret;
	struct panwrap_mapped_memory *mem;
	PROLOG(munmap);

	if (!mali_fd)
		return orig_munmap(addr, length);

	LOCK();
	ret = orig_munmap(addr, length);
	mem = panwrap_find_mapped_mem(addr);
	if (!mem)
		goto out;

	msleep(log_delay);

	/* Was it memory mapped from the GPU? We only care to log for
	 * non-replays, where the addresses are meaningful. */

	if (!do_replay) {
		if (mem->gpu_va)
			panwrap_msg("Unmapped GPU memory " MALI_PTR_FMT "@%p\n",
				    mem->gpu_va, mem->addr);
		else
			panwrap_msg("Unmapped unknown memory %p\n",
				    mem->addr);
	}

	list_del(&mem->node);
	free(mem);
out:
	UNLOCK();
	return ret;
}
