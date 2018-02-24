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
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdarg.h>
#include <list.h>

#include <mali-ioctl.h>
#include <panloader-util.h>
#include "panwrap.h"
#include "panwrap-mmap.h"
#ifdef HAVE_LINUX_MMAN_H
#include <linux/mman.h>
#endif

static LIST_HEAD(allocations);
static LIST_HEAD(mmaps);

#define FLAG_INFO(flag) { flag, #flag }
static const struct panwrap_flag_info mmap_flags_flag_info[] = {
	FLAG_INFO(MAP_SHARED),
	FLAG_INFO(MAP_PRIVATE),
	FLAG_INFO(MAP_ANONYMOUS),
	FLAG_INFO(MAP_DENYWRITE),
	FLAG_INFO(MAP_FIXED),
	FLAG_INFO(MAP_GROWSDOWN),
	FLAG_INFO(MAP_HUGETLB),
	FLAG_INFO(MAP_LOCKED),
	FLAG_INFO(MAP_NONBLOCK),
	FLAG_INFO(MAP_NORESERVE),
	FLAG_INFO(MAP_POPULATE),
	FLAG_INFO(MAP_STACK),
#if MAP_UNINITIALIZED != 0
	FLAG_INFO(MAP_UNINITIALIZED),
#endif
	{}
};

static const struct panwrap_flag_info mmap_prot_flag_info[] = {
	FLAG_INFO(PROT_EXEC),
	FLAG_INFO(PROT_READ),
	FLAG_INFO(PROT_WRITE),
	{}
};
#undef FLAG_INFO

char* pointer_as_memory_reference(mali_ptr ptr)
{
	struct panwrap_mapped_memory *mapped;
	char *out = malloc(128);

	if (ptr == (uintptr_t) ptr && (mapped = panwrap_find_mapped_mem_containing((void*) (uintptr_t) ptr)))
		snprintf(out, 128, "alloc_gpu_va_%d + %d", mapped->allocation_number, (int) (ptr - mapped->gpu_va));
	else 
		snprintf(out, 128, MALI_PTR_FMT, ptr);

	return out;
}

/* On job submission, there will be a -lot- of structures built up in memory.
 * While we could decode them, for triangle #1 it's easier to just dump them
 * all verbatim, as hex arrays, and memcpy them into the allocated memory
 * spaces. The main issue is address fix up, which we also handle here. */

void replay_memory()
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		/* If we don't have write access, no replay :) */
		if (!(pos->flags & MALI_MEM_PROT_CPU_WR)) continue;

		if (pos->flags & MALI_MEM_PROT_GPU_EX) {
			/* Shaders need to be dumped but, given that the disassembler
			 * is out of tree and that compiled shaders are blobs of
			 * unclear licensing, they should not be dumped as replay
			 * memory. Thankfully, there is no fixup needed (or even
			 * allowed), so we can just dump and load a file wholesale */

			char filename[128];
			snprintf(filename, 128, "%s.bin", pos->name);

			FILE *fp = fopen(filename, "wb");
			fwrite(pos->addr, 1, pos->length, fp);
			fclose(fp);

			panwrap_log("FILE *f_%s = fopen(\"%s\", \"rb\");\n", pos->name, filename);
			panwrap_log("fread(%s, 1, %d, f_%s);\n", pos->name, pos->length, pos->name);
			panwrap_log("fclose(f_%s);\n", pos->name);
		} else {
			/* Fill it with dumped memory, skipping zeroes */
			uint32_t *array = (uint32_t *) pos->addr;

			for (uint32_t i = 0; i < pos->length / sizeof(uint32_t); ++i) {
				if (array[i])
					panwrap_log("%s%s[%d] = %s;\n", pos->touched[i] ? "// " : "", pos->name, i, pointer_as_memory_reference(array[i]));
			}
		}

		panwrap_log("\n");
	}
}

void panwrap_track_allocation(mali_ptr addr, int flags, int number)
{
	struct panwrap_allocated_memory *mem = malloc(sizeof(*mem));

	if (!do_replay)
		panwrap_msg("GPU memory allocated at GPU VA " MALI_PTR_FMT "\n",
			    addr);

	list_init(&mem->node);
	mem->gpu_va = addr;
	mem->flags = flags;
	mem->allocation_number = number;

	list_add(&mem->node, &allocations);
}

void panwrap_track_mmap(mali_ptr gpu_va, void *addr, size_t length,
			int prot, int flags)
{
	struct panwrap_mapped_memory *mapped_mem = NULL;
	struct panwrap_allocated_memory *pos, *mem = NULL;

	/* Find the pending unmapped allocation for the memory */
	list_for_each_entry(pos, &allocations, node) {
		if (pos->gpu_va == gpu_va) {
			mem = pos;
			break;
		}
	}
	if (!mem) {
		panwrap_msg("Error: Untracked gpu memory " MALI_PTR_FMT " mapped to %p\n",
			    gpu_va, addr);
		panwrap_msg("\tprot = ");
		panwrap_log_decoded_flags(mmap_prot_flag_info, prot);
		panwrap_log_cont("\n");
		panwrap_msg("\tflags = ");
		panwrap_log_decoded_flags(mmap_flags_flag_info, flags);
		panwrap_log_cont("\n");

		return;
	}

	mapped_mem = malloc(sizeof(*mapped_mem));
	list_init(&mapped_mem->node);
	mapped_mem->gpu_va =
		mem->flags & MALI_MEM_SAME_VA ? (mali_ptr) (uintptr_t) addr : gpu_va;
	mapped_mem->length = length;
	mapped_mem->addr = addr;
	mapped_mem->prot = prot;
	mapped_mem->flags = mem->flags;
	mapped_mem->allocation_number = mem->allocation_number;

	if (do_replay)
		mapped_mem->touched = calloc(length, sizeof(bool));

	list_add(&mapped_mem->node, &mmaps);

	list_del(&mem->node);
	free(mem);

	if (do_replay) {
		/* Generate somewhat semantic name for the region */
		snprintf(mapped_mem->name, sizeof(mapped_mem->name),
				"%s_%d",
				mem->flags & MALI_MEM_PROT_GPU_EX ? "shader" : "memory",
				mapped_mem->allocation_number);

		/* Map region itself */

		panwrap_log("uint32_t *%s = mmap64(NULL, %d, %d, %d, fd, alloc_gpu_va_%d);\n\n",
			    mapped_mem->name, length, prot, flags, mapped_mem->allocation_number);

		panwrap_log("if (%s == MAP_FAILED) printf(\"Error mapping %s\\n\");\n\n",
				mapped_mem->name, mapped_mem->name);
	} else {
		panwrap_msg("GPU VA " MALI_PTR_FMT " mapped to %p - %p (length == %zu)\n",
			    mapped_mem->gpu_va, addr, addr + length - 1, length);
	}
}

void panwrap_track_munmap(void *addr)
{
	struct panwrap_mapped_memory *mapped_mem =
		panwrap_find_mapped_mem(addr);

	if (!mapped_mem) {
		panwrap_msg("Unknown mmap %p unmapped\n", addr);
		return;
	}

	list_del(&mapped_mem->node);

	if (!do_replay) {
		/* As the address is nondeterministic, don't send this message
		 * for replays. It's not functionally important -- it will
		 * become a comment anyway -- but source code reproducability
		 * is important for debugging and understanding replays. */

		panwrap_msg("Unmapped GPU memory at %p\n", addr);
	}

	free(mapped_mem);
}

struct panwrap_mapped_memory *panwrap_find_mapped_mem(void *addr)
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		if (pos->addr == addr)
			return pos;
	}

	return NULL;
}

struct panwrap_mapped_memory *panwrap_find_mapped_mem_containing(void *addr)
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		if (addr >= pos->addr && addr < pos->addr + pos->length)
			return pos;
	}

	return NULL;
}

struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem(mali_ptr addr)
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		if (pos->gpu_va == addr)
			return pos;
	}

	return NULL;
}

struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem_containing(mali_ptr addr)
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		if (addr >= pos->gpu_va && addr < pos->gpu_va + pos->length)
			return pos;
	}

	return NULL;
}

void
panwrap_assert_gpu_same(const struct panwrap_mapped_memory *mem,
			mali_ptr gpu_va, size_t size,
			const unsigned char *data)
{
	const char *buffer = panwrap_fetch_gpu_mem(mem, gpu_va, size);

	for (size_t i = 0; i < size; i++) {
		if (buffer[i] != data[i]) {
			panwrap_msg("At " MALI_PTR_FMT ", expected:\n",
				    gpu_va);
			panwrap_indent++;
			panwrap_log_hexdump_trimmed(data, size);
			panwrap_indent--;
			panwrap_msg("Instead got:\n");
			panwrap_indent++;
			panwrap_log_hexdump_trimmed(buffer, size);
			panwrap_indent--;

			abort();
		}
	}
}

void
panwrap_assert_gpu_mem_zero(const struct panwrap_mapped_memory *mem,
			    mali_ptr gpu_va, size_t size)
{
	const char *buffer = panwrap_fetch_gpu_mem(mem, gpu_va, size);

	for (size_t i = 0; i < size; i++) {
		if (buffer[i] != '\0') {
			panwrap_msg("At " MALI_PTR_FMT ", expected all 0 but got:\n",
				    gpu_va);
			panwrap_indent++;
			panwrap_log_hexdump_trimmed(buffer, size);
			panwrap_indent--;

			abort();
		}
	}
}

void __attribute__((noreturn))
__panwrap_fetch_mem_err(const struct panwrap_mapped_memory *mem,
			mali_ptr gpu_va, size_t size,
			int line, const char *filename)
{
	panwrap_indent = 0;
	panwrap_msg("\n");

	panwrap_msg("INVALID GPU MEMORY ACCESS @"
		    MALI_PTR_FMT " - " MALI_PTR_FMT ":\n",
		    gpu_va, gpu_va + size);
	panwrap_msg("Occurred at line %d of %s\n", line, filename);

	if (mem) {
		panwrap_msg("Mapping information:\n");
		panwrap_indent++;
		panwrap_msg("CPU VA: %p - %p\n",
			    mem->addr, mem->addr + mem->length - 1);
		panwrap_msg("GPU VA: " MALI_PTR_FMT " - " MALI_PTR_FMT "\n",
			    mem->gpu_va,
			    (mali_ptr)(mem->gpu_va + mem->length - 1));
		panwrap_msg("Length: %zu bytes\n", mem->length);
		panwrap_indent--;

		if (!(mem->prot & MALI_MEM_PROT_CPU_RD))
			panwrap_msg("Memory is only accessible from GPU\n");
		else
			panwrap_msg("Access length was out of bounds\n");
	} else {
		panwrap_msg("GPU memory is not contained within known GPU VA mappings\n");

	}

	panwrap_log_flush();
	abort();
}
