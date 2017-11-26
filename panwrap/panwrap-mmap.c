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
#include <sys/mman.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <list.h>

#include <mali-ioctl.h>
#include <panloader-util.h>
#include "panwrap.h"
#include "panwrap-mmap.h"

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
	FLAG_INFO(MAP_UNINITIALIZED),
	{}
};

static const struct panwrap_flag_info mmap_prot_flag_info[] = {
	FLAG_INFO(PROT_EXEC),
	FLAG_INFO(PROT_READ),
	FLAG_INFO(PROT_WRITE),
	{}
};
#undef FLAG_INFO

void panwrap_track_allocation(mali_gpu_ptr addr, int flags)
{
	struct panwrap_allocated_memory *mem = malloc(sizeof(*mem));

	panwrap_log("GPU memory allocated at GPU VA " MALI_GPU_PTR_FORMAT "\n",
		    addr);
	list_init(&mem->node);
	mem->gpu_va = addr;
	mem->flags = flags;

	list_add(&mem->node, &allocations);
}

void panwrap_track_mmap(mali_gpu_ptr gpu_va, void *addr, size_t length,
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
		panwrap_log("Error: Untracked gpu memory " MALI_GPU_PTR_FORMAT " mapped to %p\n",
			    gpu_va, addr);
		panwrap_log("\tprot = ");
		panwrap_log_decoded_flags(mmap_prot_flag_info, prot);
		panwrap_log_cont("\n");
		panwrap_log("\tflags = ");
		panwrap_log_decoded_flags(mmap_flags_flag_info, flags);
		panwrap_log_cont("\n");

		return;
	}

	mapped_mem = malloc(sizeof(*mapped_mem));
	list_init(&mapped_mem->node);
	mapped_mem->gpu_va =
		mem->flags & MALI_MEM_SAME_VA ? (mali_gpu_ptr)addr : gpu_va;
	mapped_mem->length = length;
	mapped_mem->addr = addr;
	mapped_mem->prot = prot;
	mapped_mem->flags = mem->flags;

	list_add(&mapped_mem->node, &mmaps);

	list_del(&mem->node);
	free(mem);

	panwrap_log("GPU VA " MALI_GPU_PTR_FORMAT " mapped to %p - %p (length == %zu)\n",
		    mapped_mem->gpu_va, addr, addr + length, length);
}

void panwrap_track_munmap(void *addr)
{
	struct panwrap_mapped_memory *mapped_mem =
		panwrap_find_mapped_mem(addr);

	if (!mapped_mem) {
		panwrap_log("Unknown mmap %p unmapped\n", addr);
		return;
	}

	list_del(&mapped_mem->node);
	panwrap_log("Unmapped GPU memory at %p\n",
		    addr);
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
		if (addr >= pos->addr && addr <= pos->addr + pos->length)
			return pos;
	}

	return NULL;
}

struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem(mali_gpu_ptr addr)
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		if (pos->gpu_va == addr)
			return pos;
	}

	return NULL;
}

struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem_containing(mali_gpu_ptr addr)
{
	struct panwrap_mapped_memory *pos;

	list_for_each_entry(pos, &mmaps, node) {
		if (addr >= pos->gpu_va && addr <= pos->gpu_va + pos->length)
			return pos;
	}

	return NULL;
}

void __attribute__((noreturn))
__panwrap_deref_mem_err(const struct panwrap_mapped_memory *mem,
			mali_gpu_ptr gpu_va, size_t size,
			int line, const char *filename)
{
	panwrap_indent = 0;
	panwrap_log("\n");
	panwrap_log("OUT OF BOUNDS GPU_VA ACCESS:\n");
	panwrap_log("Occurred at line %d of %s\n",
		    line, filename);
	panwrap_log("Mapping information:\n");
	panwrap_indent++;
	panwrap_log("CPU VA: %p - %p\n",
		    mem->addr, mem->addr + mem->length);
	panwrap_log("GPU VA: " MALI_GPU_PTR_FORMAT " - " MALI_GPU_PTR_FORMAT "\n",
		    mem->gpu_va, (mali_gpu_ptr)(mem->gpu_va + mem->length));
	panwrap_log("Length: %zu bytes\n", mem->length);
	panwrap_indent--;
	panwrap_log("Access length was %zu (%zu out of bounds)\n",
		    size, ((gpu_va - mem->gpu_va) + size) - mem->length);
	panwrap_log_flush();
	abort();
}
