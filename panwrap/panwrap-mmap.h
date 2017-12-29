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

#ifndef __MMAP_TRACE_H__
#define __MMAP_TRACE_H__

#include <mali-ioctl.h>
#include <list.h>
#include <stdlib.h>
#include <stddef.h>
#include "panwrap.h"

struct panwrap_allocated_memory {
	mali_ptr gpu_va;
	int flags;

	struct list node;
};

struct panwrap_mapped_memory {
	size_t length;

	void *addr;
	mali_ptr gpu_va;
	int prot;
        int flags;

	struct list node;
};

void panwrap_track_allocation(mali_ptr gpu_va, int flags);
void panwrap_track_mmap(mali_ptr gpu_va, void *addr, size_t length,
                        int prot, int flags);
void panwrap_track_munmap(void *addr);

struct panwrap_mapped_memory *panwrap_find_mapped_mem(void *addr);
struct panwrap_mapped_memory *panwrap_find_mapped_mem_containing(void *addr);
struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem(mali_ptr addr);
struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem_containing(mali_ptr addr);

void __attribute__((noreturn))
__panwrap_deref_mem_err(const struct panwrap_mapped_memory *mem,
			mali_ptr gpu_va, size_t size,
			int line, const char *filename);

static inline void *
__panwrap_deref_gpu_mem(const struct panwrap_mapped_memory *mem,
			mali_ptr gpu_va, size_t size,
			int line, const char *filename)
{
	if (!mem)
		mem = panwrap_find_mapped_gpu_mem_containing(gpu_va);

	if (!mem ||
	    size + (gpu_va - mem->gpu_va) > mem->length ||
	    !(mem->prot & MALI_MEM_PROT_CPU_RD))
		__panwrap_deref_mem_err(mem, gpu_va, size, line, filename);

	return (void*)gpu_va + (ptrdiff_t)((void*)mem->gpu_va - mem->addr);
}

#define panwrap_deref_gpu_mem(mem, gpu_va, size) \
	__panwrap_deref_gpu_mem(mem, gpu_va, size, __LINE__, __FILE__)

#define PANWRAP_PTR(mem, gpu_va, type) \
	((type*)(__panwrap_deref_gpu_mem(mem, gpu_va, sizeof(type), \
					 __LINE__, __FILE__)))

#endif /* __MMAP_TRACE_H__ */
