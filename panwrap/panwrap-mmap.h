/*
 * © Copyright 2017-2018 The Panfrost Community
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
	int allocation_number;

	struct list node;
};

struct panwrap_mapped_memory {
	size_t length;

	void *addr;
	mali_ptr gpu_va;
	int prot;
        int flags;

	int allocation_number;
	char name[32];

	bool* touched;

	struct list node;
};

#define TOUCH_OLEN(mem, addr, sz, offset, ename, number) \
	memset(mem->touched + ((addr - mem->gpu_va) / sizeof(uint32_t)), 1, (sz - offset) / sizeof(uint32_t)); \
	panwrap_log("\n"); \
	panwrap_log("mali_ptr %s_%d_p = pandev_upload(%d, alloc_gpu_va_%d, %s, &%s_%d, sizeof(%s_%d) - %d);\n\n", ename, number, (int) ((addr - mem->gpu_va)), mem->allocation_number, mem->name, ename, number, ename, number, offset);

#define TOUCH_LEN(mem, addr, sz, ename, number) \
	TOUCH_OLEN(mem, addr, sz, 0, ename, number)

#define TOUCH(mem, addr, obj, ename, number) \
	TOUCH_LEN(mem, addr, sizeof(typeof(obj)), ename, number)

void replay_memory();
char *pointer_as_memory_reference(mali_ptr ptr);

void panwrap_track_allocation(mali_ptr gpu_va, int flags, int number);
void panwrap_track_mmap(mali_ptr gpu_va, void *addr, size_t length,
                        int prot, int flags);
void panwrap_track_munmap(void *addr);

struct panwrap_mapped_memory *panwrap_find_mapped_mem(void *addr);
struct panwrap_mapped_memory *panwrap_find_mapped_mem_containing(void *addr);
struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem(mali_ptr addr);
struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem_containing(mali_ptr addr);

void panwrap_assert_gpu_same(const struct panwrap_mapped_memory *mem,
			     mali_ptr gpu_va, size_t size,
			     const unsigned char *data);
void panwrap_assert_gpu_mem_zero(const struct panwrap_mapped_memory *mem,
				 mali_ptr gpu_va, size_t size);

void __attribute__((noreturn))
__panwrap_fetch_mem_err(const struct panwrap_mapped_memory *mem,
			mali_ptr gpu_va, size_t size,
			int line, const char *filename);

static inline void *
__panwrap_fetch_gpu_mem(const struct panwrap_mapped_memory *mem,
			mali_ptr gpu_va, size_t size,
			int line, const char *filename)
{
	if (!mem)
		mem = panwrap_find_mapped_gpu_mem_containing(gpu_va);

	if (!mem ||
	    size + (gpu_va - mem->gpu_va) > mem->length ||
	    !(mem->prot & MALI_MEM_PROT_CPU_RD))
		__panwrap_fetch_mem_err(mem, gpu_va, size, line, filename);

	return mem->addr + gpu_va - mem->gpu_va;
}

#define panwrap_fetch_gpu_mem(mem, gpu_va, size) \
	__panwrap_fetch_gpu_mem(mem, gpu_va, size, __LINE__, __FILE__)

/* Returns a validated pointer to mapped GPU memory with the given pointer type,
 * size automatically determined from the pointer type
 */
#define PANWRAP_PTR(mem, gpu_va, type) \
	((type*)(__panwrap_fetch_gpu_mem(mem, gpu_va, sizeof(type), \
					 __LINE__, __FILE__)))

/* Usage: <variable type> PANWRAP_PTR_VAR(name, mem, gpu_va) */
#define PANWRAP_PTR_VAR(name, mem, gpu_va) \
	name = __panwrap_fetch_gpu_mem(mem, gpu_va, sizeof(*name), \
				       __LINE__, __FILE__)

#endif /* __MMAP_TRACE_H__ */
