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

struct panwrap_allocated_memory {
	mali_gpu_ptr gpu_va;
	struct list node;
};

struct panwrap_mapped_memory {
	size_t length;

	void *addr;
	mali_gpu_ptr gpu_va;
	int prot;
        int flags;

	struct list node;
};

void panwrap_track_allocation(mali_gpu_ptr gpu_va);
void panwrap_track_mmap(mali_gpu_ptr gpu_va, void *addr, size_t length,
                        int prot, int flags);
void panwrap_track_munmap(void *addr);

struct panwrap_mapped_memory *panwrap_find_mapped_mem(void *addr);
struct panwrap_mapped_memory *panwrap_find_mapped_mem_containing(void *addr);
struct panwrap_mapped_memory *panwrap_find_mapped_gpu_mem(mali_gpu_ptr addr);

#endif /* __MMAP_TRACE_H__ */
