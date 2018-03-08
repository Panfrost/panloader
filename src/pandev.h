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

#ifndef __PANDEV_H__
#define __PANDEV_H__

#include <mali-ioctl.h>
#include <mali-job.h>
#include <linux/ioctl.h>
#include "slow-framebuffer.h"

int pandev_open();
int pandev_query_mem(int fd, mali_ptr addr, enum mali_ioctl_mem_query_type attr,
		     u64 *out);

/* Calls used while replaying */
int pandev_raw_open();
u8* pandev_map_mtp(int fd);
int pandev_ioctl(int fd, unsigned long request, void *args);

int pandev_standard_allocate(int fd, int va_pages, int flags, u64 *out);
int pandev_general_allocate(int fd, int va_pages, int commit_pages, int extent, int flags, u64 *out);

void pandev_shader_assemble(uint32_t *dst, const char *src);

off_t pandev_allocate_offset(off_t *stack, size_t sz);
mali_ptr pandev_upload(int cheating_offset, mali_ptr base, void *base_map, void *data, size_t sz);

#include <math.h>
#define inff INFINITY

#define R(...) #__VA_ARGS__

#endif /* __PANDEV_H__ */
