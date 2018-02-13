/*
 * © Copyright 2017-2018 The BiOpenly Community
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

int pandev_open();
int pandev_query_mem(int fd, mali_ptr addr, enum mali_ioctl_mem_query_type attr,
		     u64 *out);

/* Calls used while replaying */
int pandev_raw_open();
u8* pandev_map_mtp(int fd);
int pandev_ioctl(int fd, unsigned long request, void *args);

#endif /* __PANDEV_H__ */
