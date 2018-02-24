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

#ifndef PANWRAP_DECODER_H
#define PANWRAP_DECODER_H

#include <mali-ioctl.h>
#include <mali-job.h>
#include "panwrap.h"

void panwrap_replay_jc(mali_ptr jc_gpu_va);
void panwrap_replay_soft_replay(mali_ptr jc_gpu_va);

#endif /* !PANWRAP_DECODER_H */
