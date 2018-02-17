/*
 * © Copyright 2018 Alyssa Rosenzweig
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

#ifndef __SLOW_FRAMEBUFFER_H__
#define __SLOW_FRAMEBUFFER_H__

void slowfb_init(int width, int height);
void slowfb_update(uint8_t *framebuffer, int width, int height);

#endif /* __SLOW_FRAMEBUFFER_H__ */
