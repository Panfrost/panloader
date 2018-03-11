/*
 * © Copyright 2018 The Panfrost Community
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
#include "pandev.h"

// TODO: An actual allocator, perhaps
// TODO: Multiple stacks for multiple bases?

off_t stack_bottom = 0;

off_t
pandev_allocate_offset(off_t *stack, size_t sz)
{
	off_t ret = *stack;
	*stack += sz;
	return ret;
}


mali_ptr
pandev_upload(int cheating_offset, mali_ptr base, void *base_map, void *data, size_t sz)
{
	off_t offset;

	/* Allocate space for the new GPU object, if required */

	if (cheating_offset == -1) {
		offset = pandev_allocate_offset(&stack_bottom, sz);
	} else {
		offset = cheating_offset;
	}

	/* Upload it */
	memcpy(base_map + offset, data, sz);

	/* Return the GPU address */
	return base + offset;
}

