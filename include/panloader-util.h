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

/**
 * Miscellanious utilities
 */

#ifndef __PANLOADER_UTIL_H__
#define __PANLOADER_UTIL_H__

#include <inttypes.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define ASSERT_SIZEOF_TYPE(type__, size__)       \
	_Static_assert(sizeof(type__) == size__, \
                       #type__ " does not match expected size " #size__)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define YES_NO(b) ((b) ? "Yes" : "No")

#endif /* __PANLOADER_UTIL_H__ */
