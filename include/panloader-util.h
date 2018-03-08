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

/**
 * Miscellanious utilities
 */

#ifndef __PANLOADER_UTIL_H__
#define __PANLOADER_UTIL_H__

#include <inttypes.h>
#include <config.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* ASSERT_SIZEOF_TYPE:
 *
 * Forces compilation to fail if the size of the struct differs from the given
 * arch-specific size that was observed during tracing. A size of 0 indicates
 * that the ioctl has not been observed in a trace yet, and thus it's size is
 * unconfirmed.
 *
 * Useful for preventing mistakenly extending the length of an ioctl struct and
 * thus, causing all members part of said extension to be located at incorrect
 * memory locations.
 */
#ifdef __LP64__
#define ASSERT_SIZEOF_TYPE(type__, size32__, size64__)              \
	_Static_assert(size64__ == 0 || sizeof(type__) == size64__, \
                       #type__ " does not match expected size " #size64__)
#else
#define ASSERT_SIZEOF_TYPE(type__, size32__, size64__) \
	_Static_assert(size32__ == 0 || sizeof(type__) == size32__, \
		       #type__ " does not match expected size " #size32__)
#endif

#define __PASTE_TOKENS(a, b) a ## b
/*
 * PASTE_TOKENS(a, b):
 *
 * Expands a and b, then concatenates the resulting tokens
 */
#define PASTE_TOKENS(a, b) __PASTE_TOKENS(a, b)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define OFFSET_OF(type, member) __builtin_offsetof(type, member)

#define YES_NO(b) ((b) ? "Yes" : "No")

#define PANLOADER_CONSTRUCTOR \
       static void __attribute__((constructor)) PASTE_TOKENS(__panloader_ctor_l, __LINE__)()

#define PANLOADER_DESTRUCTOR \
       static void __attribute__((destructor)) PASTE_TOKENS(__panloader_dtor_l, __LINE__)()

#define msleep(n) (usleep(n * 1000))

/* Semantic logging type.
 *
 * Raw: for raw messages to be printed as is.
 * Message: for helpful information to be commented out in replays.
 * Property: for properties of a struct
 *
 * Use one of panwrap_log, panwrap_msg, or panwrap_prop as syntax sugar.
 */

enum panwrap_log_type {
	PANWRAP_RAW,
	PANWRAP_MESSAGE,
	PANWRAP_PROPERTY
};

#define panwrap_log(...)  panwrap_log_typed(PANWRAP_RAW,      __VA_ARGS__)
#define panwrap_msg(...)  panwrap_log_typed(PANWRAP_MESSAGE,  __VA_ARGS__)
#define panwrap_prop(...) panwrap_log_typed(PANWRAP_PROPERTY, __VA_ARGS__)

#endif /* __PANLOADER_UTIL_H__ */
