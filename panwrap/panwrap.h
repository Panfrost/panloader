/*
 * © Copyright 2017 The BiOpenly Community
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms
 * of such GNU license.
 *
 * A copy of the license is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 */

/*
 * Various bits and pieces of this borrowed from the freedreno project, which
 * borrowed from the lima project.
 */

#ifndef __WRAP_H__
#define __WRAP_H__

#include <dlfcn.h>
#include <panloader-util.h>

struct panwrap_flag_info {
	u64 flag;
	const char *name;
};

#define PROLOG(func) 					\
	static typeof(func) *orig_##func = NULL;	\
	if (!orig_##func)				\
		orig_##func = __rd_dlsym_helper(#func);	\

void __attribute__((format (printf, 1, 2))) panwrap_log(const char *format, ...);
void __attribute__((format (printf, 1, 2))) panwrap_log_cont(const char *format, ...);

void panwrap_freeze_time();
void panwrap_unfreeze_time();

void panwrap_log_decoded_flags(const struct panwrap_flag_info *flag_info,
			       u64 flags);
void panwrap_log_hexdump(const void *data, size_t size, const char *indent);
void panwrap_log_hexdump_trimmed(const void *data, size_t size, const char *ident);

void * __rd_dlsym_helper(const char *name);

#endif /* __WRAP_H__ */
