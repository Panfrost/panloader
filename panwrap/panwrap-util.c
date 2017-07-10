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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include "panwrap.h"

static bool enable_timestamps = false;
static struct timespec start_time;
static FILE *log_output = stdout;

void
panwrap_print_decoded_flags(const struct panwrap_flag_info *flag_info,
			    u64 flags)
{
	bool print_bitwise_or = false;
	u64 undecoded_flags = flags;

	if (!flags) {
		panwrap_log_cont("0x000000000");
		return;
	}

	panwrap_log_cont("0x%010lx (", flags);

	for (int i = 0; flag_info[i].flag; i++) {
		if ((flags & flag_info[i].flag) != flag_info[i].flag)
			continue;

		panwrap_log_cont("%s%s",
				 print_bitwise_or ? " | " : "",
				 flag_info[i].name);

		print_bitwise_or = true;
		undecoded_flags &= ~flag_info[i].flag;
	}

	if (undecoded_flags)
		panwrap_log_cont("%s0x%lx",
				 print_bitwise_or ? " | " : "",
				 undecoded_flags);

	panwrap_log_cont(")");
}

/**
 * Grab the location of a symbol from the system's libc instead of our
 * preloaded one
 */
void *
__rd_dlsym_helper(const char *name)
{
	static void *libc_dl;
	void *func;

	if (!libc_dl)
		libc_dl = dlopen("libc.so", RTLD_LAZY);
	if (!libc_dl) {
		fprintf(stderr, "Failed to dlopen libc: %s\n", dlerror());
		exit(-1);
	}

	func = dlsym(libc_dl, name);
	if (!func) {
		fprintf(stderr, "Failed to find %s: %s\n", name, dlerror());
		exit(-1);
	}

	return func;
}

static void
panwrap_timestamp(struct timespec *tp)
{
	if (clock_gettime(CLOCK_MONOTONIC, tp)) {
		fprintf(stderr, "Failed to call clock_gettime: %s\n",
			strerror(errno));
		exit(1);
	}

	tp->tv_sec -= start_time.tv_sec;
	tp->tv_nsec -= start_time.tv_nsec;

	if (tp->tv_nsec < 0) {
		tp->tv_sec--;
		tp->tv_nsec = 1e+9 + tp->tv_nsec;
	}
}

void
panwrap_log(const char *format, ...)
{
	struct timespec tp;
	va_list ap;

	if (enable_timestamps) {
		panwrap_timestamp(&tp);
		fprintf(log_output,
			"panwrap [%.8lf]: ", tp.tv_sec + tp.tv_nsec / 1e+9F);
	} else {
		fprintf(log_output, "panwrap: ");
	}

	va_start(ap, format);
	vfprintf(log_output, format, ap);
	va_end(ap);
}

/* Eventually this function might do more */
void
panwrap_log_cont(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(log_output, format, ap);
	va_end(ap);
}

static void __attribute__((constructor))
panwrap_util_init()
{
	const char *log_output_env, *enable_timestamps_env;

	enable_timestamps_env = getenv("PANWRAP_ENABLE_TIMESTAMPS");
	if (enable_timestamps_env) {
		if (strcmp(enable_timestamps_env, "1") == 0) {
			enable_timestamps = true;
			if (clock_gettime(CLOCK_MONOTONIC, &start_time)) {
				fprintf(stderr,
					"Failed to call clock_gettime: %s\n",
					strerror(errno));
				exit(1);
			}
		} else if (strcmp(enable_timestamps_env, "0") != 0) {
			fprintf(
			    stderr,
			    "Invalid value for PANWRAP_ENABLE_TIMESTAMPS: %s\n"
			    "Valid values are 0 or 1\n",
			    enable_timestamps_env);
			exit(1);
		}
	}

	log_output_env = getenv("PANWRAP_OUTPUT");
	if (log_output_env) {
		/* Don't try to reopen stderr or stdout, that won't work */
		if (strcmp(log_output_env, "/dev/stderr") == 0) {
			log_output = stderr;
		} else if (strcmp(log_output_env, "/dev/stdout") == 0) {
			log_output = stdout;
		} else {
			log_output = fopen(log_output_env, "w+");
			if (!log_output) {
				fprintf(stderr, "Failed to open %s: %s\n",
					log_output_env, strerror(errno));
				exit(1);
			}
		}
	}
}
