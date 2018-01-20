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
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include "panwrap.h"

#define HEXDUMP_COL_LEN  4
#define HEXDUMP_ROW_LEN 16

static bool enable_timestamps = false,
	    enable_hexdump_trimming = true;
static struct timespec start_time;
static FILE *log_output;
short panwrap_indent = 0;

void
panwrap_log_decoded_flags(const struct panwrap_flag_info *flag_info,
			  u64 flags)
{
	bool decodable_flags_found = false;

	panwrap_log_cont("0x%" PRIx64, flags);

	for (int i = 0; flag_info[i].name; i++) {
		if ((flags & flag_info[i].flag) != flag_info[i].flag)
			continue;

		if (!decodable_flags_found) {
			decodable_flags_found = true;
			panwrap_log_cont(" (");
		} else {
			panwrap_log_cont(" | ");
		}

		panwrap_log_cont("%s", flag_info[i].name);

		flags &= ~flag_info[i].flag;
	}

	if (decodable_flags_found) {
		if (flags)
			panwrap_log_cont(" | 0x%" PRIx64, flags);

		panwrap_log_cont(")");
	}
}

void
panwrap_log_hexdump(const void *data, size_t size)
{
	unsigned char *buf = (void *) data;
	char alpha[HEXDUMP_ROW_LEN + 1];
	int i;

	for (i = 0; i < size; i++) {
		if (!(i % HEXDUMP_ROW_LEN))
			panwrap_log("%08X", (unsigned int) i);
		if (!(i % HEXDUMP_COL_LEN))
			panwrap_log_cont(" ");

		if (((void *) (buf + i)) < ((void *) data)) {
			panwrap_log_cont("   ");
			alpha[i % HEXDUMP_ROW_LEN] = '.';
		} else {
			panwrap_log_cont(" %02x", buf[i]);

			if (isprint(buf[i]) && (buf[i] < 0xA0))
				alpha[i % HEXDUMP_ROW_LEN] = buf[i];
			else
				alpha[i % HEXDUMP_ROW_LEN] = '.';
		}

		if ((i % HEXDUMP_ROW_LEN) == HEXDUMP_ROW_LEN - 1) {
			alpha[HEXDUMP_ROW_LEN] = 0;
			panwrap_log_cont("  |%s|\n", alpha);
		}
	}

	if (i % HEXDUMP_ROW_LEN) {
		for (i %= HEXDUMP_ROW_LEN; i < HEXDUMP_ROW_LEN; i++) {
			if (!(i % HEXDUMP_COL_LEN))
				panwrap_log_cont(" ");

			panwrap_log_cont("   ");
			alpha[i] = '.';

			if (i == HEXDUMP_ROW_LEN - 1) {
				alpha[HEXDUMP_ROW_LEN] = 0;
				panwrap_log_cont("  |%s|\n", alpha);
			}
		}
	}
}

/**
 * Same as panwrap_log_hexdump, but trims off sections of the memory that look
 * empty
 */
void
panwrap_log_hexdump_trimmed(const void *data, size_t size)
{
	const char *d = data;
	off_t trim_offset;
	size_t trim_size = size;
	bool trimming = false;

	if (!enable_hexdump_trimming)
		goto out;

	/*
	 * Find the last byte of the memory region that looks initialized,
	 * starting from the end
	 */
	for (trim_offset = size - 1; trim_offset != -1; trim_offset--) {
		if (d[trim_offset] != 0)
			break;
	}
	if (trim_offset < 0)
		goto out;

	trimming = true;
	trim_size = trim_offset + 1;
out:
	panwrap_log_hexdump(data, trim_size);
	if (trimming)
		panwrap_log("<0 repeating %zu times>\n", size - trim_size);
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
	if (!libc_dl)
		libc_dl = dlopen("libc.so.6", RTLD_LAZY);
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

	for (int i = 0; i < panwrap_indent; i++) {
		fputs("  ", log_output);
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

void
panwrap_log_flush()
{
	fflush(log_output);
}

/* Some functions for debugging in gdb */
void *
panwrap_download_mem(void *p, size_t s)
{
	void *cpy = malloc(s);
	memcpy(cpy, p, s);
	return cpy;
}

static bool
parse_env_bool(const char *env, bool def)
{
	const char *val = getenv(env);

	if (!val)
		return def;

	if (strcmp(val, "1") == 0)
		return true;
	else if (strcmp(val, "0") == 0)
		return false;

	fprintf(stderr,
		"Invalid value for %s: %s\n"
		"Valid values are 0 or 1\n",
		env, val);
	exit(1);
}

PANLOADER_CONSTRUCTOR {
	const char *env;

	if (parse_env_bool("PANWRAP_ENABLE_TIMESTAMPS", false)) {
		enable_timestamps = true;
		if (clock_gettime(CLOCK_MONOTONIC, &start_time)) {
			fprintf(stderr,
				"Failed to call clock_gettime: %s\n",
				strerror(errno));
			exit(1);
		}
	}

	enable_hexdump_trimming = parse_env_bool("PANWRAP_ENABLE_HEXDUMP_TRIM",
						 true);

	env = getenv("PANWRAP_OUTPUT");
	if (env) {
		/* Don't try to reopen stderr or stdout, that won't work */
		if (strcmp(env, "/dev/stderr") == 0) {
			log_output = stderr;
		} else if (strcmp(env, "/dev/stdout") == 0) {
			log_output = stdout;
		} else {
			log_output = fopen(env, "w+");
			if (!log_output) {
				fprintf(stderr, "Failed to open %s: %s\n",
					env, strerror(errno));
				exit(1);
			}
		}
	} else {
		log_output = stdout;
	}
}
