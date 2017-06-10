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
#include "panwrap.h"

void
panwrap_print_decoded_flags(const struct panwrap_flag_info *flag_info,
			    u64 flags)
{
	bool print_bitwise_or = false;
	u64 undecoded_flags = flags;

	if (!flags) {
		printf("0x000000000");
		return;
	}

	printf("0x%010lx (", flags);

	for (int i = 0; flag_info[i].flag; i++) {
		if (!(flags & flag_info[i].flag))
			continue;

		printf("%s%s",
		       print_bitwise_or ? " | " : "", flag_info[i].name);

		print_bitwise_or = true;
		undecoded_flags &= ~flag_info[i].flag;
	}

	if (undecoded_flags)
		printf("%s0x%lx",
		       print_bitwise_or ? " | " : "", undecoded_flags);

	printf(")");
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
