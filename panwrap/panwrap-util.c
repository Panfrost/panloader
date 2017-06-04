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
#include "panwrap.h"

/**
 * Literally grab the location of a symbol from libc so that we can change it
 * to whatever we want
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
