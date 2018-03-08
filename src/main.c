/*
 * © Copyright 2017 The Panfrost Community
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
#include "pandev.h"

int main(int argc, char **argv)
{
	int fd = pandev_open();

	if (fd < 0) {
		printf("pandev_open() failed with rc%d\n", -fd);
		return -fd;
	}

	printf("More to come soon :)\n");

	return 0;
}
