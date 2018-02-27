/*
 * © Copyright 2018 The BiOpenly Community
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

/* TODO: Bifrost */

/* Takes shader source code in *src, calls out to the shader assembler, and
 * sticks the resulting raw binary in dst, for use in replays */

/* TODO: Interface with Python C API directly? */

void
pandev_shader_assemble(uint32_t *dst, const char *src)
{
	FILE *fp0 = fopen("/dev/shm/shader.asm", "w");
	fwrite(src, 1, strlen(src), fp0);
	fclose(fp0);

	system("python3 /home/guest/midgard-assembler/assemble.py /dev/shm/shader.asm /dev/shm/shader.bin > /dev/null");

	FILE *fp1 = fopen("/dev/shm/shader.bin", "rb");

	fseek(fp1, 0, SEEK_END);
	size_t sz = ftell(fp1);
	fseek(fp1, 0, SEEK_SET);

	fread(dst, 1, sz, fp1);
	fclose(fp1);
}
