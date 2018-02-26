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

#include "panwrap.h"
#include <mali-ioctl.h>
#include <mali-job.h>
#include <stdio.h>
#include <memory.h>

/* Routines for handling shader assembly, calling out to external assembler and
 * disassemblers. Currently only implemented under Midgard; Bifrost code should
 * be integrated here as well in the near future, once an assembler is written
 * for that platform. */

/* TODO: expose in meson so Lyude doesn't get annoyed at me for breaking
 * Bifrost */

#define SHADER_MIDGARD

#ifdef SHADER_MIDGARD

/* TODO: Cleanup dependency mess with cwabbotts-open-gpu-tools fork */

#include <ogt.h>

/* Disassemble the shader itself. */

void
panwrap_shader_disassemble(mali_ptr shader_ptr)
{
	struct panwrap_mapped_memory *shaders = panwrap_find_mapped_gpu_mem_containing(shader_ptr);

	int offset = shader_ptr - shaders->gpu_va;

	if (!ogt_arch_disassemble(ogt_arch_lima_t600,
				  shaders->addr + offset,
				  shaders->length - offset,
				  NULL,
				  ogt_asm_type_fragment, ogt_asm_syntax_explicit, 0)) {
		panwrap_msg("Error disassembling shader\n");
		return;
	}


#if 0
	FILE *tmpfp = fopen("/dev/shm/shader.bin", "wb");
	fwrite(shaders->addr + (shader_ptr - shaders->gpu_va), 1, shaders->length - (shader_ptr - shaders->gpu_va), tmpfp);
	fclose(tmpfp);
#endif

	/*
	system("/dev/shm/disassemble /dev/shm/shader.bin 2>/dev/null > /dev/shm/shader.c");
	FILE *disfp = popen("/dev/shm/disassemble /dev/shm/shader.bin", "r");

	panwrap_log("#if 0\n");

	char buffer[512];
	while (fgets(buffer, sizeof(buffer), disfp) != NULL) {
		panwrap_log_cont("%s\n", buffer);
		break;
	}

	panwrap_log("#endif\n");
	pclose(disfp);*/
}

#else

void
panwrap_shader_disassemble(mali_ptr shader_ptr)
{
	panwrap_msg("Shader decoding is not yet supported on non-Midgard platforms\n");
	panwrap_msg("No disassembly performed for shader at " MALI_PTR_FMT, shader_ptr);
}

#endif
