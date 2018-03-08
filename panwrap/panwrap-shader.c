/*
 * © Copyright 2018 The Panfrost Community
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
panwrap_shader_disassemble(mali_ptr shader_ptr, int shader_no)
{
	struct panwrap_mapped_memory *shaders = panwrap_find_mapped_gpu_mem_containing(shader_ptr);

	int offset = shader_ptr - shaders->gpu_va;

	/* Disassemble it at trace time... */

	panwrap_log("const char shader_src_%d[] = R\"(\n", shader_no);

	if (!ogt_arch_disassemble(ogt_arch_lima_t600,
				  shaders->addr + offset,
				  shaders->length - offset,
				  NULL,
				  ogt_asm_type_fragment, ogt_asm_syntax_explicit, 1)) {
		panwrap_msg("Error disassembling shader\n");
		return;
	}

	panwrap_log(")\";\n\n");

	/* ...but reassemble at runtime! */

	panwrap_log("pandev_shader_assemble(%s + %d, shader_src_%d);\n\n",
			shaders->name,
			offset / sizeof(uint32_t),
			shader_no);
}

#else

void
panwrap_shader_disassemble(mali_ptr shader_ptr, int shader_no)
{
	panwrap_msg("Shader decoding is not yet supported on non-Midgard platforms\n");
	panwrap_msg("No disassembly performed for shader at " MALI_PTR_FMT, shader_ptr);
}

#endif
