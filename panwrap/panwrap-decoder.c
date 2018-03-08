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

#include "panwrap.h"
#include <mali-ioctl.h>
#include <mali-job.h>
#include <stdio.h>
#include <memory.h>

#include "panwrap-shader.h"

#define MEMORY_PROP(obj, p) {\
	char *a = pointer_as_memory_reference(obj->p); \
	panwrap_prop("%s = %s", #p, a); \
	free(a); \
}

#define FLAG_INFO(flag) { MALI_GL_##flag, "MALI_GL_" #flag }
static const struct panwrap_flag_info gl_enable_flag_info[] = {
	FLAG_INFO(CULL_FACE),
	{}
};
#undef FLAG_INFO

extern char* replace_fragment;
extern char* replace_vertex;

static char *panwrap_job_type_name(enum mali_job_type type)
{
#define DEFINE_CASE(name) case JOB_TYPE_ ## name: return "JOB_TYPE_" #name
	switch (type) {
	DEFINE_CASE(NULL);
	DEFINE_CASE(SET_VALUE);
	DEFINE_CASE(CACHE_FLUSH);
	DEFINE_CASE(COMPUTE);
	DEFINE_CASE(VERTEX);
	DEFINE_CASE(TILER);
	DEFINE_CASE(FUSED);
	DEFINE_CASE(FRAGMENT);
	case JOB_NOT_STARTED:
		return "NOT_STARTED";
	default:
		panwrap_log("Warning! Unknown job type %x\n", type);
		return "!?!?!?";
	}
#undef DEFINE_CASE
}

static char *panwrap_gl_mode_name(enum mali_gl_mode mode)
{
#define DEFINE_CASE(name) case MALI_ ## name: return "MALI_" #name
	switch(mode) {
	DEFINE_CASE(GL_POINTS);
	DEFINE_CASE(GL_LINES);
	DEFINE_CASE(GL_TRIANGLES);
	DEFINE_CASE(GL_TRIANGLE_STRIP);
	DEFINE_CASE(GL_TRIANGLE_FAN);
	DEFINE_CASE(GL_LINE_STRIP);
	DEFINE_CASE(GL_LINE_LOOP);
	default: return "MALI_GL_TRIANGLES /* XXX: Unknown GL mode, check dump */";
	}
#undef DEFINE_CASE
}

static void panwrap_property_u32_list(const char *name, const u32 *lst, size_t c)
{
	panwrap_log(".%s = { ", name);
	panwrap_indent++;
	for (int i = 0; i < c; ++i)
		panwrap_log_cont("0x%" PRIx32 ", ", lst[i]);
	panwrap_indent--;
	panwrap_log_cont("},\n");
}

static inline char *panwrap_decode_fbd_type(enum mali_fbd_type type)
{
	if (type == MALI_SFBD)      return "SFBD";
	else if (type == MALI_MFBD) return "MFBD";
	else return "WTF!?";
}

static void panwrap_replay_sfbd(uint64_t gpu_va, int job_no)
{
	struct panwrap_mapped_memory *mem = panwrap_find_mapped_gpu_mem_containing(gpu_va);
	const struct mali_tentative_sfbd *PANWRAP_PTR_VAR(s, mem, (mali_ptr) gpu_va);

	/* FBDs are frequently duplicated, so watch for this */
	if (mem->touched[(gpu_va - mem->gpu_va) / sizeof(uint32_t)]) return;

	panwrap_log("struct mali_tentative_sfbd fbd_%d = {\n", job_no);
	panwrap_indent++;

	panwrap_prop("unknown1 = 0x%" PRIx32, s->unknown1);
	panwrap_prop("flags = 0x%" PRIx32, s->flags);
	panwrap_prop("heap_free_address = 0x%" PRIx64, s->heap_free_address);
	panwrap_prop("unknown2 = 0x%" PRIx32, s->unknown2);
	panwrap_prop("unknown3 = 0x%" PRIx32, s->unknown3);

	panwrap_prop("width = MALI_POSITIVE(%" PRId16 ")", s->width + 1);
	panwrap_prop("height = MALI_POSITIVE(%" PRId16 ")", s->height + 1);

	panwrap_property_u32_list("weights", s->weights, MALI_FBD_HIERARCHY_WEIGHTS);

	panwrap_prop("depth_buffer = " MALI_PTR_FMT, s->depth_buffer);
	panwrap_prop("depth_buffer_enable = %s", DS_ENABLE(s->depth_buffer_enable));

	panwrap_prop("stencil_buffer = " MALI_PTR_FMT, s->depth_buffer);
	panwrap_prop("stencil_buffer_enable = %s", DS_ENABLE(s->stencil_buffer_enable));

	panwrap_prop("clear_color_1 = 0x%" PRIx32, s->clear_color_1);
	panwrap_prop("clear_color_2 = 0x%" PRIx32, s->clear_color_2);
	panwrap_prop("clear_color_3 = 0x%" PRIx32, s->clear_color_3);
	panwrap_prop("clear_color_4 = 0x%" PRIx32, s->clear_color_4);

	panwrap_prop("clear_depth_1 = %f", s->clear_depth_1);
	panwrap_prop("clear_depth_2 = %f", s->clear_depth_2);
	panwrap_prop("clear_depth_3 = %f", s->clear_depth_3);
	panwrap_prop("clear_depth_4 = %f", s->clear_depth_4);

	panwrap_prop("clear_stencil = 0x%x", s->clear_stencil);

	MEMORY_PROP(s, unknown_address_0);
	MEMORY_PROP(s, unknown_address_1);
	MEMORY_PROP(s, unknown_address_2);

	panwrap_prop("unknown8 = 0x%" PRIx32, s->unknown8);
	panwrap_prop("unknown9 = 0x%" PRIx32, s->unknown9);

	panwrap_prop("tiler_jc_list = 0x%" PRIx64, s->tiler_jc_list);

	MEMORY_PROP(s, unknown_address_4);

	panwrap_indent--;
	panwrap_log("};\n");

	int zero_sum_pun = 0;
	zero_sum_pun += s->zero1;
	zero_sum_pun += s->zero2;
	for (int i = 0; i < sizeof(s->zero3)/sizeof(s->zero3[0]); ++i) zero_sum_pun += s->zero3[i];
	for (int i = 0; i < sizeof(s->zero6)/sizeof(s->zero6[0]); ++i) zero_sum_pun += s->zero6[i];

	if (zero_sum_pun)
		panwrap_msg("Zero sum tripped (%d), replay may be wrong\n", zero_sum_pun);

	TOUCH(mem, (mali_ptr) gpu_va, *s, "fbd", job_no);
}

void panwrap_replay_attributes(const struct panwrap_mapped_memory *mem,
			       mali_ptr addr, int job_no, int attr_no,
			       bool varying)
{
	/* Varyings in particlar get duplicated between parts of the job */
	if (mem->touched[(addr - mem->gpu_va) / sizeof(uint32_t)]) return;

	struct mali_attr *PANWRAP_PTR_VAR(attr, mem, addr);
	mali_ptr raw_elements = attr->elements & ~3;
	int flags = attr->elements & 3;
	size_t vertex_count;
	size_t component_count;

	int human_attr_number = (job_no * 100) + attr_no;
	char *prefix = varying ? "varying" : "attr";

	panwrap_log("struct mali_attr %s_%d = {\n", prefix, human_attr_number);
	panwrap_indent++;

	char *a = pointer_as_memory_reference(raw_elements);
	panwrap_prop("elements = (%s) | %d", a, flags);
	free(a);

	panwrap_prop("stride = 0x%" PRIx32, attr->stride);
	panwrap_prop("size = 0x%" PRIx32, attr->size);
	panwrap_indent--;
	panwrap_log("};\n");

	TOUCH(mem, addr, *attr, prefix, human_attr_number);

	if (!varying && attr->size < 0x40) {
		/* TODO: Attributes are not necessarily float32 vectors in general;
		 * decoding like this is unsafe all things considered */

		float *buffer = panwrap_fetch_gpu_mem(mem, raw_elements, attr->size);

		vertex_count = attr->size / attr->stride;
		component_count = attr->stride / sizeof(float);

		panwrap_log("float attributes_%d[] = {\n", human_attr_number);

		panwrap_indent++;
		for (int row = 0; row < vertex_count; row++) {
			panwrap_log_empty();

			for (int i = 0; i < component_count; i++)
				panwrap_log_cont("%ff, ", buffer[i]);

			panwrap_log_cont("\n");

			buffer += component_count;
		}
		panwrap_indent--;
		panwrap_log("};\n");

		TOUCH_LEN(mem, raw_elements, attr->size, "attributes", human_attr_number);
	}
}

void panwrap_replay_vertex_or_tiler_job(const struct mali_job_descriptor_header *h,
					const struct panwrap_mapped_memory *mem,
					mali_ptr payload, int job_no)
{
	struct mali_payload_vertex_tiler *PANWRAP_PTR_VAR(v, mem, payload);
	struct mali_shader_meta *meta;
	struct panwrap_mapped_memory *attr_mem;
	mali_ptr shader_meta_ptr = (u64) (uintptr_t) (v->_shader_upper << 4);

	panwrap_log("struct mali_payload_vertex_tiler vertex_tiler_%d = {\n", job_no);
	panwrap_indent++;


	panwrap_prop("line_width = %ff", v->line_width);
	panwrap_prop("vertex_count = MALI_POSITIVE(%" PRId32 ")", v->vertex_count + 1);
	panwrap_prop("unk1 = 0x%" PRIx32, v->unk1);

	if (h->job_type == JOB_TYPE_TILER) {
		panwrap_prop("draw_mode = 0x%" PRIx32 " | %s", v->draw_mode & ~(0xF), panwrap_gl_mode_name(v->draw_mode & 0xF));
	} else {
		panwrap_prop("draw_mode = 0x%" PRIx32, v->draw_mode);
	}

	/* Index count only exists for tiler jobs anyway */ 

	if (v->index_count)
		panwrap_prop("index_count = MALI_POSITIVE(%" PRId32 ")", v->index_count + 1);

	uint32_t remaining_gl_enables = v->gl_enables;

	panwrap_log(".gl_enables = ");
	
	if (h->job_type == JOB_TYPE_TILER) {
		panwrap_log_cont("MALI_GL_FRONT_FACE(MALI_GL_%s) | ",
		    v->gl_enables & MALI_GL_FRONT_FACE(MALI_GL_CW) ? "CW" : "CCW");

		remaining_gl_enables &= ~(MALI_GL_FRONT_FACE(1));
	}

	panwrap_log_decoded_flags(gl_enable_flag_info, remaining_gl_enables);

	panwrap_log_cont(",\n");

	if (h->job_type == JOB_TYPE_VERTEX && v->index_count)
		panwrap_msg("Warning: index count set in vertex job\n");

	if (v->zero0 | v->zero1 | v->zero3 | v->zero4 | v->zero5 | v->zero6) {
		panwrap_msg("Zero tripped, replay may be wrong\n");
		panwrap_prop("zero0 = 0x%" PRIx32, v->zero0);
		panwrap_prop("zero1 = 0x%" PRIx32, v->zero1);
		panwrap_prop("zero3 = 0x%" PRIx32, v->zero3);
		panwrap_prop("zero4 = 0x%" PRIx32, v->zero4);
		panwrap_prop("zero5 = 0x%" PRIx32, v->zero5);
		panwrap_prop("zero6 = 0x%" PRIx32, v->zero6);
	}

	MEMORY_PROP(v, indices);
	MEMORY_PROP(v, unknown0);
	MEMORY_PROP(v, unknown1); /* pointer */
	MEMORY_PROP(v, texture_meta_trampoline);
	MEMORY_PROP(v, sampler_descriptor);
	MEMORY_PROP(v, uniforms);
	MEMORY_PROP(v, attributes); /* struct attribute_buffer[] */
	MEMORY_PROP(v, attribute_meta); /* attribute_meta[] */
	MEMORY_PROP(v, varyings); /* pointer */
	MEMORY_PROP(v, unknown6); /* pointer */
	MEMORY_PROP(v, nullForVertex);
	MEMORY_PROP(v, fbd);

	char *a = pointer_as_memory_reference(shader_meta_ptr);
	panwrap_prop("_shader_upper = (%s) >> 4", a);
	free(a);

	panwrap_prop("flags = %d", v->flags); 

	panwrap_indent--;
	panwrap_log("};\n");

	TOUCH(mem, payload, *v, "vertex_tiler", job_no);

	/* TODO: Isn't this an -M-FBD? What's the difference? */
	panwrap_replay_sfbd(v->fbd, job_no);

	if (shader_meta_ptr) {
		struct panwrap_mapped_memory *smem = panwrap_find_mapped_gpu_mem_containing(shader_meta_ptr);
		struct mali_shader_meta *PANWRAP_PTR_VAR(s, smem, shader_meta_ptr);

		panwrap_log("struct mali_shader_meta shader_meta_%d = {\n", job_no);
		panwrap_indent++;

		/* TODO: Decode flags */
		mali_ptr shader_ptr = s->shader & ~15;

		char *a = pointer_as_memory_reference(shader_ptr);
		panwrap_prop("shader = (%s) | %d", a, (int) (s->shader & 15));
		free(a);

		panwrap_prop("zero = 0x%" PRIx32, s->zero);
		panwrap_prop("attribute_count = %" PRId16, s->attribute_count);
		panwrap_prop("unknown1 = 0x%" PRIx16, s->unknown1);

		/* Structure is still mostly unknown, unfortunately */
		panwrap_prop("uniform_registers = (%d << 20) | 0x%" PRIx32, (s->uniform_registers >> 20) & 0xFF, s->uniform_registers & ~0x0FF00000);

		panwrap_indent--;
		panwrap_log("};\n");
		TOUCH(smem, shader_meta_ptr, *meta, "shader_meta", job_no);

		panwrap_shader_disassemble(shader_ptr, job_no);

	} else
		panwrap_msg("<no shader>\n");
	
	if (v->nullForVertex) {
		struct panwrap_mapped_memory *fmem = panwrap_find_mapped_gpu_mem_containing(v->nullForVertex);
		struct nullForVertex *PANWRAP_PTR_VAR(f, fmem, v->nullForVertex);

		if (f->zero0)
			panwrap_msg("zero tripped (%X)\n", f->zero0);

		panwrap_log("struct nullForVertex nullForVertex_%d = {\n", job_no);
		panwrap_indent++;
		panwrap_log(".floats = {\n");
		panwrap_indent++;

		for (int i = 0; i < sizeof(f->floats) / sizeof(f->floats[0]); i += 2)
			panwrap_log("%ff, %ff,\n", f->floats[i], f->floats[i + 1]);

		panwrap_indent--;
		panwrap_log("},\n");
		panwrap_prop("width = MALI_POSITIVE(%" PRId16 ")", f->width + 1);
		panwrap_prop("height = MALI_POSITIVE(%" PRId16 ")", f->height + 1);
		panwrap_indent--;
		panwrap_log("};\n");

		TOUCH(fmem, v->nullForVertex, *f, "nullForVertex", job_no);
	}

	if (v->attribute_meta) {
		panwrap_log("struct mali_attr_meta attributes_%d[] = {\n", job_no);
		panwrap_indent++;

		size_t count = 0;

		struct mali_attr_meta *attr_meta;
		mali_ptr p;

		attr_mem = panwrap_find_mapped_gpu_mem_containing(v->attribute_meta);

		for (p = v->attribute_meta;
		     *PANWRAP_PTR(attr_mem, p, u64) != 0;
		     p += sizeof(struct mali_attr_meta), count++) {
			attr_meta = panwrap_fetch_gpu_mem(attr_mem, p,
							  sizeof(*attr_mem));

			panwrap_log("{ .index = %d, .flags = 0x%" PRIx64 "},\n",
					attr_meta->index, (u64) attr_meta->flags);
		}

		panwrap_indent--;
		panwrap_log("};\n");

		TOUCH_LEN(attr_mem, v->attribute_meta, sizeof(struct mali_attr_meta) * count, "attributes", job_no);

		attr_mem = panwrap_find_mapped_gpu_mem_containing(v->attributes);

		for (p = v->attribute_meta;
		     *PANWRAP_PTR(attr_mem, p, u64) != 0;
		     p += sizeof(struct mali_attr_meta), count++) {
			attr_meta = panwrap_fetch_gpu_mem(attr_mem, p,
							  sizeof(*attr_mem));

			panwrap_replay_attributes(
			    attr_mem,
			    v->attributes + (attr_meta->index *
					     sizeof(struct mali_attr)),
			    job_no, attr_meta->index, false);
		}
	}

	/* Varyings are encoded like attributes but not actually sent; we just
	 * pass a zero buffer with the right stride/size set, (or whatever)
	 * since the GPU will write to it itself */

	if (v->varyings) {
		attr_mem = panwrap_find_mapped_gpu_mem_containing(v->varyings);

		/* TODO: How many varyings? Is there a meta descriptor for them somewhere? */

		panwrap_replay_attributes(attr_mem, v->varyings, job_no, 0, true);
		panwrap_replay_attributes(attr_mem, v->varyings + sizeof(struct mali_attr), job_no, 1, true);
	}

	/* XXX: This entire block is such a hack... where are uniforms configured exactly? */

	if (v->uniforms) {
#if 0
		int rows = 2, width = 4;
		size_t sz = rows * width * sizeof(float);

		struct panwrap_mapped_memory *uniform_mem = panwrap_find_mapped_gpu_mem_containing(v->uniforms);
		panwrap_fetch_gpu_mem(uniform_mem, v->uniforms, sz);
		float *PANWRAP_PTR_VAR(uniforms, uniform_mem, v->uniforms);

		panwrap_log("float uniforms_%d[] = {\n", job_no);

		panwrap_indent++;
		for (int row = 0; row < rows; row++) {
			panwrap_log_empty();

			for (int i = 0; i < width; i++)
				panwrap_log_cont("%ff, ", uniforms[i]);

			panwrap_log_cont("\n");

			uniforms += width;
		}
		panwrap_indent--;
		panwrap_log("};\n");

		TOUCH_LEN(mem, v->uniforms, sz, "uniforms", job_no);
#else
		panwrap_msg("TODO: Handle uniforms appropriately\n");
#endif
	}

	if (v->unknown1) {
		struct panwrap_mapped_memory *umem = panwrap_find_mapped_gpu_mem_containing(v->unknown1);

		if (umem) {
			u64 *PANWRAP_PTR_VAR(u, umem, v->unknown1);

			mali_ptr ptr = *u >> 8;
			uint8_t flags = *u & 0xFF;

			char *a = pointer_as_memory_reference(ptr);
			panwrap_log("u64 unknown1_%d = ((%s) << 8) | %d;\n", job_no, a, flags);
			free(a);

			TOUCH(umem, v->unknown1, u64, "unknown1", job_no);
		}
	}

	if (v->unknown6) {
		struct panwrap_mapped_memory *umem = panwrap_find_mapped_gpu_mem_containing(v->unknown6);

		if (umem) {
			struct mali_unknown6 *PANWRAP_PTR_VAR(u, umem, v->unknown6);

			panwrap_log("struct mali_unknown6 unknown6_%d = {\n", job_no);
			panwrap_indent++;

			panwrap_prop("unknown0 = 0x%" PRIx64, u->unknown0);
			panwrap_prop("unknown1 = 0x%" PRIx64, u->unknown1);


			panwrap_indent--;
			panwrap_log("};\n");

			TOUCH(umem, v->unknown6, *u, "unknown6", job_no);
		}
	}

	/* Just a pointer to... another pointer >_< */

	if (v->texture_meta_trampoline) {
		struct panwrap_mapped_memory *mmem = panwrap_find_mapped_gpu_mem_containing(v->texture_meta_trampoline);

		if (mmem) {
			mali_ptr *PANWRAP_PTR_VAR(u, mmem, v->texture_meta_trampoline);

			char *a = pointer_as_memory_reference(*u);
			panwrap_log("uint64_t texture_meta_trampoline_%d = %s;", job_no, a);
			free(a);

			TOUCH(mmem, v->texture_meta_trampoline, *u, "texture_meta_trampoline", job_no);

			/* Now, finally, descend down into the texture descriptor */
			struct panwrap_mapped_memory *tmem = panwrap_find_mapped_gpu_mem_containing(*u);

			if (tmem) {
				struct mali_texture_descriptor *PANWRAP_PTR_VAR(t, tmem, *u);

				panwrap_log("struct mali_texture_descriptor texture_descriptor_%d = {\n", job_no);
				panwrap_indent++;

				panwrap_prop("width = MALI_POSITIVE(%" PRId16 ")", t->width + 1);
				panwrap_prop("height = MALI_POSITIVE(%" PRId16 ")", t->height + 1);

				panwrap_prop("unknown1 = 0x%" PRIx32, t->unknown1);
				
				/* TODO: I don't understand how these work at all yet */
				panwrap_prop("format1 = 0x%" PRIx32, t->format1);
				panwrap_prop("format2 = 0x%" PRIx32, t->format2);

				panwrap_prop("unknown3 = 0x%" PRIx32, t->unknown3);

				panwrap_prop("unknown5 = 0x%" PRIx32, t->unknown5);
				panwrap_prop("unknown6 = 0x%" PRIx32, t->unknown6);
				panwrap_prop("unknown7 = 0x%" PRIx32, t->unknown7);

				MEMORY_PROP(t, swizzled_bitmap_0);
				MEMORY_PROP(t, swizzled_bitmap_1);

				panwrap_indent--;
				panwrap_log("};\n");

				TOUCH(tmem, *u, *t, "texture_descriptor", job_no);
			}
		}
	}

	if (v->sampler_descriptor) {
		struct panwrap_mapped_memory *smem = panwrap_find_mapped_gpu_mem_containing(v->sampler_descriptor);

		if (smem) {
			struct mali_sampler_descriptor *PANWRAP_PTR_VAR(s, smem, v->sampler_descriptor);

			panwrap_log("struct mali_sampler_descriptor sampler_descriptor_%d = {\n", job_no);
			panwrap_indent++;

			/* Only the lower two bits are understood right now; the rest we display as hex */
			panwrap_log(".filter_mode = MALI_GL_TEX_MIN(%s) | MALI_GL_TEX_MAG(%s) | 0x%" PRIx32",\n",
				       	MALI_FILTER_NAME(s->filter_mode & MALI_GL_TEX_MIN_MASK),
				       	MALI_FILTER_NAME(s->filter_mode & MALI_GL_TEX_MAG_MASK),
					s->filter_mode & ~3);

			panwrap_prop("unknown1 = 0x%" PRIx32, s->unknown1);
			panwrap_prop("unknown2 = 0x%" PRIx32, s->unknown2);

			panwrap_indent--;
			panwrap_log("};\n");

			TOUCH(smem, v->sampler_descriptor, *s, "sampler_descriptor", job_no);
		}
	}

	if (v->indices) {
		struct panwrap_mapped_memory *imem = panwrap_find_mapped_gpu_mem_containing(v->indices);

		if (imem) {
			/* Indices are literally just a u32 array :) */

			uint32_t *PANWRAP_PTR_VAR(indices, imem, v->indices);

			panwrap_log("uint32_t indices_%d[] = {\n", job_no);
			panwrap_indent++;

			for(int i = 0; i < (v->index_count + 1); i += 3)
				panwrap_log("%d, %d, %d,\n",
						indices[i],
						indices[i + 1],
						indices[i + 2]);

			panwrap_indent--;
			panwrap_log("};\n");

			TOUCH_LEN(imem, v->indices, sizeof(uint32_t) * (v->index_count + 1), "indices", job_no);
		}
	}
}

static void panwrap_replay_fragment_job(const struct panwrap_mapped_memory *mem,
					mali_ptr payload, int job_no)
{
	const struct mali_payload_fragment *PANWRAP_PTR_VAR(s, mem, payload);

	uintptr_t p = (uintptr_t) s->fbd & FBD_MASK;

	panwrap_log("struct mali_payload_fragment fragment_%d = {\n", job_no);
	panwrap_indent++;

	if (s->zero)
		panwrap_msg("ZT\n");

	/* See the comments by the macro definitions for mathematical context
	 * on why this is so weird */

	panwrap_prop("_min_tile_coord = MALI_COORDINATE_TO_TILE_MIN(%d, %d, %d)",
			MALI_TILE_COORD_X(s->_min_tile_coord) << MALI_TILE_SHIFT,
			MALI_TILE_COORD_Y(s->_min_tile_coord) << MALI_TILE_SHIFT,
			MALI_TILE_COORD_FLAGS(s->_min_tile_coord));

	panwrap_prop("_max_tile_coord = MALI_COORDINATE_TO_TILE_MAX(%d, %d, %d)",
			(MALI_TILE_COORD_X(s->_max_tile_coord) + 1) << MALI_TILE_SHIFT,
			(MALI_TILE_COORD_Y(s->_max_tile_coord) + 1) << MALI_TILE_SHIFT,
			MALI_TILE_COORD_FLAGS(s->_max_tile_coord));

	panwrap_prop("fbd = %s | MALI_%s", pointer_as_memory_reference(p), s->fbd & MALI_MFBD ? "MFBD" : "SFBD");
	panwrap_indent--;
	panwrap_log("};\n");
	TOUCH(mem, payload, *s, "fragment", job_no);

	if ((s->fbd & FBD_TYPE) == MALI_SFBD)
		panwrap_replay_sfbd(s->fbd & FBD_MASK, job_no);
}

static int job_descriptor_number = 0;

void panwrap_replay_jc(mali_ptr jc_gpu_va)
{
	struct mali_job_descriptor_header *h;

	do {
		struct panwrap_mapped_memory *mem =
			panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);

		void *payload;

		h = PANWRAP_PTR(mem, jc_gpu_va, typeof(*h));

		int offset = h->job_descriptor_size == MALI_JOB_32 ? 4 : 0;
		mali_ptr payload_ptr = jc_gpu_va + sizeof(*h) - offset;

		payload = panwrap_fetch_gpu_mem(mem, payload_ptr,
						MALI_PAYLOAD_SIZE);

		int job_no = job_descriptor_number++;

		panwrap_log("struct mali_job_descriptor_header job_%d = {\n", job_no);
		panwrap_indent++;

		panwrap_prop("job_type = %s", panwrap_job_type_name(h->job_type));
		panwrap_prop("job_descriptor_size = %d", h->job_descriptor_size);

		if (h->exception_status)
			panwrap_prop("exception_status = %d", h->exception_status);

		if (h->first_incomplete_task)
			panwrap_prop("first_incomplete_task = %d", h->first_incomplete_task);

		if (h->fault_pointer)
			panwrap_prop("fault_pointer = 0x%" PRIx64, h->fault_pointer);

		if (h->job_barrier)
			panwrap_prop("job_barrier = %d", h->job_barrier);

		panwrap_prop("job_index = %d", h->job_index);

		if (h->unknown_flags)
			panwrap_prop("unknown_flags = %d", h->unknown_flags);

		if (h->job_dependency_index_1 | h->job_dependency_index_2) {
			panwrap_prop("job_dependency_index_1 = %d", h->job_dependency_index_1);
			panwrap_prop("job_dependency_index_2 = %d", h->job_dependency_index_2);
		} 

		u64 ptr = h->next_job;

		if (!h->job_descriptor_size)
			ptr = (u64) (u32) h->next_job; 


		char *a = pointer_as_memory_reference(ptr);
		panwrap_prop("next_job = %s", a);
		free(a);

		panwrap_indent--;
		panwrap_log("};\n");

		/* Touch the fields, careful about 32/64-bit */
		TOUCH_OLEN(mem, jc_gpu_va, sizeof(*h), offset, "job", job_no);

		switch (h->job_type) {
		case JOB_TYPE_SET_VALUE:
			{
				struct mali_payload_set_value *s = payload;

				panwrap_log("struct mali_payload_set_value set_value_%d = {\n", job_no);
				panwrap_indent++;
				panwrap_prop("out = 0x%" PRIX64, s->out);
				panwrap_prop("unknown = 0x%" PRIX64, s->unknown);
				panwrap_indent--;
				panwrap_log("};\n");

				TOUCH(mem, payload_ptr, *s, "set_value", job_no);

				break;
			}
		case JOB_TYPE_TILER:
		case JOB_TYPE_VERTEX:
			panwrap_replay_vertex_or_tiler_job(h, mem, payload_ptr, job_no);
			break;
		case JOB_TYPE_FRAGMENT:
			panwrap_replay_fragment_job(mem, payload_ptr, job_no);
			break;
		default:
			break;
		}
	} while ((jc_gpu_va = h->job_descriptor_size ? h->next_job : (u32) h->next_job));
}

void panwrap_replay_soft_replay_payload(mali_ptr jc_gpu_va, int job_no)
{
	struct mali_jd_replay_payload *v;

	struct panwrap_mapped_memory *mem =
		panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);

	v = PANWRAP_PTR(mem, jc_gpu_va, typeof(*v));

	panwrap_log("struct mali_jd_replay_payload soft_replay_payload_%d = {\n", job_no);
	panwrap_indent++;

	MEMORY_PROP(v, tiler_jc_list);
	MEMORY_PROP(v, fragment_jc);
	MEMORY_PROP(v, tiler_heap_free);

	panwrap_prop("fragment_hierarchy_mask = 0x%" PRIx32, v->fragment_hierarchy_mask);
	panwrap_prop("tiler_hierarchy_mask = 0x%" PRIx32, v->tiler_hierarchy_mask);
	panwrap_prop("hierarchy_default_weight = 0x%" PRIx32, v->hierarchy_default_weight);

	panwrap_log(".tiler_core_req = ");
	if (v->tiler_core_req)
		ioctl_log_decoded_jd_core_req(v->tiler_core_req);
	else
		panwrap_log_cont("0");
	panwrap_log_cont(",\n");

	panwrap_log(".fragment_core_req = ");
	if (v->fragment_core_req)
		ioctl_log_decoded_jd_core_req(v->fragment_core_req);
	else
		panwrap_log_cont("0");
	panwrap_log_cont(",\n");

	panwrap_indent--;
	panwrap_log("};\n");

	TOUCH(mem, jc_gpu_va, *v, "soft_replay_payload", job_no);
}

void panwrap_replay_soft_replay(mali_ptr jc_gpu_va)
{
	struct mali_jd_replay_jc *v;

	do {
		struct panwrap_mapped_memory *mem =
			panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);

		v = PANWRAP_PTR(mem, jc_gpu_va, typeof(*v));

		int job_no = job_descriptor_number++;
		panwrap_log("struct mali_jd_replay_jc soft_replay_%d = {\n", job_no);
		panwrap_indent++;

		MEMORY_PROP(v, next);
		MEMORY_PROP(v, jc);

		panwrap_indent--;
		panwrap_log("};\n");

		panwrap_replay_soft_replay_payload(jc_gpu_va + sizeof(struct mali_jd_replay_jc), job_no);

		TOUCH(mem, jc_gpu_va, *v, "soft_replay", job_no);
	} while ((jc_gpu_va = v->next));
}
