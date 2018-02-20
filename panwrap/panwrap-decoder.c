/*
 * © Copyright 2017-2018 The BiOpenly Community
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

#define MEMORY_PROP(p) {\
	char *a = pointer_as_memory_reference(v->p); \
	panwrap_prop("%s = %s", #p, a); \
	free(a); \
}

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
	default: return "GL_TRIANGLES /* XXX: Unknown GL mode, check dump */";
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
	panwrap_prop("unknown4 = 0x%" PRIx32, s->unknown4);

	panwrap_property_u32_list("weights", s->weights, MALI_FBD_HIERARCHY_WEIGHTS);

	panwrap_prop("depth_buffer = " MALI_PTR_FMT, s->depth_buffer);
	panwrap_prop("depth_buffer_unknown = 0x%" PRIx64, s->depth_buffer_unknown);

	panwrap_prop("stencil_buffer = " MALI_PTR_FMT, s->depth_buffer);
	panwrap_prop("stencil_buffer_unknown = 0x%" PRIx64, s->stencil_buffer_unknown);

	panwrap_prop("clear_color_1 = 0x%" PRIx32, s->clear_color_1);
	panwrap_prop("clear_color_2 = 0x%" PRIx32, s->clear_color_2);
	panwrap_prop("clear_color_3 = 0x%" PRIx32, s->clear_color_3);
	panwrap_prop("clear_color_4 = 0x%" PRIx32, s->clear_color_4);

	panwrap_prop("clear_depth_1 = %f", s->clear_depth_1);
	panwrap_prop("clear_depth_2 = %f", s->clear_depth_2);
	panwrap_prop("clear_depth_3 = %f", s->clear_depth_3);
	panwrap_prop("clear_depth_4 = %f", s->clear_depth_4);

	panwrap_prop("clear_stencil = 0x%x", s->clear_stencil);

	char *a = pointer_as_memory_reference(s->unknown_address_1);
	panwrap_prop("unknown_address_1 = %s", a);
	free(a);
	
	a = pointer_as_memory_reference(s->unknown_address_2);
	panwrap_prop("unknown_address_2 = %s", a);
	free(a);

	panwrap_prop("unknown_address_0 = 0x%" PRIx64, s->unknown_address_0);

	panwrap_prop("unknown8 = 0x%" PRIx32, s->unknown8);
	panwrap_prop("unknown9 = 0x%" PRIx32, s->unknown9);

	panwrap_prop("tiler_jc_list = 0x%" PRIx64, s->tiler_jc_list);
	panwrap_prop("unknown_address_4 = 0x%" PRIx64, s->unknown_address_4);

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

void panwrap_decode_attributes(const struct panwrap_mapped_memory *mem,
			       mali_ptr addr)
{
#if 0
	struct mali_attr *PANWRAP_PTR_VAR(attr, mem, addr);
	float *buffer = panwrap_fetch_gpu_mem(
	    mem, attr->elements_upper << 2, attr->size);
	size_t vertex_count;
	size_t component_count;

	vertex_count = attr->size / attr->stride;
	component_count = attr->stride / sizeof(float);

	panwrap_log(MALI_SHORT_PTR_FMT " (%x):\n",
		    attr->elements_upper << 2, attr->flags);

	panwrap_indent++;
	for (int row = 0; row < vertex_count; row++) {
		panwrap_log("<");
		for (int i = 0; i < component_count; i++)
			panwrap_log_cont("%f%s",
					 buffer[i],
					 i < component_count - 1 ? ", " : "");
		panwrap_log_cont(">\n");
	}
	panwrap_indent--;
#endif
}

static void panwrap_trace_fbd(const struct panwrap_mapped_memory *mem,
			      const u64 *fbd_meta)
{
	mali_ptr fbd_ptr = *fbd_meta & FBD_MASK;
	struct mali_tentative_mfbd *mfbd;

	if (!fbd_ptr) {
		panwrap_log("<no fbd>\n");
		return;
	}

	mfbd = panwrap_fetch_gpu_mem(NULL, fbd_ptr, sizeof(*mfbd));

	panwrap_log("%s @ " MALI_PTR_FMT ":\n",
		    panwrap_decode_fbd_type(*fbd_meta & FBD_TYPE), fbd_ptr);
	panwrap_indent++;

	/* XXX We're not entirely sure which parts of the fbd format that we
	 * have so far are and aren't correct, so do a hexdump so we can catch
	 * errors more easily
	 */
	panwrap_log("Raw fbd:\n");
	panwrap_indent++;
	panwrap_log_hexdump(mfbd, sizeof(*mfbd));
	panwrap_indent--;

#define OFFSET(m) OFFSET_OF(struct mali_tentative_mfbd, m)
#define END(m) OFFSET(m) + sizeof(mfbd->m) - 1
	panwrap_log("Block #1 (+0x%zx-0x%zx):\n",
		    OFFSET(block1), END(block1));
	panwrap_indent++;
	panwrap_log_hexdump(mfbd->block1, sizeof(mfbd->block1));
	panwrap_indent--;

	panwrap_log("Flags (+0x%zx): 0x%x\n", OFFSET(flags), mfbd->flags);
	panwrap_log("Heap free address (+0x%zx): " MALI_PTR_FMT "\n",
		    OFFSET(heap_free_address), mfbd->heap_free_address);

	panwrap_log("Unknown #2 (+0x%zx):\n", OFFSET(unknown2));
	panwrap_indent++;
	/* Seems to sometimes be a pointer but sometimes not? Eithr way, we
	 * can't make assumptions on this one since freedreno's test-clear demo
	 * seems to crash this by having an invalid memory address here
	 */
	if (mfbd->unknown2) {
		struct panwrap_mapped_memory *unk2_mem =
			panwrap_find_mapped_gpu_mem_containing(mfbd->unknown2);

		if (unk2_mem) {
			panwrap_log_hexdump(
			    panwrap_fetch_gpu_mem(unk2_mem, mfbd->unknown2, 64),
			    64);
		} else {
			panwrap_log("Error! unk2 has unknown address " MALI_PTR_FMT "\n",
				    mfbd->unknown2);
		}
	} else
		panwrap_log("<none>\n");
	panwrap_indent--;

	/* XXX: Cafe was asserting zeroes here in block2[0] and block2[1] (in
	 * our version since we use u8, this would be block2[8] for 64bit or
	 * block2[4] for 32bit. It's probable that there's some sort of data
	 * here sometimes
	 */
	panwrap_log("Block #2 (+0x%zx-0x%zx):\n",
		    OFFSET(block1), END(block1));
	panwrap_indent++;
	panwrap_log_hexdump(mfbd->block2, sizeof(mfbd->block2));
	panwrap_indent--;

	/* Somehow maybe sort of kind of framebufferish?
	 * It changes predictably in the same way as the FB.
	 * Unclear what exactly it is, though.
	 *
	 * Where the framebuffer is: 1A 33 00 00
	 * This is: 71 B3 03 71 6C 4D 87 46
	 * Where the framebuffer is: 1A 33 1A 00
	 * This is: AB E4 43 9C E8 D6 D1 25
	 *
	 * It repeats, too, but everything 8 bytes rather than 4.
	 *
	 * It is a function of the colour painted. But the exact details
	 * are elusive.
	 *
	 * Also, this is an output, not an input.
	 * Assuming the framebuffer works as intended, RE may be
	 * pointless.
	 */

	panwrap_log("ugaT (+0x%zx) = " MALI_PTR_FMT ", uga (+0x%zx) = " MALI_PTR_FMT "\n",
		    OFFSET(ugaT), mfbd->ugaT,
		    OFFSET(unknown_gpu_address), mfbd->unknown_gpu_address);
	panwrap_log("ugan (+0x%zx) = " MALI_PTR_FMT "\n",
		    OFFSET(unknown_gpu_addressN), mfbd->unknown_gpu_addressN);

	panwrap_log("blah (+0x%zx) = %" PRIx64 "\n",
		    OFFSET(blah), mfbd->blah);

#define PR_UNK(n, s) panwrap_log("unknown" #n " (+0x%zx) = %" PRIx ## s "\n", \
				 OFFSET(unknown ## n), mfbd->unknown ## n)
	PR_UNK(1, 32);

	panwrap_log("unknown2 (+0x%zx) = " MALI_PTR_FMT "\n", \
				 OFFSET(unknown2), mfbd->unknown2);

	PR_UNK(3, 64);
#undef PR_UNK

	panwrap_log("Weights (+0x%zx-0x%zx) = [ ",
		    OFFSET(weights), END(weights));
	for (int i = 0; i < ARRAY_SIZE(mfbd->weights); i++) {
		panwrap_log_cont("%" PRIx32, mfbd->weights[i]);
		if (i + 1 < ARRAY_SIZE(mfbd->weights))
			panwrap_log_cont(", ");
	}
	panwrap_log_cont(" ]\n");

	panwrap_indent--;
#undef OFFSET
#undef END
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

	if (!varying) {
		/* TODO: Attributes are not necessarily float32 vectors in general;
		 * decoding like this is unsafe all things considered */

		float *buffer = panwrap_fetch_gpu_mem(mem, raw_elements, attr->size);

		vertex_count = attr->size / attr->stride;
		component_count = attr->stride / sizeof(float);

		panwrap_log("float attributes_%d[] = {\n", human_attr_number);

		panwrap_indent++;
		for (int row = 0; row < vertex_count; row++) {
			panwrap_log("");

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
	struct mali_attr_meta *attr_meta;
	u8 *shader;
	mali_ptr shader_meta_ptr = (u64) (uintptr_t) (v->_shader_upper << 4);
	mali_ptr p;

	panwrap_log("struct mali_payload_vertex_tiler vertex_tiler_%d = {\n", job_no);
	panwrap_indent++;


	panwrap_prop("unk0 = 0x%" PRIx32, v->unk0);
	panwrap_prop("unk1 = 0x%" PRIx32, v->unk1);

	if (h->job_type == JOB_TYPE_TILER) {
		panwrap_prop("draw_mode = %s", panwrap_gl_mode_name(v->draw_mode));
	} else {
		panwrap_prop("draw_mode = 0x%" PRIx32, v->draw_mode);
	}

	panwrap_prop("unk5 = 0x%" PRIx32, v->unk5);
	panwrap_prop("unk8 = 0x%" PRIx32, v->unk8);

	if (v->zero0 | v->zero1 | v->zero2 | v->zero3 | v->zero4 | v->zero5 | v->zero6)
		panwrap_msg("Zero tripped, replay may be wrong\n");

	MEMORY_PROP(unknown0);
	MEMORY_PROP(unknown1); /* pointer */
	MEMORY_PROP(texture_meta_address);
	MEMORY_PROP(texture_unknown);
	MEMORY_PROP(uniforms);
	MEMORY_PROP(attributes); /* struct attribute_buffer[] */
	MEMORY_PROP(attribute_meta); /* attribute_meta[] */
	MEMORY_PROP(varyings); /* pointer */
	MEMORY_PROP(unknown6); /* pointer */
	MEMORY_PROP(nullForVertex);
	MEMORY_PROP(fbd);

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
		char *a = pointer_as_memory_reference(s->shader & ~7);
		panwrap_prop("shader = (%s) | %d", a, (int) (s->shader & 7));
		free(a);

		panwrap_prop("zero = 0x%" PRIx32, s->zero);
		panwrap_prop("unknown1 = 0x%" PRIx32, s->unknown1);
		panwrap_prop("unknown2 = 0x%" PRIx32, s->unknown2);

		panwrap_indent--;
		panwrap_log("};\n");
		TOUCH(smem, shader_meta_ptr, *meta, "shader_meta", job_no);
	} else
		panwrap_msg("<no shader>\n");
	
	if (v->nullForVertex) {
		struct panwrap_mapped_memory *fmem = panwrap_find_mapped_gpu_mem_containing(v->nullForVertex);
		struct nullForVertex *PANWRAP_PTR_VAR(f, fmem, v->nullForVertex);

		if (f->zero0)
			panwrap_msg("zero tripped (%X)\n", f->zero0);

		panwrap_log("struct nullForVertex nullForVertex_%d = {\n", job_no);
		panwrap_indent++;
		panwrap_log(".floats = {\n", job_no);
		panwrap_indent++;

		for (int i = 0; i < sizeof(f->floats) / sizeof(f->floats[0]); i += 2)
			panwrap_log("%ff, %ff,\n", f->floats[i], f->floats[i + 1]);

		panwrap_indent--;
		panwrap_log("},\n");
		panwrap_prop("unknown0 = 0x%" PRIx32, f->unknown0);
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
					attr_meta->index, attr_meta->flags);
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
		int rows = 2, width = 4;
		size_t sz = rows * width * sizeof(float);

		struct panwrap_mapped_memory *uniform_mem = panwrap_find_mapped_gpu_mem_containing(v->uniforms);
		panwrap_fetch_gpu_mem(uniform_mem, v->uniforms, sz);
		float *PANWRAP_PTR_VAR(uniforms, uniform_mem, v->uniforms);

		panwrap_log("float uniforms_%d[] = {\n", job_no);

		panwrap_indent++;
		for (int row = 0; row < rows; row++) {
			panwrap_log("");

			for (int i = 0; i < width; i++)
				panwrap_log_cont("%ff, ", uniforms[i]);

			panwrap_log_cont("\n");

			uniforms += width;
		}
		panwrap_indent--;
		panwrap_log("};\n");

		TOUCH_LEN(mem, v->uniforms, sz, "uniforms", job_no);
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
}

void panwrap_decode_vertex_or_tiler_job(const struct mali_job_descriptor_header *h,
					const struct panwrap_mapped_memory *mem,
					mali_ptr payload)
{
	struct mali_payload_vertex_tiler *PANWRAP_PTR_VAR(v, mem, payload);
	struct mali_shader_meta *meta;
	struct panwrap_mapped_memory *attr_mem;
	struct mali_attr_meta *attr_meta;
	u8 *shader;
	mali_ptr meta_ptr = v->_shader_upper << 4;
	mali_ptr p;

	attr_mem = panwrap_find_mapped_gpu_mem_containing(v->attribute_meta);

	panwrap_log("%s shader @ " MALI_PTR_FMT " (flags 0x%x)\n",
		    h->job_type == JOB_TYPE_VERTEX ? "Vertex" : "Fragment",
		    meta_ptr, v->flags);

	panwrap_indent++;

	if (meta_ptr) {
		meta = panwrap_fetch_gpu_mem(NULL, meta_ptr, sizeof(*meta));
		shader = panwrap_fetch_gpu_mem(NULL, meta->shader, 64);

		/* For testing the shader compiler infrastructure, panloader
		 * can replace shaders at runtime, configurable by
		 * environmental variables. */

		char *replacement = h->job_type == JOB_TYPE_VERTEX ?
			replace_vertex : replace_fragment;

		if (*replacement) {
			/* TODO: Determine size and possibly allocate our own
			 * shader buffer */

			FILE *fp = fopen(replacement, "rb");
			fread(shader, 1, 64, fp);
			fclose(fp);
		}

		panwrap_log("Shader blob: @ " MALI_PTR_FMT " (@ " MALI_PTR_FMT ")\n",
				meta_ptr, meta->shader & ~7);
		panwrap_indent++;
		panwrap_log_hexdump(
		    panwrap_fetch_gpu_mem(NULL, meta->shader & ~7, 832), 832);
		panwrap_indent--;

	} else
		panwrap_log("<no shader>\n");

	if (v->attribute_meta) {
		panwrap_log("Attribute list:\n");
		panwrap_indent++;
		for (p = v->attribute_meta;
		     *PANWRAP_PTR(attr_mem, p, u64) != 0;
		     p += sizeof(u64)) {
			attr_meta = panwrap_fetch_gpu_mem(attr_mem, p,
							  sizeof(*attr_mem));

			panwrap_log("%x:\n", attr_meta->index);
			panwrap_indent++;

			panwrap_log("flags = 0x%014" PRIx64 "\n",
				    (u64) attr_meta->flags);
			panwrap_decode_attributes(
			    attr_mem,
			    v->attributes + (attr_meta->index *
					     sizeof(struct mali_attr)));

			panwrap_indent--;
		}
		panwrap_indent--;
	} else
		panwrap_log("<no attributes>\n");

	/*
	panwrap_log("Block #2:\n");
	panwrap_indent++;
	panwrap_log_hexdump(v->block2, sizeof(v->block2));
	panwrap_indent--;
	*/

	/*
	if (h->job_type == JOB_TYPE_TILER && v->block1[7]) {
		panwrap_log("GL draw mode: %s\n",
			    panwrap_gl_mode_name(
				*PANWRAP_PTR(attr_mem, v->block1[7], u8)));
	}
	*/

	if (v->uniforms) {
		/* XXX: How do we know how many to print? How do we know to use
		 * half-floats? */

		struct panwrap_mapped_memory *uniform_mem = panwrap_find_mapped_gpu_mem_containing(v->uniforms);

		panwrap_log("Uniforms: \n");
		panwrap_fetch_gpu_mem(uniform_mem, v->uniforms, 4 * sizeof(__fp16));

		__fp16 *PANWRAP_PTR_VAR(uniforms, uniform_mem, v->uniforms);

		panwrap_indent++;
		panwrap_log("<");

		for (int i = 0; i < 4; i++)
			panwrap_log_cont("%f%s",
					 (float) uniforms[i],
					 i < 4 - 1 ? ", " : "");

		panwrap_log_cont(">\n");
		panwrap_indent--;
	}

	/*
	panwrap_log("nulls: " MALI_SHORT_PTR_FMT ", " MALI_SHORT_PTR_FMT "\n",
		    v->null0, v->null4);
	    */

	if (v->texture_meta_address || v->texture_unknown) {
		panwrap_log("Texture:");
		panwrap_indent++;
		panwrap_log("Meta address: " MALI_SHORT_PTR_FMT "\n", v->texture_meta_address);
		panwrap_log("Unknown address: " MALI_SHORT_PTR_FMT "\n", v->texture_unknown);
		panwrap_indent--;
	}

	panwrap_trace_fbd(mem, &v->fbd);

	panwrap_indent--;
}


static void panwrap_replay_fragment_job(const struct panwrap_mapped_memory *mem,
					mali_ptr payload, int job_no)
{
	const struct mali_payload_fragment *PANWRAP_PTR_VAR(s, mem, payload);

	uintptr_t p = (uintptr_t) s->fbd & FBD_MASK;
	struct panwrap_mapped_memory *fbd_map = panwrap_find_mapped_mem_containing((void *) p);

	panwrap_log("struct mali_payload_fragment fragment_%d = {\n", job_no);
	panwrap_indent++;

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

static void panwrap_decode_fragment_job(const struct panwrap_mapped_memory *mem,
					mali_ptr payload)
{
	const struct mali_payload_fragment *PANWRAP_PTR_VAR(f, mem, payload);

	panwrap_log("Coordinates:\n");
	panwrap_indent++;
	panwrap_log("Min: %02dx%02d (flags: 0x%08" PRIx32 ")\n",
		    MALI_TILE_COORD_X(f->_min_tile_coord),
		    MALI_TILE_COORD_Y(f->_min_tile_coord),
		    MALI_TILE_COORD_FLAGS(f->_min_tile_coord));
	panwrap_log("Max: %02dx%02d (flags: 0x%08" PRIx32 ")\n",
		    MALI_TILE_COORD_X(f->_max_tile_coord),
		    MALI_TILE_COORD_Y(f->_max_tile_coord),
		    MALI_TILE_COORD_FLAGS(f->_max_tile_coord));
	panwrap_indent--;

	panwrap_trace_fbd(mem, &f->fbd);
}

void panwrap_trace_hw_chain(mali_ptr jc_gpu_va)
{
	struct panwrap_mapped_memory *mem =
		panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);
	struct mali_job_descriptor_header *h;

	do {
		mali_ptr payload_ptr = jc_gpu_va + sizeof(*h);
		void *payload;

		h = PANWRAP_PTR(mem, jc_gpu_va, typeof(*h));
		payload = panwrap_fetch_gpu_mem(mem, payload_ptr,
						MALI_PAYLOAD_SIZE);

		panwrap_log("%s job, %d-bit, status %X, incomplete %X\n",
			    panwrap_job_type_name(h->job_type),
			    h->job_descriptor_size ? 64 : 32,
			    h->exception_status,
			    h->first_incomplete_task);
		panwrap_log("fault %" PRIX64 ", barrier %d, index %hX\n",
			    h->fault_pointer,
			    h->job_barrier,
			    h->job_index);
		panwrap_log("dependencies (%hX, %hX)\n",
			    h->job_dependency_index_1,
			    h->job_dependency_index_2);

		panwrap_indent++;

		panwrap_log("Raw payload:\n");
		panwrap_indent++;
		panwrap_log_hexdump(payload, MALI_PAYLOAD_SIZE);
		panwrap_indent--;

		switch (h->job_type) {
		case JOB_TYPE_SET_VALUE:
			{
				struct mali_payload_set_value *s = payload;

				panwrap_log("set value -> %" PRIX64 " (%" PRIX64 ")\n",
					    s->out, s->unknown);
				break;
			}
		case JOB_TYPE_TILER:
		case JOB_TYPE_VERTEX:
			panwrap_decode_vertex_or_tiler_job(h, mem, payload_ptr);
			break;
		case JOB_TYPE_FRAGMENT:
			panwrap_decode_fragment_job(mem, payload_ptr);
			break;
		default:
			break;
		}

		panwrap_indent--;
	} while ((jc_gpu_va = h->next_job));
}

static int job_descriptor_number = 0;

void panwrap_replay_jc(mali_ptr jc_gpu_va)
{
	struct mali_job_descriptor_header *h;

	do {
		struct panwrap_mapped_memory *mem =
			panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);

		mali_ptr payload_ptr = jc_gpu_va + sizeof(*h);
		void *payload;

		h = PANWRAP_PTR(mem, jc_gpu_va, typeof(*h));
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

		char *a = pointer_as_memory_reference(h->next_job);
		panwrap_prop("next_job = %s", a);
		free(a);

		panwrap_indent--;
		panwrap_log("};\n");

		/* Touch the fields */
		TOUCH(mem, jc_gpu_va, *h, "job", job_no);

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
	} while ((jc_gpu_va = ((u64) (uintptr_t) h->next_job) & (((u64)1<<55) - 1)));
}

void panwrap_replay_soft_replay_payload(mali_ptr jc_gpu_va, int job_no)
{
	struct mali_jd_replay_payload *v;

	struct panwrap_mapped_memory *mem =
		panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);

	v = PANWRAP_PTR(mem, jc_gpu_va, typeof(*v));

	panwrap_log("struct mali_jd_replay_payload soft_replay_payload_%d = {\n", job_no);
	panwrap_indent++;

	MEMORY_PROP(tiler_jc_list);
	MEMORY_PROP(fragment_jc);
	MEMORY_PROP(tiler_heap_free);

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

		MEMORY_PROP(next);
		MEMORY_PROP(jc);

		panwrap_indent--;
		panwrap_log("};\n");

		panwrap_replay_soft_replay_payload(jc_gpu_va + sizeof(struct mali_jd_replay_jc), job_no);

		TOUCH(mem, jc_gpu_va, *v, "soft_replay", job_no);
	} while ((jc_gpu_va = v->next));
}
