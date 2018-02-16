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

extern char* replace_fragment;
extern char* replace_vertex;

static char *panwrap_job_type_name(enum mali_job_type type)
{
#define DEFINE_CASE(name) case JOB_TYPE_ ## name: return #name
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
#define DEFINE_CASE(name) case MALI_ ## name: return #name
	switch(mode) {
	DEFINE_CASE(GL_POINTS);
	DEFINE_CASE(GL_LINES);
	DEFINE_CASE(GL_TRIANGLES);
	DEFINE_CASE(GL_TRIANGLE_STRIP);
	DEFINE_CASE(GL_TRIANGLE_FAN);
	default: return "!!! GL_UNKNOWN !!!";
	}
#undef DEFINE_CASE
}

static inline char *panwrap_decode_fbd_type(enum mali_fbd_type type)
{
	if (type == MALI_SFBD)      return "SFBD";
	else if (type == MALI_MFBD) return "MFBD";
	else return "WTF!?";
}

void panwrap_decode_attributes(const struct panwrap_mapped_memory *mem,
			       mali_ptr addr)
{
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

void panwrap_replay_vertex_or_tiler_job(const struct mali_job_descriptor_header *h,
					const struct panwrap_mapped_memory *mem,
					mali_ptr payload, int job_no)
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

		panwrap_log("Shader blob: @ " MALI_PTR_FMT " (@ " MALI_PTR_FMT ")\n",
			       	meta_ptr, meta->shader & ~7);
		panwrap_indent++;
		/*panwrap_log_hexdump(
		    panwrap_fetch_gpu_mem(NULL, meta->shader & ~7, 832), 832);*/
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

			panwrap_indent--;
		}
		panwrap_indent--;
	} else
		panwrap_log("<no attributes>\n");

	if (h->job_type == JOB_TYPE_TILER && v->block1[7]) {
		panwrap_log("GL draw mode: %s\n",
			    panwrap_gl_mode_name(
				*PANWRAP_PTR(attr_mem, v->block1[7], u8)));
	}

	if (v->uniforms) {
		/* XXX: How do we know how many to print? How do we know to use
		 * half-floats? */

		struct panwrap_mapped_memory *uniform_mem = panwrap_find_mapped_gpu_mem_containing(v->uniforms);

		panwrap_log("Uniforms: \n");
		panwrap_fetch_gpu_mem(uniform_mem, v->uniforms, 4 * sizeof(__fp16));
	}

	if (v->null0 || v->null4)
		panwrap_msg("Fragment/tiler null tripped;replay may be wrong\n");

	if (v->texture_meta_address || v->texture_unknown) {
		panwrap_log("Texture:");
		panwrap_indent++;
		panwrap_log("Meta address: " MALI_SHORT_PTR_FMT "\n", v->texture_meta_address);
		panwrap_log("Unknown address: " MALI_SHORT_PTR_FMT "\n", v->texture_unknown);
		panwrap_indent--;
	}

	//panwrap_trace_fbd(mem, &v->fbd);

	panwrap_indent--;
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

	panwrap_log("Block #1:\n");
	panwrap_indent++;
	panwrap_log_hexdump(v->block1, sizeof(v->block1));
	panwrap_indent--;

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

	panwrap_log("Block #2:\n");
	panwrap_indent++;
	panwrap_log_hexdump(v->block2, sizeof(v->block2));
	panwrap_indent--;

	if (h->job_type == JOB_TYPE_TILER && v->block1[7]) {
		panwrap_log("GL draw mode: %s\n",
			    panwrap_gl_mode_name(
				*PANWRAP_PTR(attr_mem, v->block1[7], u8)));
	}

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

	panwrap_log("nulls: " MALI_SHORT_PTR_FMT ", " MALI_SHORT_PTR_FMT "\n",
		    v->null0, v->null4);

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

static void panwrap_replay_sfbd(const struct panwrap_mapped_memory *mem, uint64_t gpu_va, int job_no)
{
	const struct mali_tentative_sfbd *PANWRAP_PTR_VAR(s, mem, (mali_ptr) gpu_va);

	panwrap_log("struct mali_tentative_sfbd fbd_%d = {\n", job_no);
	panwrap_indent++;

	panwrap_prop("unknown1 = 0x%" PRIx32, s->unknown1);
	panwrap_prop("flags = 0x%" PRIx32, s->flags);
	panwrap_prop("heap_free_address = 0x%" PRIx64, s->heap_free_address);
	panwrap_prop("unknown2 = 0x%" PRIx32, s->unknown2);
	panwrap_prop("unknown3 = 0x%" PRIx32, s->unknown3);
	panwrap_prop("unknown4 = 0x%" PRIx32, s->unknown4);

	panwrap_log(".weights = { ");
	panwrap_indent++;
	for (int i = 0; i < MALI_FBD_HIERARCHY_WEIGHTS; ++i)
		panwrap_log_cont("0x%" PRIx32 ", ", s->weights[i]);
	panwrap_indent--;
	panwrap_log_cont("},\n");

	panwrap_prop("pdcm_1_1 = " MALI_PTR_FMT, s->pdcm_1_1);
	panwrap_prop("pdcm_1_2 = 0x%" PRIx64, s->pdcm_1_2);
	panwrap_prop("pdcm_2_1 = " MALI_PTR_FMT, s->pdcm_1_1);
	panwrap_prop("pdcm_2_2 = 0x%" PRIx64, s->pdcm_1_2);

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

	panwrap_prop("shader_1 = 0x%" PRIx64, s->shader_1);

	panwrap_prop("unknown8 = 0x%" PRIx32, s->unknown8);
	panwrap_prop("unknown9 = 0x%" PRIx32, s->unknown9);

	panwrap_prop("shader_3 = 0x%" PRIx64, s->shader_3);
	panwrap_prop("shader_4 = 0x%" PRIx64, s->shader_4);

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

#define TILE_PROP(n, c, bias) \
	panwrap_prop("_" n "_tile_coord = MALI_COORDINATE_TO_TILE(%d, %d, %d)", \
			(MALI_TILE_COORD_X(c) + bias) << MALI_TILE_SHIFT, \
			(MALI_TILE_COORD_Y(c) + bias) << MALI_TILE_SHIFT, \
			MALI_TILE_COORD_FLAGS(c));

	TILE_PROP("min", s->_min_tile_coord, 0);
	TILE_PROP("max", s->_max_tile_coord, 1);

#undef TILE_PROP

	panwrap_prop("fbd = %s | MALI_%s", pointer_as_memory_reference(p), s->fbd & MALI_MFBD ? "MFBD" : "SFBD");
	panwrap_indent--;
	panwrap_log("};\n");
	TOUCH(mem, payload, *s, "fragment", job_no);

	if ((s->fbd & FBD_TYPE) == MALI_SFBD)
		panwrap_replay_sfbd(fbd_map, s->fbd & FBD_MASK, job_no);
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
	struct panwrap_mapped_memory *mem =
		panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);
	struct mali_job_descriptor_header *h;

	do {
		mali_ptr payload_ptr = jc_gpu_va + sizeof(*h);
		void *payload;

		h = PANWRAP_PTR(mem, jc_gpu_va, typeof(*h));
		payload = panwrap_fetch_gpu_mem(mem, payload_ptr,
						MALI_PAYLOAD_SIZE);

		int job_no = job_descriptor_number++;

		panwrap_log("struct mali_job_descriptor_header job_%d = {\n", job_no);
		panwrap_indent++;

		panwrap_prop("job_type = %d", h->job_type);
		panwrap_prop("job_descriptor_size = %d", h->job_descriptor_size);
		panwrap_prop("exception_status = %d", h->exception_status);
		panwrap_prop("first_incomplete_task = %d", h->first_incomplete_task);

		panwrap_prop("fault_pointer = 0x%" PRIx64, h->fault_pointer);
		panwrap_prop("job_barrier = %d", h->job_barrier);
		panwrap_prop("job_index = %d", h->job_index);

		panwrap_prop("job_dependency_index_1 = %d", h->job_dependency_index_1);
		panwrap_prop("job_dependency_index_1 = %d", h->job_dependency_index_2);

		panwrap_prop("next_job = " MALI_PTR_FMT, h->next_job);

		/* If any of these bits are set, then the replay is wrong... */
		if (h->_reserved_01 | h->_reserved_1 | h->_reserved_02
		  | h->_reserved_03 | h->_reserved_2 | h->_reserved_04
		  | h->_reserved_05) {
			panwrap_msg("XXX Reserved flag in job descriptor header set, replay may be wrong XXX");
		}

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
				//TOUCH(mem, payload_ptr, *s);

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
	} while ((jc_gpu_va = h->next_job));
}
