/*
 * © Copyright 2017 Cafe Beverage. All rights reserved.
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

#include "panwrap.h"
#include <mali-ioctl.h>
#include <mali-job.h>

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
	struct mali_attr *attr =
		panwrap_deref_gpu_mem(mem, addr, sizeof(*attr));
	float *buffer = panwrap_deref_gpu_mem(
	    mem, attr->elements_upper << 2, attr->size);
	size_t vertex_count;
	size_t component_count;

	vertex_count = attr->size / attr->stride;
	component_count = attr->stride / sizeof(float);

	panwrap_log(MALI_PTR_FORMAT " (%x):\n",
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
			      mali_ptr fbd_upper, enum mali_fbd_type type,
			      u8 flags)
{
	mali_ptr fbd_ptr = fbd_upper << 6;
	struct mali_tentative_mfbd *mfbd =
		PANWRAP_PTR(mem, fbd_ptr, typeof(*mfbd));

	panwrap_log("%s @ " MALI_PTR_FORMAT ":\n",
		    panwrap_decode_fbd_type(type), fbd_ptr);
	panwrap_indent++;

	/* XXX We're not entirely sure which parts of the fbd format that we
	 * have so far are and aren't correct, so do a hexdump so we can catch
	 * errors more easily
	 */
	panwrap_log("Raw fbd:\n");
	panwrap_indent++;
	panwrap_log_hexdump(mfbd, sizeof(*mfbd));
	panwrap_indent--;

	panwrap_log("Flags: 0x%x\n", mfbd->flags);
	panwrap_log("Heap free address: " MALI_PTR_FORMAT "\n",
		    mfbd->heap_free_address);

	panwrap_log("Block #1:\n");
	panwrap_indent++;
	panwrap_log_hexdump(mfbd->block1, sizeof(mfbd->block1));
	panwrap_indent--;

	panwrap_log("Unknown #2:\n");
	panwrap_indent++;
	if (mfbd->unknown2)
		panwrap_log_hexdump(panwrap_deref_gpu_mem(mem, mfbd->unknown2, 64),
				    64);
	else
		panwrap_log("<none>\n");
	panwrap_indent--;

	/*panwrap_log("ugan */
	if (mfbd->unknown_gpu_addressN) {

	}

	/* XXX: Cafe was asserting zeroes here in block2[0] and block2[1] (in
	 * our version since we use u8, this would be block2[8] for 64bit or
	 * block2[4] for 32bit. It's probable that there's some sort of data
	 * here sometimes
	 */
	panwrap_log("Block #2:\n");
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

	panwrap_log("ugaT " MALI_PTR_FORMAT ", uga " MALI_PTR_FORMAT "\n",
		    mfbd->ugaT, mfbd->unknown_gpu_address);
	panwrap_log("ugan " MALI_PTR_FORMAT "\n",
		    mfbd->unknown_gpu_addressN);

	panwrap_indent++;
	if (mfbd->unknown_gpu_addressN) {
		panwrap_log_hexdump_trimmed(
		    panwrap_deref_gpu_mem(NULL, mfbd->unknown_gpu_addressN,
					  64),
		    64);
	} else {
		panwrap_log("<none>\n");
	}
	panwrap_indent--;

	panwrap_log("blah = " MALI_PTR_FORMAT "\n", mfbd->blah);
	panwrap_log("unk1 = %" PRIx32 " unk2 = %" PRIx64 " unk3 = %" PRIx64 "\n",
		    mfbd->unknown1, mfbd->unknown2, mfbd->unknown3);

	panwrap_log("Weights = [ ");
	for (int i = 0; i < ARRAY_SIZE(mfbd->weights); i++) {
		panwrap_log_cont("%" PRIx32, mfbd->weights[i]);
		if (i + 1 < ARRAY_SIZE(mfbd->weights))
			panwrap_log_cont(", ");
	}
	panwrap_log_cont(" ]\n");

	panwrap_indent--;
}

void panwrap_decode_vertex_or_tiler_job(const struct mali_job_descriptor_header *h,
					const struct panwrap_mapped_memory *mem,
					mali_ptr payload)
{
	struct mali_payload_vertex_tiler *v =
		PANWRAP_PTR(mem, payload, typeof(*v));
	struct mali_shader_meta *meta;
	struct panwrap_mapped_memory *attr_mem;
	struct mali_attr_meta *attr_meta;
	mali_ptr meta_ptr = v->_shader_upper << 4;
	mali_ptr p;

	/* From chai, no idea what this is for */
	if ((meta_ptr & 0xFFF00000) == 0x5AB00000) {
		panwrap_log("Job sabotaged\n");
	}

	attr_mem = panwrap_find_mapped_gpu_mem_containing(v->attribute_meta);

	panwrap_log("%s shader @ " MALI_PTR_FORMAT " (flags 0x%x)\n",
		    h->job_type == JOB_TYPE_VERTEX ? "Vertex" : "Fragment",
		    meta_ptr, v->flags);

	panwrap_indent++;

	panwrap_log("Block #1:\n");
	panwrap_indent++;
	panwrap_log_hexdump(v->block1, sizeof(v->block1));
	panwrap_indent--;

	if (meta_ptr) {
		meta = panwrap_deref_gpu_mem(NULL, meta_ptr, sizeof(*meta));

		panwrap_log("Shader blob: @ " MALI_PTR_FORMAT "\n", meta_ptr);
		panwrap_indent++;
		panwrap_log_hexdump(
		    panwrap_deref_gpu_mem(NULL, meta->shader, 832), 832);
		panwrap_indent--;
	} else
		panwrap_log("<no shader>\n");

	if (v->attribute_meta) {
		panwrap_log("Attribute list:\n");
		panwrap_indent++;
		for (p = v->attribute_meta;
		     *PANWRAP_PTR(attr_mem, p, u64) != 0;
		     p += sizeof(u64)) {
			attr_meta = panwrap_deref_gpu_mem(attr_mem, p,
							  sizeof(*attr_mem));

			panwrap_log("%x:\n", attr_meta->index);
			panwrap_indent++;

			panwrap_log("flags = 0x%014" PRIx64 "\n",
				    attr_meta->flags);
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

	if (h->job_type == JOB_TYPE_TILER) {
		panwrap_log("GL draw mode: %s\n",
			    panwrap_gl_mode_name(
				*PANWRAP_PTR(attr_mem, v->block1[8], u8)));
	}

	/* TODO: Rename appropriately */
	panwrap_log("nulls: " MALI_PTR_FORMAT ", " MALI_PTR_FORMAT ", " MALI_PTR_FORMAT ", " MALI_PTR_FORMAT "\n",
		    v->null0, v->null1, v->null2, v->null4);

	/* FIXME: cafe had some sort of hex dump thingy here that seemed to
	 * dump some unknown structures but for the life of me I cannot figure
	 * out what the heck it does very easily. Unfortunately, the comments
	 * on said code do not clarify much. If we're missing something, this
	 * might be it.
	 */
	panwrap_trace_fbd(mem, v->_fbd_upper, v->fbd_type, v->fbd_flags);

	panwrap_indent--;
}

void panwrap_trace_hw_chain(mali_ptr jc_gpu_va)
{
	struct panwrap_mapped_memory *mem =
		panwrap_find_mapped_gpu_mem_containing(jc_gpu_va);
	struct mali_job_descriptor_header *h =
		panwrap_deref_gpu_mem(mem, jc_gpu_va, sizeof(*h));
	mali_ptr payload = jc_gpu_va + sizeof(*h);

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
	panwrap_log_hexdump(panwrap_deref_gpu_mem(mem, payload, 256), 256);
	panwrap_indent--;

	switch (h->job_type) {
	case JOB_TYPE_SET_VALUE:
		{
			struct mali_payload_set_value *s =
				panwrap_deref_gpu_mem(mem, payload, sizeof(*s));

			panwrap_log("set value -> %" PRIX64 " (%" PRIX64 ")\n",
				    s->out, s->unknown);
			break;
		}
	case JOB_TYPE_TILER:
	case JOB_TYPE_VERTEX:
		panwrap_decode_vertex_or_tiler_job(h, mem, payload);
		break;
	default:
		break;
	}

	panwrap_indent--;
}
