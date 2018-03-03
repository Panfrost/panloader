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

#ifndef __MALI_JOB_H__
#define __MALI_JOB_H__

#include <config.h>
#include <mali-ioctl.h>

#define MALI_SHORT_PTR_BITS (sizeof(uintptr_t)*8)

#define MALI_FBD_HIERARCHY_WEIGHTS 8

#define MALI_PAYLOAD_SIZE 256

enum mali_job_type {
	JOB_NOT_STARTED	= 0,
	JOB_TYPE_NULL = 1,
	JOB_TYPE_SET_VALUE = 2,
	JOB_TYPE_CACHE_FLUSH = 3,
	JOB_TYPE_COMPUTE = 4,
	JOB_TYPE_VERTEX = 5,
	JOB_TYPE_TILER = 7,
	JOB_TYPE_FUSED = 8,
	JOB_TYPE_FRAGMENT = 9,
};

enum mali_gl_mode {
	MALI_GL_POINTS         = 0x1,
	MALI_GL_LINES          = 0x2,
	MALI_GL_LINE_STRIP     = 0x4,
	MALI_GL_LINE_LOOP      = 0x6,
	MALI_GL_TRIANGLES      = 0x8,
	MALI_GL_TRIANGLE_STRIP = 0xA,
	MALI_GL_TRIANGLE_FAN   = 0xC,
};

/* TODO: Where are the other values? Goes with glState */
#define MALI_GL_CULL_FACE 0x80

/* TODO: Might this actually be a finer bitfield? */
#define MALI_DEPTH_STENCIL_ENABLE 0x6400

#define DS_ENABLE(field) \
	(field == MALI_DEPTH_STENCIL_ENABLE) \
	? "MALI_DEPTH_STENCIL_ENABLE" \
	: (field == 0) ? "0" \
	: "0 /* XXX: Unknown, check hexdump */"

struct mali_shader_meta {
	mali_ptr shader;
	u32 zero;

	/* TODO: Does this consider size? */
	u16 attribute_count;

	/* Zero for no attributes, small non-zero for attributes, it appears */
	u16 unknown1;

	/* Format here is very weird and only partially understood, but in a 32-bit hex word:
	 * .XX..... is the known format, where X is the whole number of uniform
	 * registers used, times two. The other bits are unknown but nonzero.
	 */

	u32 uniform_registers;
};

/* This only concerns hardware jobs */

/* Possible values for job_descriptor_size */

#define MALI_JOB_32 0
#define MALI_JOB_64 1

struct mali_job_descriptor_header {
	u32 exception_status;
	u32 first_incomplete_task;
	u64 fault_pointer;
	u8 job_descriptor_size : 1;
	enum mali_job_type job_type : 7;
	u8 job_barrier : 1;
	u8 unknown_flags : 7;
	u16 job_index;
	u16 job_dependency_index_1;
	u16 job_dependency_index_2;
	mali_ptr next_job;
} __attribute__((packed));

struct mali_payload_set_value {
	u64 out;
	u64 unknown;
} __attribute__((packed));

struct mali_attr {
	mali_ptr elements;
	u32 stride;
	u32 size;
} __attribute__((packed));

struct mali_attr_meta {
	u8 index;
	u64 flags :56;
} __attribute__((packed));
ASSERT_SIZEOF_TYPE(struct mali_attr_meta,
		   sizeof(u64), sizeof(u64));

enum mali_fbd_type {
	MALI_SFBD = 0,
	MALI_MFBD = 1,
};

#define FBD_TYPE (1)
#define FBD_MASK (~0x3f)

struct mali_payload_vertex_tiler {
	/* Off by one */
	u32 vertex_count; 

	u32 unk1; // 0x28000000
	u32 draw_mode; 
	u32 zero0;
	u32 zero1;

	/* Like many other strictly nonzero quantities, index_count is
	 * subtracted by one. For an indexed cube, this is equal to 35 = 6
	 * faces * 2 triangles/per face * 3 vertices/per triangle - 1. For
	 * non-indexed draws, equal to vertex_count. */

	u32 index_count;

	/* No hidden structure; literally just a pointer to an array of
	 * uint32_t indeices. Thanks, guys, for not making my life insane for
	 * once! NULL for non-indexed draws. */

	uintptr_t indices;

	u32 zero3;
	u32 gl_enables; // 0x5
	u32 zero4;

	u32 zero5;
	uintptr_t unknown0;
	uintptr_t unknown1; /* pointer */

	/* For reasons I don't quite understand this is a pointer to a pointer.
	 * That second pointer points to the actual texture descriptor. */
	uintptr_t texture_meta_trampoline;

	/* For OpenGL, from what I've seen, this is intimately connected to
	 * texture_meta. cwabbott says this is not the case under Vulkan, hence
	 * why this field is seperate (Midgard is Vulkan capable) */
	uintptr_t sampler_descriptor;

	uintptr_t uniforms;
	u8 flags : 4;
	uintptr_t _shader_upper : MALI_SHORT_PTR_BITS - 4; /* struct shader_meta */
	uintptr_t attributes; /* struct attribute_buffer[] */
	uintptr_t attribute_meta; /* attribute_meta[] */
	uintptr_t varyings; /* struct attr */
	uintptr_t unknown6; /* pointer */
	uintptr_t nullForVertex;
	u32 zero6;
	u64 fbd;
} __attribute__((packed));
//ASSERT_SIZEOF_TYPE(struct mali_payload_vertex_tiler, 256, 256);

/* Pointed to from texture_meta_trampoline, mostly unknown still, haven't
 * managed to replay successfully */

/* Purposeful off-by-one in width, height fields. For example, a (64, 64)
 * texture is stored as (63, 63) in these fields. This adjusts for that.
 * There's an identical pattern in the framebuffer descriptor. */

#define MALI_DIMENSION(dim) (dim - 1)

struct mali_texture_descriptor {
	uint16_t width;
	uint16_t height;

	uint32_t unknown1;

	/* No idea on format1 and format2 */

	uint32_t format1;

	uint32_t unknown3;

	uint32_t format2;

	uint32_t unknown5;
	uint32_t unknown6;
	uint32_t unknown7;

	mali_ptr swizzled_bitmap_0;
	mali_ptr swizzled_bitmap_1;
} __attribute__((packed));

/* Used as part of filter_mode */

#define MALI_GL_LINEAR 0
#define MALI_GL_NEAREST 1

/* Used to construct low bits of filter_mode */

#define MALI_GL_TEX_MAG(mode) (((mode) & 1) << 0)
#define MALI_GL_TEX_MIN(mode) (((mode) & 1) << 1)

#define MALI_GL_TEX_MAG_MASK (1)
#define MALI_GL_TEX_MIN_MASK (2)

#define MALI_FILTER_NAME(filter) (filter ? "MALI_GL_NEAREST" : "MALI_GL_LINEAR")

struct mali_sampler_descriptor {
	uint32_t filter_mode;
	
	/* Apparently the same as one of the fields in texture_descriptor, so
	 * maybe it's how linkage is specified */
	uint32_t unknown1;

	uint32_t unknown2;
} __attribute__((packed));

/* TODO: What is this? In practice, it looks like { -inf, -inf, inf, inf, 0.0,
 * 1.0, }, followed by a hex thingy, and then zeroes, which suggests some kind
 * of bounds, perhaps mapping coordinate systems. But why only for tiler jobs?
 *
 * Might the two combine together into a single u64?
 *
 * width and height fields are equal to those in the associated framebuffer
 * descriptor, for some reason.
 */

struct nullForVertex {
	float floats[6];
	u32 zero0;

	u16 width;
	u16 height;
};

/* TODO: I have no idea what this could possibly be, whatsoever. */

struct mali_unknown6 {
	u64 unknown0;
	u64 unknown1;
};

/* From presentations, 16x16 tiles externally. Use shift for fast computation
 * of tile numbers. */

#define MALI_TILE_SHIFT 4
#define MALI_TILE_LENGTH (1 << MALI_TILE_SHIFT)

/* Tile coordinates are stored as a compact u32, as only 12 bits are needed to
 * each component. Notice that this provides a theoretical upper bound of (1 <<
 * 12) = 4096 tiles in each direction, addressing a maximum framebuffer of size
 * 65536x65536. Multiplying that together, times another four given that Mali
 * framebuffers are 32-bit ARGB8888, means that this upper bound would take 16
 * gigabytes of RAM just to store the uncompressed framebuffer itself, let
 * alone rendering in real-time to such a buffer.
 *
 * Nice job, guys.*/

/* From mali_kbase_10969_workaround.c */
#define MALI_X_COORD_MASK 0x00000FFF
#define MALI_Y_COORD_MASK 0x0FFF0000

/* Extract parts of a tile coordinate */

#define MALI_TILE_COORD_X(coord) ((coord) & MALI_X_COORD_MASK)
#define MALI_TILE_COORD_Y(coord) (((coord) & MALI_Y_COORD_MASK) >> 16)
#define MALI_TILE_COORD_FLAGS(coord) ((coord) & ~(MALI_X_COORD_MASK | MALI_Y_COORD_MASK))

/* No known flags yet, but just in case...? */

#define MALI_TILE_NO_FLAG (0)

/* Helpers to generate tile coordinates based on the boundary coordinates in
 * screen space. So, with the bounds (0, 0) to (128, 128) for the screen, these
 * functions would convert it to the bounding tiles (0, 0) to (7, 7).
 * Intentional "off-by-one"; finding the tile number is a form of fencepost
 * problem. */

#define MALI_MAKE_TILE_COORDS(X, Y, flag) ((X) | ((Y) << 16) | (flag))
#define MALI_BOUND_TO_TILE(B, bias) ((B - bias) >> MALI_TILE_SHIFT)
#define MALI_COORDINATE_TO_TILE(W, H, flag, bias) MALI_MAKE_TILE_COORDS(MALI_BOUND_TO_TILE(W, bias), MALI_BOUND_TO_TILE(H, bias), flag)
#define MALI_COORDINATE_TO_TILE_MIN(W, H, flag) MALI_COORDINATE_TO_TILE(W, H, flag, 0) 
#define MALI_COORDINATE_TO_TILE_MAX(W, H, flag) MALI_COORDINATE_TO_TILE(W, H, flag, 1)

struct mali_payload_fragment {
	/* XXX: we might be able to translate these into bitfields someday, but
	 * that will only be sensible if the mask of flags is limited to
	 * 0xF0000000 or 0x0000F000. If it's 0xF000F000, feel free to just
	 * remove this comment
	 */
	u32 _min_tile_coord;
	u32 _max_tile_coord;
	u64 fbd;
} __attribute__((packed));
//ASSERT_SIZEOF_TYPE(struct mali_payload_fragment, 12, 16);

/* (Single?) Framebuffer Descriptor */

struct mali_tentative_sfbd {
	u32 unknown1;
	u32 flags;
	u64 unknown_address_0;
	u64 zero1;
	u64 heap_free_address;

	u32 unknown2; // 0xB8..
	u32 unknown3; // 0x10..
	u32 zero2;

	/* Purposeful off-by-one in these fields should be accounted for by the
	 * MALI_DIMENSION macro */

	u16 width;
	u16 height;

	u32 zero3[4];

	u32 weights[8];

	/* Depth and stencil buffers are interleaved, it appears, as they are
	 * set to the same address in captures. Both fields set to zero if the
	 * buffer is not being cleared. Depending on GL_ENABLE magic, you might
	 * get a zero enable despite the buffer being present; that still is
	 * disabled. */

	mali_ptr depth_buffer; // not SAME_VA
	u64 depth_buffer_enable; 

	mali_ptr stencil_buffer; // not SAME_VA
	u64 stencil_buffer_enable; 

	u32 clear_color_1; // RGBA8888 from glClear, actually used by hardware
	u32 clear_color_2; // always equal, but unclear function?
	u32 clear_color_3; // always equal, but unclear function?
	u32 clear_color_4; // always equal, but unclear function?

	/* Set to zero if not cleared */

	float clear_depth_1; // float32, ditto
	float clear_depth_2; // float32, ditto
	float clear_depth_3; // float32, ditto
	float clear_depth_4; // float32, ditto

	u32 clear_stencil; // Exactly as it appears in OpenGL

	u32 zero6[7];

	u32 unknown8; // 0x02000000
	u32 unknown9; // 0x00000001

	u64 unknown_address_1; /* Pointing towards... a zero buffer? */
	u64 unknown_address_2;

	/* Determined by symmetry with the replay soft job, documented in the kernel */
	u64 tiler_jc_list;

	u64 unknown_address_4;

	/* More below this, maybe */
} __attribute__((packed));

/* Multi? Framebuffer Descriptor */

struct mali_tentative_mfbd {
	u64 blah; /* XXX: what the fuck is this? */
	/* This GPU address is unknown, except for the fact there's something
	 * executable here... */
	u64 ugaT;
	u32 block1[10];
	u32 unknown1;
	u32 flags;
	u8 block2[16];
	u64 heap_free_address;
	u64 unknown2;
	u32 weights[MALI_FBD_HIERARCHY_WEIGHTS];
	u64 unknown_gpu_addressN;
	u8 block3[88];
	u64 unknown_gpu_address;
	u64 unknown3;
	u8 block4[40];
} __attribute__((packed));

/* Originally from chai, which found it from mali_kase_reply.c */

#endif /* __MALI_JOB_H__ */
