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

#define MALI_SHORT_PTR_BITS (sizeof(mali_short_ptr)*8)

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
	MALI_GL_POINTS         = 0x01,
	MALI_GL_LINES          = 0x02,
	MALI_GL_TRIANGLES      = 0x08,
	MALI_GL_TRIANGLE_STRIP = 0x0A,
	MALI_GL_TRIANGLE_FAN   = 0x0C,
};

struct mali_shader_meta {
	mali_ptr shader;
	mali_ptr unknown1;
	mali_ptr unknown2;
};

/* FIXME: This might only concern fragment/vertex jobs? notes unclear */

struct mali_job_descriptor_header {
	u32 exception_status;
	u32 first_incomplete_task;
	u64 fault_pointer;
	u8 job_descriptor_size : 1;
	enum mali_job_type job_type : 7;
	u8 job_barrier : 1;
	u8 _reserved_01 : 1;
	u8 _reserved_1 : 1;
	u8 _reserved_02 : 1;
	u8 _reserved_03 : 1;
	u8 _reserved_2 : 1;
	u8 _reserved_04 : 1;
	u8 _reserved_05 : 1;
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
	u8 flags : 2;
	mali_ptr elements_upper : MALI_SHORT_PTR_BITS - 2;
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

/* TODO: using 32 bit datatypes is kind of awkward when you're just dealing
 * with binary data. Eventually remove all of them and replace them with proper
 * unsigned char types
 */
struct mali_payload_vertex_tiler {
	u32 block1[10];

	/* Lyude: no idea what the null's were supposed to represent here. */
	mali_short_ptr null0;
	mali_short_ptr unknown0;
	mali_short_ptr unknown1; /* pointer */
	mali_short_ptr texture_meta_address;
	mali_short_ptr texture_unknown;
	mali_short_ptr uniforms;
	u8 flags : 4;
	mali_short_ptr _shader_upper : MALI_SHORT_PTR_BITS - 4; /* struct shader_meta */
	mali_short_ptr attributes; /* struct attribute_buffer[] */
	mali_short_ptr attribute_meta; /* attribute_meta[] */
	mali_short_ptr unknown5; /* pointer */
	mali_short_ptr unknown6; /* pointer */
	mali_short_ptr nullForVertex;
	mali_short_ptr null4;
	u64 fbd;
	mali_short_ptr unknown7; /* pointer */

	u32 block2[36];
} __attribute__((packed));
//ASSERT_SIZEOF_TYPE(struct mali_payload_vertex_tiler, 256, 256);

/* From mali_kbase_10969_workaround.c */
#define MALI_X_COORD_MASK 0x00000FFF
#define MALI_Y_COORD_MASK 0x0FFF0000
#define MALI_TILE_COORD_X(coord) ((coord) & MALI_X_COORD_MASK)
#define MALI_TILE_COORD_Y(coord) (((coord) & MALI_Y_COORD_MASK) >> 16)
#define MALI_TILE_COORD_FLAGS(coord) ((coord) & ~(MALI_X_COORD_MASK | MALI_Y_COORD_MASK))

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

/* FBD: Fragment B[unknown] D[escriptor?]
 */
struct mali_tentative_sfbd {
	u32 unknown1;
	u32 flags;
	u64 shader_1;
	u64 zero1;
	u64 heap_free_address;

	u32 unknown2; // 0xB8..
	u32 unknown3; // 0x10..
	u32 zero2;
	u32 unknown4; // 0x00EF...
	u32 zero3[4];

	u32 weights[8];

	u32 zero5[8];

	u32 clear_color_1; // RGBA8888 from glClear, actually used by hardware
	u32 clear_color_2; // always equal, but unclear function?
	u32 clear_color_3; // always equal, but unclear function?
	u32 clear_color_4; // always equal, but unclear function?

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

	u64 shader_3;
	u64 shader_4;

	/* More below this, maybe */
} __attribute__((packed));

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
