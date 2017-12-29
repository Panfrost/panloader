This is a job-based architecture. All interesting behaviour (shaders,
rendering) is a result of jobs. Each job is sent from the driver across
the shim to the GPU. The job is encoded as a special data structure in
GPU memory.

There are two families of jobs, hardware jobs and software jobs.
Hardware jobs interact with the GPU directly. Software jobs are used to
manipulate the driver. Software jobs set BASE_JD_REQ_SOFT_JOB in the
.core_req field of the atom.

Hardware jobs contain the jc pointer into GPU memory. This points to the
job descriptor. All hardware jobs begin with the job descriptor header
which is found in the shim headers. The header contains a field,
job_type, which must be set according to the job type:

Byte  | Job type
----- | ---------
0     | Not started
1     | Null
2     | Set value
3     | Cache flush
4     | Compute
5     | Vertex
6     | (none)
7     | Tiler
8     | Fused
9     | Fragment

This header contains a pointer to the next job, forming sequences of
hardware jobs.

The header also denotes the type of job (vertex, fragment, or tiler).
After the header there is simple type specific information.

Set value jobs follow:

	struct tentative_set_value {
		uint64_t write_iut; /* Maybe vertices or shader? */
		uint64_t unknown1; /* Trace has it set at 3 */
	}


Fragment jobs follow:

	struct tentative_fragment {
		tile_coord_t min_tile_coord;
		tile_coord_t max_tile_coord;
		uint64_t fragment_fbd;
	};

tile_coord_t is an ordered pair for specifying a tile. It is encoded as
a uint32_t where bits 0-11 represent the X coordinate and bits 16-27
represent the Y coordinate.

Tiles are 16x16 pixels. This can be concluded from max_tile_coord in
known render sizes.

Fragment jobs contain an external resource, the framebuffer (in shared
memory / UMM). The framebuffer is in BGRA8888 format.

Vertex and tiler jobs follow the same structure (pointers are 32-bit to
GPU memory):

	struct tentative_vertex_tiler {
		uint32_t block1[11];
		uint32_t addresses1[4];
		tentative_shader *shaderMeta;
		attribute_buffer *vb[];
		attribute_meta_t *attribute_meta[];
		uint32_t addresses2[5];
		tentative_fbd *fbd;
		uint32_t addresses3[1];
		uint32_t block2[36];
	}

In tiler jobs, block1[8] encodes the drawing mode used:

Byte  | Mode
----- | -----
0x01  | GL_POINTS
0x02  | GL_LINES
0x08  | GL_TRIANGLES
0x0A  | GL_TRIANGLE_STRIP
0x0C  | GL_TRIANGLE_FAN

The shader metadata follows a (very indirect) structure:

	struct tentative_shader {
		uint64_t shader; /* ORed with 16 bytes of flags */
		uint32_t block[unknown];
	}

Shader points directly to the compiled instruction stream. For vertex
jobs, this is the vertex shader. For tiler jobs, this is the fragment
shader.

Shaders are 128-bit aligned. The lower 128-bits of the shader metadata
pointer contains flags. Bit 0 is set for all shaders. Bit 2 is set for
vertex shaders. Bit 3 is set for fragment shaders.

The attribute buffers encode each attribute (like vertex data) specified
in the shader.

	struct attribute_buffer {
		float *elements;
		size_t element_size; /* sizeof(*elements) * component_count */
		size_t total_size; /* element_size * num_vertices */
	}

The attribute buffers themselves have metadata in attribute_meta_t,
which is a uint64_t internally. The lowest byte of attribute_meta_t is
the corresponding attribute number. The rest appears to be flags
(0x2DEA2200). After the final attribute, the metadata will be zero,
acting as a null terminator for the attribute list.
