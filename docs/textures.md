Comparing a simple triangle sample with a texture mapped sample, the
following differences appear between the fragment jobs:

- Different shaders (obviously)
- Texture mapped attributes aren't decoding at all (vec5?)
- Null tripped!

null1: B291E720
null2: B291E700

(null 3 is still NULL)

Notice that these are both SAME_VA addresses 32 bytes apart.

null1 contains texture metadata. In this case, the 0x20 buffer is:

23 00 00 00  00 00 01 00  88 e8 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00

null2 contains a(nother) list of addresses, like how attributes are
encoded. In this case, the buffer is:

c0 81 02 02  01 00 00 00  00 00 00 00  00 00 00 00
00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00

It appears null1 is a zero-terminated array of metadata and null2 is the
corresponding zero-terminated array of textures themselves.

- Different uniforms (understandable)
- Shader metadata is different:

No texture map: 00 00 00 00  00 00 08 00  02 06 22 00
        ^ mask: 01 00 01 00  00 00 0F 00  00 08 20 00
Texture mapped: 01 00 01 00  00 00 07 00  02 0e 02 00

- Addr[8] is a little different, but not necessarily related

- Addr[9] is one byte different (ditto)
