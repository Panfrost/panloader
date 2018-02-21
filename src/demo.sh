gcc sample.c pandev.c slow-framebuffer.c -I../include -I../build/include -I. -lm -ldl -lpthread -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE=1 -lX11
