project(panwrap)

set(SRCS panwrap-syscall.c panwrap-util.c)

add_library(panwrap SHARED ${SRCS})
