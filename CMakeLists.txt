cmake_minimum_required(VERSION 3.5)
include(CheckCSourceCompiles)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

message(STATUS "Checking if compiler supports __attribute__((packed))")
check_c_source_compiles("struct s { int a; } __attribute__((packed)); main;"
                        ATTRIBUTE_PACKED_SUPPORT)
if (NOT ATTRIBUTE_PACKED_SUPPORT)
    message(FATAL_ERROR "Compiler must support __attribute__((packed))")
endif()

include_directories("include")
add_subdirectory(src)
add_subdirectory(panwrap)

# vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab :
