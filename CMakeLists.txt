cmake_minimum_required(VERSION 3.5)
include(CheckCSourceCompiles)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions("-Werror-implicit-function-declaration")

macro(c_attribute_required attrname code)
    if (NOT DEFINED ATTRIBUTE_${attrname}_SUPPORT OR
        NOT ATTRIBUTE_${attrname}_SUPPORT)

        message(STATUS "Checking if compiler supports __attribute__((${attrname}))")
        check_c_source_compiles("${code}" ATTRIBUTE_${attrname}_SUPPORT)
        if (NOT ATTRIBUTE_${attrname}_SUPPORT)
            message(FATAL_ERROR "Compiler must support __attribute__((${attrname}))")
        endif()
    endif()
endmacro()

c_attribute_required(packed "struct s { int a; } __attribute__((packed)); main;")
c_attribute_required(constructor "void __attribute__((constructor)) f(){}main;")
c_attribute_required(format
    "void __attribute__((format (printf, 1, 2))) f(const char *, ...);main;")

include_directories("include")
add_subdirectory(src)
add_subdirectory(panwrap)

# vim: tabstop=4 softtabstop=4 shiftwidth=4 expandtab :
