cmake_minimum_required(VERSION 2.6)

set(BLAKE_SRC blake2-ref.c)
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_C_FLAGS "-O3")
endif ()
add_library(blake2 STATIC "${BLAKE_SRC}")
