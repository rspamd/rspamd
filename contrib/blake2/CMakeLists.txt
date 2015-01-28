cmake_minimum_required(VERSION 2.6)

set(BLAKE_SRC blake2b-ref.c)
add_library(blake2 STATIC "${BLAKE_SRC}")
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	set_target_properties(blake2 PROPERTIES COMPILER_FLAGS "-O3")
endif ()
