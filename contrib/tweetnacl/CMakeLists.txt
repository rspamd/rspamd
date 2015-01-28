cmake_minimum_required(VERSION 2.6)

set(NACL_SRC tweetnacl.c)

add_library(tweetnacl STATIC "${NACL_SRC}")
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	set_target_properties(tweetnacl PROPERTIES COMPILER_FLAGS "-O3")
endif ()