cmake_minimum_required(VERSION 2.6)

set(SIPHASH_SRC siphash.c)
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif ()
add_library(siphash STATIC "${SIPHASH_SRC}")

add_executable(siphash-test EXCLUDE_FROM_ALL "siphash_test.c")
target_link_libraries(siphash-test siphash)
add_custom_target(check DEPENDS siphash-test)
add_custom_target(run-test COMMAND siphash-test DEPENDS siphash-test)
