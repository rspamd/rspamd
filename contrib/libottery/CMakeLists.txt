SET(OTTERYSRC            chacha_merged.c
                         ottery.c
                         ottery_cpuinfo.c
                         ottery_entropy.c
                         ottery_global.c)
ADD_LIBRARY(ottery STATIC ${OTTERYSRC})
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	set_target_properties(ottery PROPERTIES COMPILER_FLAGS "-O3")
endif ()