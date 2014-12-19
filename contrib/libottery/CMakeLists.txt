SET(OTTERYSRC            chacha_merged.c
                         ottery.c
                         ottery_cpuinfo.c
                         ottery_entropy.c
                         ottery_global.c)
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif ()
ADD_LIBRARY(ottery STATIC ${OTTERYSRC})  