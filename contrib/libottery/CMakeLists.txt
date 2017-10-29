SET(OTTERYSRC            chacha_merged.c
                         ottery.c
                         ottery_cpuinfo.c
                         ottery_entropy.c
                         ottery_global.c
                         chacha_cryptobox.c
                         aes_cryptobox.c)
ADD_LIBRARY(ottery STATIC ${OTTERYSRC})

SET(OTTERY_CFLAGS "-DBUILD_RSPAMD")
IF(ENABLE_FULL_DEBUG MATCHES "OFF")
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    SET(OTTERY_CFLAGS "${OTTERY_CFLAGS} -O3")
endif ()
ENDIF()
set_target_properties(ottery PROPERTIES COMPILE_FLAGS "${OTTERY_CFLAGS}")