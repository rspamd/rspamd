SET(LPEGSRC lpcap.c
        lpcode.c
        lpprint.c
        lptree.c
        lpvm.c)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    SET(LPEG_CFLAGS "${LPEG_CFLAGS} -O3")
endif ()

SET(LIB_TYPE STATIC)
ADD_LIBRARY(rspamd-lpeg ${LIB_TYPE} ${LPEGSRC})
set_target_properties(rspamd-lpeg PROPERTIES COMPILE_FLAGS "${LPEG_CFLAGS}")
