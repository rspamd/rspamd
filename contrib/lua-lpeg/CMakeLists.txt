SET(LPEGSRC lpcap.c
        lpcode.c
        lpprint.c
        lptree.c
        lpvm.c)

SET(LIB_TYPE STATIC)
ADD_LIBRARY(rspamd-lpeg ${LIB_TYPE} ${LPEGSRC})
set_target_properties(rspamd-lpeg PROPERTIES COMPILE_FLAGS "${LPEG_CFLAGS}")
