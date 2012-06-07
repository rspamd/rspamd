# Json support makefile
SET(JSONSRC				dump.c
						hashtable.c
						load.c
						strbuffer.c
						utf.c
						value.c)

ADD_LIBRARY(rspamd-json ${LINK_TYPE} ${JSONSRC})
TARGET_LINK_LIBRARIES(rspamd-json rspamd-util)
SET_TARGET_PROPERTIES(rspamd-json PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(rspamd-json PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
INSTALL(TARGETS rspamd-json 
    LIBRARY DESTINATION ${LIBDIR} 
    PUBLIC_HEADER DESTINATION ${INCLUDEDIR}
    ARCHIVE DESTINATION ${LIBDIR})
