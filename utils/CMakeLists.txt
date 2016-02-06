SET(UTILSERVERSRC rspamd_http_server.c)
SET(UTILBENCHSRC rspamd_http_bench.c)

#ADD_EXECUTABLE(rspamd-http-server ${UTILSERVERSRC})
#SET_TARGET_PROPERTIES(rspamd-http-server PROPERTIES LINKER_LANGUAGE C)
#TARGET_LINK_LIBRARIES(rspamd-http-server rspamd-server)
#TARGET_LINK_LIBRARIES(rspamd-http-server rspamd-http-parser)
#TARGET_LINK_LIBRARIES(rspamd-http-server ${RSPAMD_REQUIRED_LIBRARIES})

#ADD_EXECUTABLE(rspamd-http-bench ${UTILBENCHSRC})
#SET_TARGET_PROPERTIES(rspamd-http-bench PROPERTIES LINKER_LANGUAGE C)
#TARGET_LINK_LIBRARIES(rspamd-http-bench rspamd-server)
#TARGET_LINK_LIBRARIES(rspamd-http-bench rspamd-http-parser)
#TARGET_LINK_LIBRARIES(rspamd-http-bench ${RSPAMD_REQUIRED_LIBRARIES})

# Redirector
IF (ENABLE_REDIRECTOR MATCHES "ON")
    CONFIGURE_FILE(redirector.pl.in redirector.pl @ONLY)
    INSTALL(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/redirector.pl"
            DESTINATION bin RENAME rspamd-redirector)
ENDIF (ENABLE_REDIRECTOR MATCHES "ON")