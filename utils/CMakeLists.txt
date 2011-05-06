ADD_SUBDIRECTORY(statshow)

# Redirector
IF(ENABLE_REDIRECTOR MATCHES "ON")
    CONFIGURE_FILE(redirector.pl.in redirector.pl @ONLY)
	INSTALL(PROGRAMS redirector.pl DESTINATION bin RENAME rspamd-redirector)
ENDIF(ENABLE_REDIRECTOR MATCHES "ON")