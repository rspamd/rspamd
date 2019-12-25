SET(AHOCORASICSRC	acism_create.c
					acism.c)

IF(NOT GPL_RSPAMD_BINARY)
	ADD_LIBRARY(rspamd-actrie SHARED ${AHOCORASICSRC})
	target_link_libraries(rspamd-actrie glib-2.0)

	INSTALL(TARGETS rspamd-actrie
			LIBRARY DESTINATION ${RSPAMD_LIBDIR})
ELSE()
	ADD_LIBRARY(rspamd-actrie STATIC ${AHOCORASICSRC})
	target_link_libraries(rspamd-actrie glib-2.0)
ENDIF()
