# Librspamd mime
SET(LIBRSPAMDMIMESRC
		${CMAKE_CURRENT_SOURCE_DIR}/received.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/email_addr.c
				${CMAKE_CURRENT_SOURCE_DIR}/mime_expressions.c
        ${CMAKE_CURRENT_SOURCE_DIR}/scan_result.c
				${CMAKE_CURRENT_SOURCE_DIR}/images.c
				${CMAKE_CURRENT_SOURCE_DIR}/message.c
				${CMAKE_CURRENT_SOURCE_DIR}/archives.c
				${CMAKE_CURRENT_SOURCE_DIR}/content_type.c
				${CMAKE_CURRENT_SOURCE_DIR}/mime_headers.c
				${CMAKE_CURRENT_SOURCE_DIR}/mime_parser.c
				${CMAKE_CURRENT_SOURCE_DIR}/mime_encoding.c
				${CMAKE_CURRENT_SOURCE_DIR}/lang_detection.c
		${CMAKE_CURRENT_SOURCE_DIR}/mime_string.cxx
		)

SET(RSPAMD_MIME ${LIBRSPAMDMIMESRC} PARENT_SCOPE)