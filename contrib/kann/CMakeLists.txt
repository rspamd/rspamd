SET(LIBKANNSRC	kautodiff.c kann.c)

IF(ENABLE_STATIC MATCHES "ON")
	ADD_LIBRARY(rspamd-kann STATIC ${LIBKANNSRC})
ELSE()
	ADD_LIBRARY(rspamd-kann SHARED ${LIBKANNSRC})
ENDIF()

target_link_libraries(rspamd-kann "${RSPAMD_REQUIRED_LIBRARIES}")
target_link_libraries(rspamd-kann "m")
IF(WITH_BLAS)
    MESSAGE(STATUS "Use openblas to accelerate kann")
    TARGET_LINK_LIBRARIES(rspamd-kann ${BLAS_REQUIRED_LIBRARIES})
ENDIF(WITH_BLAS)

INSTALL(TARGETS rspamd-kann LIBRARY DESTINATION ${RSPAMD_LIBDIR})