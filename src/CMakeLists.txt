MACRO(_AddModulesForced MLIST)
# Generate unique string for this build
	SET(MODULES_C "${CMAKE_CURRENT_BINARY_DIR}/modules.c")
	FILE(WRITE "${MODULES_C}"
		"#include \"rspamd.h\"\n")

	# Handle even old cmake
	LIST(LENGTH ${MLIST} MLIST_COUNT)
	MATH(EXPR MLIST_MAX ${MLIST_COUNT}-1)

	FOREACH(MOD_IDX RANGE ${MLIST_MAX})
		LIST(GET ${MLIST} ${MOD_IDX} MOD)
		FILE(APPEND "${MODULES_C}" "extern module_t ${MOD}_module;\n")
	ENDFOREACH(MOD_IDX RANGE ${MLIST_MAX})

	FILE(APPEND "${MODULES_C}" "\n\nmodule_t *modules[] = {\n")

	FOREACH(MOD_IDX RANGE ${MLIST_MAX})
		LIST(GET ${MLIST} ${MOD_IDX} MOD)
		FILE(APPEND "${MODULES_C}" "&${MOD}_module,\n")
	ENDFOREACH(MOD_IDX RANGE ${MLIST_MAX})

	FILE(APPEND "${MODULES_C}" "NULL\n};\n")
ENDMACRO(_AddModulesForced MLIST)

MACRO(_AddWorkersForced WLIST)
	SET(WORKERS_C "${CMAKE_CURRENT_BINARY_DIR}/workers.c")
	FILE(WRITE "${WORKERS_C}"
		"#include \"rspamd.h\"\n")

	# Handle even old cmake
	LIST(LENGTH ${WLIST} WLIST_COUNT)
	MATH(EXPR WLIST_MAX ${WLIST_COUNT}-1)
	FOREACH(MOD_IDX RANGE ${WLIST_MAX})
		LIST(GET ${WLIST} ${MOD_IDX} WRK)
		FILE(APPEND "${WORKERS_C}" "extern worker_t ${WRK}_worker;\n")
	ENDFOREACH(MOD_IDX RANGE ${WLIST_MAX})

	FILE(APPEND "${WORKERS_C}" "\n\nworker_t *workers[] = {\n")

	FOREACH(MOD_IDX RANGE ${WLIST_MAX})
		LIST(GET ${WLIST} ${MOD_IDX} WRK)
		FILE(APPEND "${WORKERS_C}" "&${WRK}_worker,\n")
	ENDFOREACH(MOD_IDX RANGE ${WLIST_MAX})
	FILE(APPEND "${WORKERS_C}" "NULL\n};\n")
ENDMACRO(_AddWorkersForced WLIST)

MACRO(AddModules MLIST WLIST)
	_AddModulesForced(${MLIST})
	_AddWorkersForced(${WLIST})
	#IF(NOT EXISTS "modules.c")
	#	_AddModulesForced(${MLIST} ${WLIST})
	#ELSE(NOT EXISTS "modules.c")
	#	FILE(STRINGS "modules.c" FILE_ID_RAW REGEX "^/.*[a-zA-Z0-9]+.*/$")
	#	STRING(REGEX MATCH "[a-zA-Z0-9]+" FILE_ID "${FILE_ID_RAW}")
	#	IF(NOT FILE_ID STREQUAL MODULES_ID)
	#		MESSAGE("Regenerate modules info")
	#		_AddModulesForced(${MLIST} ${WLIST})
	#	ENDIF(NOT FILE_ID STREQUAL MODULES_ID)
	#ENDIF(NOT EXISTS "modules.c")
ENDMACRO(AddModules MLIST WLIST)

# Rspamd core components
IF (ENABLE_CLANG_PLUGIN MATCHES "ON")
	SET(CMAKE_C_FLAGS
			"${CMAKE_C_FLAGS} -Xclang -load -Xclang ${CMAKE_CURRENT_BINARY_DIR}/../clang-plugin/librspamd-clang${CMAKE_SHARED_LIBRARY_SUFFIX} -Xclang -add-plugin -Xclang rspamd-ast")
	IF(CLANG_EXTRA_PLUGINS_LIBS)
		FOREACH(_lib ${CLANG_EXTRA_PLUGINS_LIBS})
			SET(CMAKE_C_FLAGS
					"${CMAKE_C_FLAGS} -Xclang -load -Xclang ${_lib}")
			SET(CMAKE_CXX_FLAGS
					"${CMAKE_CXX_FLAGS} -Xclang -load -Xclang ${_lib}")
		ENDFOREACH()
	ENDIF()
	IF(CLANG_EXTRA_PLUGINS)
		FOREACH(_plug ${CLANG_EXTRA_PLUGINS})
			SET(CMAKE_C_FLAGS
					"${CMAKE_C_FLAGS} -Xclang -add-plugin -Xclang ${_plug}")
			SET(CMAKE_CXX_FLAGS
					"${CMAKE_C_FLAGS} -Xclang -add-plugin -Xclang ${_plug}")
		ENDFOREACH()
	ENDIF()
ENDIF ()

ADD_SUBDIRECTORY(lua)
ADD_SUBDIRECTORY(libcryptobox)
ADD_SUBDIRECTORY(libutil)
ADD_SUBDIRECTORY(libserver)
ADD_SUBDIRECTORY(libmime)
ADD_SUBDIRECTORY(libstat)
ADD_SUBDIRECTORY(client)
ADD_SUBDIRECTORY(rspamadm)

SET(RSPAMDSRC	controller.c
				fuzzy_storage.c
				rspamd.c
				worker.c
				rspamd_proxy.c)

SET(PLUGINSSRC  plugins/regexp.c
				plugins/chartable.c
				plugins/fuzzy_check.c
				plugins/dkim_check.c
				libserver/rspamd_control.c)

SET(MODULES_LIST regexp chartable fuzzy_check dkim)
SET(WORKERS_LIST normal controller fuzzy rspamd_proxy)
IF (ENABLE_HYPERSCAN MATCHES "ON")
	LIST(APPEND WORKERS_LIST "hs_helper")
	LIST(APPEND RSPAMDSRC "hs_helper.c")
ENDIF()

AddModules(MODULES_LIST WORKERS_LIST)
LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)

SET(RAGEL_DEPENDS "${CMAKE_SOURCE_DIR}/src/ragel/smtp_address.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_date.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_ip.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_base.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/content_disposition.rl")
RAGEL_TARGET(ragel_smtp_addr
	INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/smtp_addr_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -T1
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/smtp_addr_parser.rl.c)
RAGEL_TARGET(ragel_content_disposition
	INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/content_disposition_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -G2
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/content_disposition.rl.c)
RAGEL_TARGET(ragel_rfc2047
	INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/rfc2047_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -G2
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/rfc2047.rl.c)
RAGEL_TARGET(ragel_smtp_date
	INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/smtp_date_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -G2
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/date_parser.rl.c)
RAGEL_TARGET(ragel_smtp_ip
	INPUTS ${CMAKE_SOURCE_DIR}/src/ragel/smtp_ip_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -G2
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ip_parser.rl.c)
# Fucking cmake...
FOREACH(_GEN ${LIBSERVER_GENERATED})
	set_source_files_properties(${_GEN} PROPERTIES GENERATED TRUE)
ENDFOREACH()
######################### LINK SECTION ###############################

IF(ENABLE_STATIC MATCHES "ON")
	ADD_LIBRARY(rspamd-server STATIC
			${RSPAMD_CRYPTOBOX}
			${RSPAMD_UTIL}
			${RSPAMD_LUA}
			${RSPAMD_SERVER}
			${RSPAMD_STAT}
			${RSPAMD_MIME}
			${CMAKE_CURRENT_BINARY_DIR}/modules.c
			${PLUGINSSRC}
			"${RAGEL_ragel_smtp_addr_OUTPUTS}"
			"${RAGEL_ragel_newlines_strip_OUTPUTS}"
			"${RAGEL_ragel_content_type_OUTPUTS}"
			"${RAGEL_ragel_content_disposition_OUTPUTS}"
			"${RAGEL_ragel_rfc2047_OUTPUTS}"
			"${RAGEL_ragel_smtp_date_OUTPUTS}"
			"${RAGEL_ragel_smtp_ip_OUTPUTS}")
ELSE()
	ADD_LIBRARY(rspamd-server SHARED
			${RSPAMD_CRYPTOBOX}
			${RSPAMD_UTIL}
			${RSPAMD_SERVER}
			${RSPAMD_STAT}
			${RSPAMD_MIME}
			${RSPAMD_LUA}
			${CMAKE_CURRENT_BINARY_DIR}/modules.c
			${PLUGINSSRC}
			"${RAGEL_ragel_smtp_addr_OUTPUTS}"
			"${RAGEL_ragel_newlines_strip_OUTPUTS}"
			"${RAGEL_ragel_content_type_OUTPUTS}"
			"${RAGEL_ragel_content_disposition_OUTPUTS}"
			"${RAGEL_ragel_rfc2047_OUTPUTS}"
			"${RAGEL_ragel_smtp_date_OUTPUTS}"
			"${RAGEL_ragel_smtp_ip_OUTPUTS}")
ENDIF()

FOREACH(_DEP ${LIBSERVER_DEPENDS})
	ADD_DEPENDENCIES(rspamd-server "${_DEP}")
ENDFOREACH()

TARGET_LINK_LIBRARIES(rspamd-server rspamd-http-parser)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-fpconv)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-cdb)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-lpeg)
TARGET_LINK_LIBRARIES(rspamd-server lcbtrie)
IF(SYSTEM_ZSTD MATCHES "OFF")
	TARGET_LINK_LIBRARIES(rspamd-server rspamd-zstd)
ELSE()
	TARGET_LINK_LIBRARIES(rspamd-server zstd)
ENDIF()
TARGET_LINK_LIBRARIES(rspamd-server rspamd-fastutf8)
TARGET_LINK_LIBRARIES(rspamd-server fmt)

IF (ENABLE_CLANG_PLUGIN MATCHES "ON")
	ADD_DEPENDENCIES(rspamd-server rspamd-clang)
ENDIF()

IF (NOT WITH_LUAJIT)
	TARGET_LINK_LIBRARIES(rspamd-server rspamd-bit)
ENDIF()

IF (ENABLE_SNOWBALL MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-server stemmer)
ENDIF()
TARGET_LINK_LIBRARIES(rspamd-server rspamd-hiredis)

IF (ENABLE_FANN MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-server fann)
ENDIF ()

IF (ENABLE_HYPERSCAN MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd-server hs)
ENDIF()

IF(WITH_BLAS)
	TARGET_LINK_LIBRARIES(rspamd-server ${BLAS_REQUIRED_LIBRARIES})
ENDIF()

TARGET_LINK_LIBRARIES(rspamd-server ${RSPAMD_REQUIRED_LIBRARIES})

ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${CMAKE_CURRENT_BINARY_DIR}/workers.c)
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE CXX)
SET_TARGET_PROPERTIES(rspamd-server PROPERTIES LINKER_LANGUAGE CXX)
IF(NOT DEBIAN_BUILD)
	SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

#TARGET_LINK_LIBRARIES(rspamd ${RSPAMD_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd rspamd-server)

INSTALL(TARGETS rspamd RUNTIME DESTINATION bin)
INSTALL(TARGETS rspamd-server LIBRARY DESTINATION ${RSPAMD_LIBDIR})