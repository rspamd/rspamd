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
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Xclang -load -Xclang ${CMAKE_CURRENT_BINARY_DIR}/../clang-plugin/librspamd-clang.so -Xclang -add-plugin -Xclang rspamd-ast")
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
				lua_worker.c
				rspamd.c
				smtp_proxy.c
				worker.c
				rspamd_proxy.c
				log_helper.c)

SET(PLUGINSSRC	plugins/surbl.c
				plugins/regexp.c
				plugins/chartable.c
				plugins/fuzzy_check.c
				plugins/spf.c
				plugins/dkim_check.c
				libserver/rspamd_control.c
				lua/lua_fann.c)

SET(MODULES_LIST surbl regexp chartable fuzzy_check spf dkim)
SET(WORKERS_LIST normal controller smtp_proxy fuzzy lua rspamd_proxy log_helper)
IF (ENABLE_HYPERSCAN MATCHES "ON")
	LIST(APPEND WORKERS_LIST "hs_helper")
	LIST(APPEND RSPAMDSRC "hs_helper.c")
ENDIF()

AddModules(MODULES_LIST WORKERS_LIST)
LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)

SET(RAGEL_DEPENDS "${CMAKE_SOURCE_DIR}/src/ragel/smtp_address.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_date.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_ip.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_whitespace.rl"
	"${CMAKE_SOURCE_DIR}/src/ragel/smtp_received.rl")
RAGEL_TARGET(ragel_smtp_addr
	INPUTS ragel/smtp_addr_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -T1
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/smtp_addr_parser.rl.c)
RAGEL_TARGET(ragel_smtp_received
	INPUTS ragel/smtp_received_parser.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -T1
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/smtp_received_parser.rl.c)
RAGEL_TARGET(ragel_newlines_strip
	INPUTS ragel/newlines_strip.rl
	DEPENDS ${RAGEL_DEPENDS}
	COMPILE_FLAGS -G2
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/newlines_strip.rl.c)
######################### LINK SECTION ###############################

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
		"${RAGEL_ragel_smtp_received_OUTPUTS}"
		"${RAGEL_ragel_newlines_strip_OUTPUTS}")
TARGET_LINK_LIBRARIES(rspamd-server rspamd-http-parser)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-cdb)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-lpeg)
TARGET_LINK_LIBRARIES(rspamd-server lcbtrie)

IF (ENABLE_CLANG_PLUGIN MATCHES "ON")
	ADD_DEPENDENCIES(rspamd-server rspamd-clang)
ENDIF()
ADD_DEPENDENCIES(rspamd-server rspamd_lua_preprocess)

ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${CMAKE_CURRENT_BINARY_DIR}/workers.c)
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS "-DRSPAMD_MAIN")
IF(NOT DEBIAN_BUILD)
	SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

TARGET_LINK_LIBRARIES(rspamd rspamd-server)
IF (ENABLE_SNOWBALL MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd stemmer)
ENDIF()
IF(ENABLE_HIREDIS MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd rspamd-hiredis)
ENDIF()

IF (ENABLE_FANN MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd fann)
ENDIF ()

IF (ENABLE_HYPERSCAN MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd hs)
	SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE CXX)
ENDIF()

TARGET_LINK_LIBRARIES(rspamd ${RSPAMD_REQUIRED_LIBRARIES})

INSTALL(TARGETS rspamd RUNTIME DESTINATION bin)
