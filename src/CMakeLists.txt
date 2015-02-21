MACRO(_AddModulesForced MLIST WLIST)
# Generate unique string for this build
	STRING(RANDOM LENGTH 8 _MODULES_ID)
	SET(MODULES_ID ${_MODULES_ID} CACHE INTERNAL "Modules ID" FORCE)
	SET(MODULES_C "${CMAKE_CURRENT_BINARY_DIR}/modules.c")
	FILE(WRITE "${MODULES_C}"
		"/* ${MODULES_ID} */\n#include \"config.h\"\n")
	
	# Handle even old cmake
	LIST(LENGTH ${MLIST} MLIST_COUNT)
	LIST(LENGTH ${WLIST} WLIST_COUNT)
	MATH(EXPR MLIST_MAX ${MLIST_COUNT}-1)
	MATH(EXPR WLIST_MAX ${WLIST_COUNT}-1)
	
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
	
	FOREACH(MOD_IDX RANGE ${WLIST_MAX})
		LIST(GET ${WLIST} ${MOD_IDX} WRK)
		FILE(APPEND "${MODULES_C}" "extern worker_t ${WRK}_worker;\n")
	ENDFOREACH(MOD_IDX RANGE ${WLIST_MAX})
	 
	FILE(APPEND "${MODULES_C}" "\n\nworker_t *workers[] = {\n")
	
	FOREACH(MOD_IDX RANGE ${WLIST_MAX})
		LIST(GET ${WLIST} ${MOD_IDX} WRK)
		FILE(APPEND "${MODULES_C}" "&${WRK}_worker,\n")
	ENDFOREACH(MOD_IDX RANGE ${WLIST_MAX})
	FILE(APPEND "${MODULES_C}" "NULL\n};\n")
ENDMACRO(_AddModulesForced MLIST WLIST)

MACRO(AddModules MLIST WLIST)
	_AddModulesForced(${MLIST} ${WLIST})
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

# Contrib software
ADD_SUBDIRECTORY(cdb)
# Rspamd core components
ADD_SUBDIRECTORY(lua)
ADD_SUBDIRECTORY(libcryptobox)
ADD_SUBDIRECTORY(libutil)
ADD_SUBDIRECTORY(libserver)
ADD_SUBDIRECTORY(libmime)
ADD_SUBDIRECTORY(libstat)
ADD_SUBDIRECTORY(client)
				
SET(RSPAMDSRC	${CMAKE_CURRENT_BINARY_DIR}/modules.c
				controller.c
				fuzzy_storage.c
				lua_worker.c
				main.c
				smtp_proxy.c
				worker.c)

SET(PLUGINSSRC	plugins/surbl.c
				plugins/regexp.c
				plugins/chartable.c
				plugins/fuzzy_check.c
				plugins/spf.c
				plugins/dkim_check.c)
				
SET(MODULES_LIST surbl regexp chartable fuzzy_check spf dkim)
SET(WORKERS_LIST normal controller smtp_proxy fuzzy lua)

AddModules(MODULES_LIST WORKERS_LIST)
LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)
######################### LINK SECTION ###############################

ADD_LIBRARY(rspamd-server STATIC ${RSPAMD_UTIL} ${RSPAMD_LUA} ${RSPAMD_SERVER}
		${RSPAMD_STAT} ${RSPAMD_MIME} ${RSPAMD_CRYPTOBOX})
TARGET_LINK_LIBRARIES(rspamd-server rspamd-http-parser)
TARGET_LINK_LIBRARIES(rspamd-server rspamd-cdb)

ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${PLUGINSSRC})
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS "-DRSPAMD_MAIN")
IF(NOT DEBIAN_BUILD)
	SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

TARGET_LINK_LIBRARIES(rspamd rspamd-server)
TARGET_LINK_LIBRARIES(rspamd stemmer)

TARGET_LINK_LIBRARIES(rspamd ${RSPAMD_REQUIRED_LIBRARIES})

INSTALL(TARGETS rspamd RUNTIME DESTINATION bin)
