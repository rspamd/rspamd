# Librspamdserver
SET(LIBSTATSRC		${CMAKE_CURRENT_SOURCE_DIR}/stat_config.c
					${CMAKE_CURRENT_SOURCE_DIR}/stat_process.c)

SET(TOKENIZERSSRC	${CMAKE_CURRENT_SOURCE_DIR}/tokenizers/tokenizers.c
					${CMAKE_CURRENT_SOURCE_DIR}/tokenizers/osb.c)

SET(CLASSIFIERSSRC	${CMAKE_CURRENT_SOURCE_DIR}/classifiers/bayes.c
					${CMAKE_CURRENT_SOURCE_DIR}/classifiers/lua_classifier.c)

SET(BACKENDSSRC 	${CMAKE_CURRENT_SOURCE_DIR}/backends/mmaped_file.c
					${CMAKE_CURRENT_SOURCE_DIR}/backends/sqlite3_backend.c
					${CMAKE_CURRENT_SOURCE_DIR}/backends/cdb_backend.cxx
					${CMAKE_CURRENT_SOURCE_DIR}/backends/redis_backend.c)

SET(CACHESSRC 	${CMAKE_CURRENT_SOURCE_DIR}/learn_cache/sqlite3_cache.c
					${CMAKE_CURRENT_SOURCE_DIR}/learn_cache/redis_cache.c)

SET(RSPAMD_STAT ${LIBSTATSRC}
			${TOKENIZERSSRC}
			${CLASSIFIERSSRC}
			${BACKENDSSRC}
			${CACHESSRC} PARENT_SCOPE)

