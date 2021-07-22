# Librspamdserver
ADD_SUBDIRECTORY(css)
SET(LIBRSPAMDSERVERSRC
				${CMAKE_CURRENT_SOURCE_DIR}/cfg_utils.c
				${CMAKE_CURRENT_SOURCE_DIR}/cfg_rcl.c
				${CMAKE_CURRENT_SOURCE_DIR}/composites/composites.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/composites/composites_manager.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/dkim.c
				${CMAKE_CURRENT_SOURCE_DIR}/dns.c
				${CMAKE_CURRENT_SOURCE_DIR}/dynamic_cfg.c
				${CMAKE_CURRENT_SOURCE_DIR}/async_session.c
				${CMAKE_CURRENT_SOURCE_DIR}/fuzzy_backend/fuzzy_backend.c
				${CMAKE_CURRENT_SOURCE_DIR}/fuzzy_backend/fuzzy_backend_sqlite.c
				${CMAKE_CURRENT_SOURCE_DIR}/fuzzy_backend/fuzzy_backend_redis.c
				${CMAKE_CURRENT_SOURCE_DIR}/milter.c
				${CMAKE_CURRENT_SOURCE_DIR}/monitored.c
				${CMAKE_CURRENT_SOURCE_DIR}/protocol.c
				${CMAKE_CURRENT_SOURCE_DIR}/re_cache.c
		${CMAKE_CURRENT_SOURCE_DIR}/redis_pool.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/roll_history.c
				${CMAKE_CURRENT_SOURCE_DIR}/spf.c
				${CMAKE_CURRENT_SOURCE_DIR}/ssl_util.c
				${CMAKE_CURRENT_SOURCE_DIR}/rspamd_symcache.c
				${CMAKE_CURRENT_SOURCE_DIR}/task.c
				${CMAKE_CURRENT_SOURCE_DIR}/url.c
				${CMAKE_CURRENT_SOURCE_DIR}/worker_util.c
				${CMAKE_CURRENT_SOURCE_DIR}/logger/logger.c
				${CMAKE_CURRENT_SOURCE_DIR}/logger/logger_file.c
				${CMAKE_CURRENT_SOURCE_DIR}/logger/logger_syslog.c
				${CMAKE_CURRENT_SOURCE_DIR}/logger/logger_console.c
				${CMAKE_CURRENT_SOURCE_DIR}/http/http_util.c
				${CMAKE_CURRENT_SOURCE_DIR}/http/http_message.c
				${CMAKE_CURRENT_SOURCE_DIR}/http/http_connection.c
				${CMAKE_CURRENT_SOURCE_DIR}/http/http_router.c
				${CMAKE_CURRENT_SOURCE_DIR}/http/http_context.c
				${CMAKE_CURRENT_SOURCE_DIR}/maps/map.c
				${CMAKE_CURRENT_SOURCE_DIR}/maps/map_helpers.c
				${CMAKE_CURRENT_SOURCE_DIR}/html/html_entities.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/html/html_url.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/html/html.cxx
				${CMAKE_CURRENT_SOURCE_DIR}/html/html_tests.cxx
				${LIBCSSSRC})

# Librspamd-server
SET(RSPAMD_SERVER ${LIBRSPAMDSERVERSRC} PARENT_SCOPE)
SET(LIBSERVER_DEPENDS "${LIBCSS_DEPENDS}" PARENT_SCOPE)
SET(LIBSERVER_GENERATED "${LIBCSS_GENERATED}" PARENT_SCOPE)
