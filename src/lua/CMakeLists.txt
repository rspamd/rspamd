# Lua support makefile
SET(LUASRC			  ${CMAKE_CURRENT_SOURCE_DIR}/lua_common.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_logger.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_task.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_config.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_classifier.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_cfg_file.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_regexp.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_cdb.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_xmlrpc.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_http.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_redis.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_upstream.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_mempool.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_dns_resolver.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_rsa.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_ip.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_expression.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_trie.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_mimepart.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_url.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_util.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_tcp.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_html.cxx
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_sqlite3.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_cryptobox.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_map.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_thread_pool.cxx
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_dns.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_udp.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_text.c
		 			  ${CMAKE_CURRENT_SOURCE_DIR}/lua_worker.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_kann.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_spf.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_tensor.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_parsers.c
					  ${CMAKE_CURRENT_SOURCE_DIR}/lua_compress.c)

SET(RSPAMD_LUA ${LUASRC} PARENT_SCOPE)