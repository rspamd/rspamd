# A simple makefile to generate documentation from .md using pandoc

PANDOC ?= pandoc
LUADOC ?= doxydown/doxydown.pl
LLUADOC ?= ${LUADOC} -l lua -e lua

all: man

man: rspamd.8 rspamc.1 rspamadm.1

rspamd.8: rspamd.8.md
	$(PANDOC) -s -f markdown -t man -o rspamd.8 rspamd.8.md
rspamc.1: rspamc.1.md
	$(PANDOC) -s -f markdown -t man -o rspamc.1 rspamc.1.md
rspamadm.1: rspamadm.1.md
	$(PANDOC) -s -f markdown -t man -o rspamadm.1 rspamadm.1.md

lua-dirs:
	mkdir -p markdown/lua

lua-doc: lua-dirs rspamd_regexp rspamd_ip rspamd_config rspamd_task ucl rspamd_http rspamd_trie \
	rspamd_resolver rspamd_redis rspamd_upstream_list rspamd_expression rspamd_mimepart rspamd_logger rspamd_url \
	rspamd_tcp rspamd_mempool rspamd_html rspamd_util rspamd_sqlite3 rspamd_cryptobox rspamd_map \
	lua_redis lua_util lua_maps lua_clickhouse lua_selectors rspamd_udp rspamd_text lua_mime rspamd_parsers \
	rspamd_cdb

lua_redis:
	$(LLUADOC) < ../lualib/lua_redis.lua > markdown/lua/lua_redis.md

lua_util:
	$(LLUADOC) < ../lualib/lua_util.lua > markdown/lua/lua_util.md

lua_maps:
	$(LLUADOC) < ../lualib/lua_maps.lua > markdown/lua/lua_maps.md

lua_clickhouse:
	$(LLUADOC) < ../lualib/lua_clickhouse.lua > markdown/lua/lua_clickhouse.md

lua_selectors:
	$(LLUADOC) < ../lualib/lua_selectors/init.lua > markdown/lua/lua_selectors.md

lua_mime:
	$(LLUADOC) < ../lualib/lua_mime.lua > markdown/lua/lua_mime.md

rspamd_regexp: ../src/lua/lua_regexp.c
	$(LUADOC) < ../src/lua/lua_regexp.c > markdown/lua/rspamd_regexp.md
rspamd_ip: ../src/lua/lua_ip.c
	$(LUADOC) < ../src/lua/lua_ip.c > markdown/lua/rspamd_ip.md
rspamd_config: ../src/lua/lua_config.c
	$(LUADOC) < ../src/lua/lua_config.c > markdown/lua/rspamd_config.md
rspamd_task: ../src/lua/lua_task.c
	$(LUADOC) < ../src/lua/lua_task.c > markdown/lua/rspamd_task.md
ucl: ../contrib/libucl/lua_ucl.c
	$(LUADOC) < ../contrib/libucl/lua_ucl.c > markdown/lua/ucl.md
rspamd_http: ../src/lua/lua_http.c
	$(LUADOC) < ../src/lua/lua_http.c > markdown/lua/rspamd_http.md
rspamd_trie: ../src/lua/lua_trie.c
	$(LUADOC) < ../src/lua/lua_trie.c > markdown/lua/rspamd_trie.md
rspamd_resolver: ../src/lua/lua_dns_resolver.c
	$(LUADOC) < ../src/lua/lua_dns_resolver.c > markdown/lua/rspamd_resolver.md
rspamd_redis: ../src/lua/lua_redis.c
	$(LUADOC) < ../src/lua/lua_redis.c > markdown/lua/rspamd_redis.md
rspamd_upstream_list: ../src/lua/lua_upstream.c
	$(LUADOC) < ../src/lua/lua_upstream.c > markdown/lua/rspamd_upstream.md
rspamd_expression: ../src/lua/lua_expression.c
	$(LUADOC) < ../src/lua/lua_expression.c > markdown/lua/rspamd_expression.md
rspamd_mimepart: ../src/lua/lua_mimepart.c
	$(LUADOC) < ../src/lua/lua_mimepart.c > markdown/lua/rspamd_mimepart.md
rspamd_logger: ../src/lua/lua_logger.c
	$(LUADOC) < ../src/lua/lua_logger.c > markdown/lua/rspamd_logger.md
rspamd_url: ../src/lua/lua_url.c
	$(LUADOC) < ../src/lua/lua_url.c > markdown/lua/rspamd_url.md
rspamd_tcp: ../src/lua/lua_tcp.c
	$(LUADOC) < ../src/lua/lua_tcp.c > markdown/lua/rspamd_tcp.md
rspamd_mempool: ../src/lua/lua_mempool.c
	$(LUADOC) < ../src/lua/lua_mempool.c > markdown/lua/rspamd_mempool.md
rspamd_html: ../src/lua/lua_html.cxx
	$(LUADOC) < ../src/lua/lua_html.cxx > markdown/lua/rspamd_html.md
rspamd_util: ../src/lua/lua_util.c
	$(LUADOC) < ../src/lua/lua_util.c > markdown/lua/rspamd_util.md
rspamd_sqlite3: ../src/lua/lua_sqlite3.c
	$(LUADOC) < ../src/lua/lua_sqlite3.c > markdown/lua/rspamd_sqlite3.md
rspamd_cryptobox: ../src/lua/lua_cryptobox.c
	$(LUADOC) < ../src/lua/lua_cryptobox.c > markdown/lua/rspamd_cryptobox.md
rspamd_map: ../src/lua/lua_map.c
	$(LUADOC) < ../src/lua/lua_map.c > markdown/lua/rspamd_map.md
rspamd_udp: ../src/lua/lua_udp.c
	$(LUADOC) < ../src/lua/lua_udp.c > markdown/lua/rspamd_udp.md
rspamd_text: ../src/lua/lua_text.c
	$(LUADOC) < ../src/lua/lua_text.c > markdown/lua/rspamd_text.md
rspamd_parsers: ../src/lua/lua_parsers.c
	$(LUADOC) < ../src/lua/lua_parsers.c > markdown/lua/rspamd_parsers.md
rspamd_cdb: ../src/lua/lua_cdb.c
	$(LUADOC) < ../src/lua/lua_cdb.c > markdown/lua/rspamd_cdb.md