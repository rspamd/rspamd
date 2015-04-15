# A simple makefile to generate documentation from .md using pandoc

PANDOC ?= pandoc
LUADOC ?= doxydown/doxydown.pl

all: man

man: rspamd.8 rspamc.1

rspamd.8: rspamd.8.md
	$(PANDOC) -s -f markdown -t man -o rspamd.8 rspamd.8.md 
rspamc.1: rspamc.1.md
	$(PANDOC) -s -f markdown -t man -o rspamc.1 rspamc.1.md 
	
lua-doc: lua_regexp lua_ip lua_config lua_task lua_ucl lua_http lua_trie \
	lua_dns lua_redis lua_upstream lua_expression lua_mimepart lua_logger

lua_regexp: ../src/lua/lua_regexp.c
	$(LUADOC) < ../src/lua/lua_regexp.c > markdown/lua/regexp.md
lua_ip: ../src/lua/lua_ip.c
	$(LUADOC) < ../src/lua/lua_ip.c > markdown/lua/ip.md
lua_config: ../src/lua/lua_config.c
	$(LUADOC) < ../src/lua/lua_config.c > markdown/lua/config.md
lua_task: ../src/lua/lua_task.c
	$(LUADOC) < ../src/lua/lua_task.c > markdown/lua/task.md
lua_ucl: ../contrib/libucl/lua_ucl.c
	$(LUADOC) < ../contrib/libucl/lua_ucl.c > markdown/lua/ucl.md
lua_http: ../src/lua/lua_http.c
	$(LUADOC) < ../src/lua/lua_http.c > markdown/lua/http.md
lua_trie: ../src/lua/lua_trie.c
	$(LUADOC) < ../src/lua/lua_trie.c > markdown/lua/trie.md
lua_dns: ../src/lua/lua_dns.c
	$(LUADOC) < ../src/lua/lua_dns.c > markdown/lua/dns.md
lua_redis: ../src/lua/lua_redis.c
	$(LUADOC) < ../src/lua/lua_redis.c > markdown/lua/redis.md
lua_upstream: ../src/lua/lua_upstream.c
	$(LUADOC) < ../src/lua/lua_upstream.c > markdown/lua/upstream.md
lua_expression: ../src/lua/lua_expression.c
	$(LUADOC) < ../src/lua/lua_expression.c > markdown/lua/expression.md
lua_mimepart: ../src/lua/lua_mimepart.c
	$(LUADOC) < ../src/lua/lua_mimepart.c > markdown/lua/mimepart.md
lua_logger: ../src/lua/lua_logger.c
	$(LUADOC) < ../src/lua/lua_logger.c > markdown/lua/logger.md
lua_url: ../src/lua/lua_url.c
	$(LUADOC) < ../src/lua/lua_url.c > markdown/lua/url.md