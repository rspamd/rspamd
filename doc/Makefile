# A simple makefile to generate documentation from .md using pandoc

PANDOC ?= pandoc
LUADOC ?= doxydown/doxydown.pl

all: man

man: rspamd.8 rspamc.1

rspamd.8: rspamd.8.md
	$(PANDOC) -s -f markdown -t man -o rspamd.8 rspamd.8.md 
rspamc.1: rspamc.1.md
	$(PANDOC) -s -f markdown -t man -o rspamc.1 rspamc.1.md 
	
lua-doc: lua_regexp lua_ip lua_config lua_task lua_ucl

lua_regexp: ../src/lua/lua_regexp.c
	$(LUADOC) < ../src/lua/lua_regexp.c > markdown/lua/regexp.md
lua_ip: ../src/lua/lua_ip.c
	$(LUADOC) < ../src/lua/lua_ip.c > markdown/lua/ip.md
lua_config: ../src/lua/lua_config.c
	$(LUADOC) < ../src/lua/lua_config.c > markdown/lua/config.md
lua_task: ../src/lua/lua_task.c
	$(LUADOC) < ../src/lua/lua_task.c > markdown/lua/task.md
lua_ucl: ../src/ucl/lua/lua_ucl.c
	$(LUADOC) < ../src/ucl/lua/lua_ucl.c > markdown/lua/ucl.md
