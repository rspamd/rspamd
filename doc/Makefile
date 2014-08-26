# A simple makefile to generate documentation from .md using pandoc

PANDOC ?= pandoc
LUADOC ?= ./lua_api.pl

all: man

man: rspamd.8 rspamc.1

rspamd.8: rspamd.8.md
	$(PANDOC) -s -f markdown -t man -o rspamd.8 rspamd.8.md 
rspamc.1: rspamc.1.md
	$(PANDOC) -s -f markdown -t man -o rspamc.1 rspamc.1.md 
	
lua-doc: lua_regexp

lua_regexp: ../src/lua/lua_regexp.c
	$(LUADOC) < ../src/lua/lua_regexp.c > markdown/lua/regexp.md
