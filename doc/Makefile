# A simple makefile to generate documentation from .md using pandoc

PANDOC ?= pandoc

all: man

man: rspamd.8 rspamc.1

rspamd.8: rspamd.8.md
	$(PANDOC) -s -f markdown -t man -o rspamd.8 rspamd.8.md 
rspamc.1: rspamc.1.md
	$(PANDOC) -s -f markdown -t man -o rspamc.1 rspamc.1.md 
