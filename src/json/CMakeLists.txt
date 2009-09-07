# Json support makefile
SET(JSONSRC				dump.c
						hashtable.c
						load.c
						strbuffer.c
						utf.c
						value.c)

ADD_LIBRARY(rspamd_json STATIC ${JSONSRC})
