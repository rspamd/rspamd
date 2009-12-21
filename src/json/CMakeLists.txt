# Json support makefile
SET(JSONSRC				dump.c
						hashtable.c
						load.c
						strbuffer.c
						utf.c
						value.c)

ADD_LIBRARY(rspamd_json STATIC ${JSONSRC})
SET_TARGET_PROPERTIES(rspamd_json PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
