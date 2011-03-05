# CDB support makefile
SET(CDBSRC				cdb_init.c
						cdb_find.c
						cdb_make.c)

ADD_LIBRARY(rspamd_cdb STATIC ${CDBSRC})
SET_TARGET_PROPERTIES(rspamd_cdb PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")