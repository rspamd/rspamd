# CDB support makefile
SET(CDBSRC				cdb_init.c
						cdb_find.c
						cdb_make.c)

ADD_LIBRARY(rspamd-cdb STATIC ${CDBSRC})
SET_TARGET_PROPERTIES(rspamd-cdb PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(rspamd-cdb PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")