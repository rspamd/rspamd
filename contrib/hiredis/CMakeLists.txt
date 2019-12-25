SET(HIREDISSRC	async.c
				dict.c
				hiredis.c
				net.c
				read.c
				sds.c)

SET(HIREDIS_CFLAGS "")
ADD_LIBRARY(rspamd-hiredis STATIC ${HIREDISSRC})

SET_TARGET_PROPERTIES(rspamd-hiredis PROPERTIES COMPILE_FLAGS "${HIREDIS_CFLAGS}")