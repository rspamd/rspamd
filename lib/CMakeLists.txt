# Librspamd
SET(LIBRSPAMDSRC			  librspamdclient.c ../src/util.c ../src/upstream.c ../src/mem_pool.c)

ADD_LIBRARY(rspamdclient SHARED ${LIBRSPAMDSRC})
ADD_LIBRARY(rspamdclient_static STATIC ${LIBRSPAMDSRC})
SET_TARGET_PROPERTIES(rspamdclient PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing -I../src/")
SET_TARGET_PROPERTIES(rspamdclient_static PROPERTIES COMPILE_FLAGS "-fno-strict-aliasing -I../src/")