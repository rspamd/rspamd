# IPmark plugin makefile
SET(IPMARKSRC		  ipmark.c
					  ../../../radix.c
					  ../../../mem_pool.c
)

ADD_LIBRARY(rspamd_ipmark SHARED ${IPMARKSRC})
TARGET_LINK_LIBRARIES(rspamd_ipmark ${GLIB2_LIBRARIES})

INSTALL(TARGETS rspamd_ipmark DESTINATION lib)
