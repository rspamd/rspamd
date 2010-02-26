# Regmark plugin makefile
SET(REGMARKSRC		  regmark.c
					  metaphone.c
					  prefix_tree.c
)

ADD_LIBRARY(rspamd_regmark MODULE ${REGMARKSRC})
TARGET_LINK_LIBRARIES(rspamd_regmark ${GLIB2_LIBRARIES})

INSTALL(TARGETS rspamd_regmark DESTINATION lib)
