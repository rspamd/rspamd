# Evdns port to support TXT records
SET(EVDNSSRC			  evdns.c)

ADD_LIBRARY(rspamd_evdns STATIC ${EVDNSSRC})
SET_TARGET_PROPERTIES(rspamd_evdns PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")
