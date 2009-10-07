# Evdns port to support TXT records
SET(EVDNSSRC			  evdns.c)

ADD_LIBRARY(rspamd_evdns STATIC ${EVDNSSRC})
