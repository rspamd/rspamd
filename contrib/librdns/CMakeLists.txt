SET(LIBRDNSSRC			util.c
						logger.c
						compression.c
						punycode.c
						curve.c
						parse.c
						packet.c
						resolver.c)

ADD_LIBRARY(rdns STATIC ${LIBRDNSSRC})
SET_TARGET_PROPERTIES(rdns PROPERTIES COMPILE_FLAGS "-DUSE_RSPAMD_CRYPTOBOX")