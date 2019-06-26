SET(UCLSRC            ucl_util.c
                      ucl_parser.c
                      ucl_emitter.c
                      ucl_emitter_streamline.c
                      ucl_hash.c
                      ucl_schema.c
                      lua_ucl.c
					  ucl_msgpack.c
					  ucl_sexp.c)


SET (LIB_TYPE STATIC)
ADD_LIBRARY(ucl ${LIB_TYPE} ${UCLSRC})

IF(ENABLE_URL_SIGN MATCHES "ON")
	IF(OPENSSL_FOUND)
		TARGET_LINK_LIBRARIES(ucl ${OPENSSL_LIBRARIES})
	ENDIF(OPENSSL_FOUND)
ENDIF(ENABLE_URL_SIGN MATCHES "ON")
