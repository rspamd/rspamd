SET(CHACHASRC ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/chacha.c
        ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/ref.c)

SET(BASE64SRC ${CMAKE_CURRENT_SOURCE_DIR}/base64/ref.c
        ${CMAKE_CURRENT_SOURCE_DIR}/base64/base64.c)

IF (HAVE_AVX2)
    IF ("${ARCH}" STREQUAL "x86_64")
        SET(CHACHASRC ${CHACHASRC} ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/avx2.S)
        MESSAGE(STATUS "Cryptobox: AVX2 support is added (chacha20)")
    ENDIF ()
    SET(BASE64SRC ${BASE64SRC} ${CMAKE_CURRENT_SOURCE_DIR}/base64/avx2.c)
    MESSAGE(STATUS "Cryptobox: AVX2 support is added (base64)")
ENDIF (HAVE_AVX2)
IF (HAVE_AVX)
    IF ("${ARCH}" STREQUAL "x86_64")
        SET(CHACHASRC ${CHACHASRC} ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/avx.S)
        MESSAGE(STATUS "Cryptobox: AVX support is added (chacha20)")
    ENDIF ()
ENDIF (HAVE_AVX)
IF (HAVE_SSE2)
    IF ("${ARCH}" STREQUAL "x86_64")
        SET(CHACHASRC ${CHACHASRC} ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/sse2.S)
        MESSAGE(STATUS "Cryptobox: SSE2 support is added (chacha20)")
    ENDIF ()
ENDIF (HAVE_SSE2)
IF (HAVE_SSE42)
    IF ("${ARCH}" STREQUAL "x86_64")
        SET(BASE64SRC ${BASE64SRC} ${CMAKE_CURRENT_SOURCE_DIR}/base64/sse42.c)
        MESSAGE(STATUS "Cryptobox: SSE42 support is added (base64)")
    ENDIF ()
ENDIF (HAVE_SSE42)

CONFIGURE_FILE(platform_config.h.in platform_config.h)
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_BINARY_DIR}")
SET(LIBCRYPTOBOXSRC ${CMAKE_CURRENT_SOURCE_DIR}/cryptobox.c
        ${CMAKE_CURRENT_SOURCE_DIR}/keypair.c
        ${CMAKE_CURRENT_SOURCE_DIR}/keypairs_cache.c
        ${CMAKE_CURRENT_SOURCE_DIR}/catena/catena.c)

SET(RSPAMD_CRYPTOBOX ${LIBCRYPTOBOXSRC} ${CHACHASRC} ${BASE64SRC} PARENT_SCOPE)
