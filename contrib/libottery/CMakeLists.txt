SET(OTTERYSRC            chacha_merged.c
                         ottery.c
                         ottery_cpuinfo.c
                         ottery_entropy.c
                         ottery_global.c)

ADD_LIBRARY(rspamd-ottery ${LINK_TYPE} ${OTTERYSRC})
SET_TARGET_PROPERTIES(rspamd-ottery PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(rspamd-ottery PROPERTIES COMPILE_FLAGS "-DRSPAMD_LIB")

IF(NO_SHARED MATCHES "OFF")
    INSTALL(TARGETS rspamd-ottery
        LIBRARY DESTINATION ${LIBDIR}
        PUBLIC_HEADER DESTINATION ${INCLUDEDIR})
ENDIF(NO_SHARED MATCHES "OFF")  