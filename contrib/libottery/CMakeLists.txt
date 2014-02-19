SET(OTTERYSRC            chacha_merged.c
                         ottery.c
                         ottery_cpuinfo.c
                         ottery_entropy.c
                         ottery_global.c)

ADD_LIBRARY(ottery STATIC ${OTTERYSRC})  