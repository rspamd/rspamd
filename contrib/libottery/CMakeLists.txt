SET(OTTERYSRC            chacha_merged.c
                         ottery.c
                         ottery_cpuinfo.c
                         ottery_entropy.c
                         ottery_global.c
                         chacha_cryptobox.c
                         aes_cryptobox.c)
ADD_LIBRARY(ottery STATIC ${OTTERYSRC})

SET(OTTERY_CFLAGS "-DBUILD_RSPAMD -DOTTERY_NO_PID_CHECK -DOTTERY_NO_INIT_CHECK -DOTTERY_NO_WIPE_STACK")
set_target_properties(ottery PROPERTIES COMPILE_FLAGS "${OTTERY_CFLAGS}")