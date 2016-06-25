SET(RSPAMADMSRC rspamadm.c
        commands.c
        pw.c
        keypair.c
        configtest.c
        fuzzy_merge.c
        configdump.c
        control.c
        confighelp.c
        stat_convert.c
        signtool.c
        lua_repl.c
        ${CMAKE_BINARY_DIR}/src/workers.c
        ${CMAKE_BINARY_DIR}/src/modules.c
        ${CMAKE_SOURCE_DIR}/src/controller.c
        ${CMAKE_SOURCE_DIR}/src/fuzzy_storage.c
        ${CMAKE_SOURCE_DIR}/src/lua_worker.c
        ${CMAKE_SOURCE_DIR}/src/smtp_proxy.c
        ${CMAKE_SOURCE_DIR}/src/worker.c
        ${CMAKE_SOURCE_DIR}/src/rspamd_proxy.c
        ${CMAKE_SOURCE_DIR}/src/log_helper.c)
SET(RSPAMADMLUASRC
        ${CMAKE_CURRENT_SOURCE_DIR}/fuzzy_stat.lua
        ${CMAKE_CURRENT_SOURCE_DIR}/confighelp.lua)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
ADD_CUSTOM_TARGET(rspamadm_lua_preprocess
        ${PERL_EXECUTABLE}
            "${CMAKE_SOURCE_DIR}/lua_preprocess.pl"
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${CMAKE_CURRENT_BINARY_DIR}"
        SOURCES ${RSPAMADMLUASRC} ${CMAKE_SOURCE_DIR}/lua_preprocess.pl)
IF (ENABLE_HYPERSCAN MATCHES "ON")
    LIST(APPEND RSPAMADMSRC "${CMAKE_SOURCE_DIR}/src/hs_helper.c")
ENDIF()
ADD_EXECUTABLE(rspamadm ${RSPAMADMSRC})
ADD_DEPENDENCIES(rspamadm rspamadm_lua_preprocess)
TARGET_LINK_LIBRARIES(rspamadm rspamd-server)
TARGET_LINK_LIBRARIES(rspamadm ${RSPAMD_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamadm rspamd-linenoise)

IF (NOT DEBIAN_BUILD)
    SET_TARGET_PROPERTIES(rspamadm PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF (NOT DEBIAN_BUILD)

IF (ENABLE_FANN MATCHES "ON")
    TARGET_LINK_LIBRARIES(rspamadm fann)
ENDIF ()
IF (ENABLE_HYPERSCAN MATCHES "ON")
    TARGET_LINK_LIBRARIES(rspamadm hs)
    SET_TARGET_PROPERTIES(rspamadm PROPERTIES LINKER_LANGUAGE CXX)
ENDIF ()

INSTALL(TARGETS rspamadm RUNTIME DESTINATION bin)
