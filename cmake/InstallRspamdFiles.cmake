# InstallRspamdFiles.cmake
# Manages the installation of Rspamd files, configurations, and components

function(InstallRspamdFiles)
    # Create necessary directories
    install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR})")
    install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${SHAREDIR})")
    install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${LUALIBDIR})")
    install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR})")
    install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${RULESDIR})")

    # Install configuration files
    set(GLOB_PATTERNS "${CMAKE_SOURCE_DIR}/conf/*.conf;${CMAKE_SOURCE_DIR}/conf/*.inc")
    if (INSTALL_EXAMPLES)
        list(APPEND GLOB_PATTERNS "${CMAKE_SOURCE_DIR}/conf/*.lua.example")
        list(APPEND GLOB_PATTERNS "${CMAKE_SOURCE_DIR}/conf/*.conf.example")
    endif ()

    file(GLOB_RECURSE CONF_FILES RELATIVE "${CMAKE_SOURCE_DIR}/conf" CONFIGURE_DEPENDS
            ${GLOB_PATTERNS})
    foreach (CONF_FILE ${CONF_FILES})
        get_filename_component(_rp ${CONF_FILE} PATH)
        install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR}/${_rp})")
        install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/conf/${CONF_FILE}"
                DESTINATION ${CONFDIR}/${_rp})
    endforeach ()

    # Install Lua plugins
    file(GLOB LUA_PLUGINS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua" CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua/*.lua")
    foreach (LUA_PLUGIN ${LUA_PLUGINS})
        get_filename_component(_rp ${LUA_PLUGIN} PATH)
        install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR}/${_rp})")
        install(FILES "src/plugins/lua/${LUA_PLUGIN}" DESTINATION ${PLUGINSDIR}/${_rp})
    endforeach ()

    # Install TLD list
    install(FILES "contrib/publicsuffix/effective_tld_names.dat" DESTINATION
            "${SHAREDIR}")

    # Install language data
    install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${SHAREDIR}/languages)")
    file(GLOB LANGUAGES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/contrib/languages-data/*.json")
    foreach (_LANG ${LANGUAGES})
        install(FILES "${_LANG}" DESTINATION ${SHAREDIR}/languages)
    endforeach ()
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/contrib/languages-data/stop_words"
            DESTINATION ${SHAREDIR}/languages)

    # Install Lua rules
    file(GLOB_RECURSE LUA_CONFIGS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/rules" CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/rules/*.lua")
    foreach (LUA_CONF ${LUA_CONFIGS})
        get_filename_component(_rp ${LUA_CONF} PATH)
        install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${RULESDIR}/${_rp})")
        install(FILES "rules/${LUA_CONF}" DESTINATION ${RULESDIR}/${_rp})
    endforeach ()

    # Install Lua libraries
    file(GLOB_RECURSE LUA_LIBS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/lualib" CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/lualib/*.lua")
    foreach (LUA_LIB ${LUA_LIBS})
        get_filename_component(_rp ${LUA_LIB} PATH)
        install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${LUALIBDIR}/${_rp})")
        install(FILES "lualib/${LUA_LIB}" DESTINATION ${LUALIBDIR}/${_rp})
    endforeach ()

    # Install third-party Lua libraries
    install(FILES "contrib/lua-fun/fun.lua" DESTINATION ${LUALIBDIR})
    install(FILES "contrib/lua-argparse/argparse.lua" DESTINATION ${LUALIBDIR})
    install(FILES "contrib/lua-tableshape/tableshape.lua" DESTINATION ${LUALIBDIR})
    install(FILES "contrib/lua-lupa/lupa.lua" DESTINATION ${LUALIBDIR})
    install(FILES "contrib/lua-lpeg/lpegre.lua" DESTINATION ${LUALIBDIR})

    # Install systemd unit if on Linux and requested
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WANT_SYSTEMD_UNITS)
        install(FILES "rspamd.service" DESTINATION ${SYSTEMDDIR})
    endif ()

    # Install man pages
    install(FILES "doc/rspamd.8" DESTINATION ${MANDIR}/man8)
    install(FILES "doc/rspamc.1" DESTINATION ${MANDIR}/man1)
    install(FILES "doc/rspamadm.1" DESTINATION ${MANDIR}/man1)

    # Install utilities
    install(PROGRAMS "utils/rspamd_stats.pl" RENAME rspamd_stats DESTINATION bin)

    # Install web UI if requested
    if (INSTALL_WEBUI)
        install(DIRECTORY "interface/" DESTINATION ${WWWDIR} PATTERN ".git" EXCLUDE)
    endif ()

    # Log installation paths
    message(STATUS "Rspamd will be installed in the following directories:")
    message(STATUS "  - Binaries: ${CMAKE_INSTALL_PREFIX}/bin")
    message(STATUS "  - Configuration: ${CONFDIR}")
    message(STATUS "  - Rules: ${RULESDIR}")
    message(STATUS "  - Lua libraries: ${LUALIBDIR}")
    message(STATUS "  - Plugins: ${PLUGINSDIR}")
    message(STATUS "  - Shared data: ${SHAREDIR}")
    if (INSTALL_WEBUI)
        message(STATUS "  - Web UI: ${WWWDIR}")
    endif ()
endfunction()
