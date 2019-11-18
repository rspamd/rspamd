# Find lua installation
MACRO(FindLua)
    # Find lua libraries
    UNSET(LUA_INCLUDE_DIR CACHE)
    UNSET(LUA_LIBRARY CACHE)
    CMAKE_PARSE_ARGUMENTS(LUA "" "VERSION_MAJOR;VERSION_MINOR;ROOT" "" ${ARGN})

    IF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
        MESSAGE(FATAL_ERROR "Invalid FindLua invocation: ${ARGN}")
    ENDIF()

    IF(ENABLE_LUAJIT MATCHES "ON")
        MESSAGE(STATUS "Check for luajit ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
        FIND_PATH(LUA_INCLUDE_DIR luajit.h
                HINTS
                "${RSPAMD_SEARCH_PATH}" "${LUA_ROOT}"
                $ENV{LUA_DIR}
                PATH_SUFFIXES "include/luajit-2.0"
                "include/luajit-2.1"
                "include/luajit${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                "include/luajit${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                "include/luajit-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                "include/luajit-${LUA_VERSION_MAJOR}_${LUA_VERSION_MINOR}-2.0"
                "include/luajit-${LUA_VERSION_MAJOR}_${LUA_VERSION_MINOR}-2.1"
                "include/luajit"
                "include/lua${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                "include/lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                "include/lua-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                include/lua include
                PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
                )
        FIND_LIBRARY(LUA_LIBRARY
                NAMES luajit
                "luajit-2.0"
                "luajit2.0"
                "luajit${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                "luajit${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                "luajit-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                HINTS
                "${RSPAMD_SEARCH_PATH}" "${LUA_ROOT}"
                $ENV{LUA_DIR}
                PATH_SUFFIXES lib64 lib
                PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
                DOC "Lua library"
                )

        IF(NOT LUA_LIBRARY OR NOT LUA_INCLUDE_DIR)
            MESSAGE(STATUS "Fallback from luajit to plain lua")
            SET(ENABLE_LUAJIT "OFF")
            MESSAGE(STATUS "Check for lua ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
            FIND_PATH(LUA_INCLUDE_DIR lua.h
                    HINTS
                    "${RSPAMD_SEARCH_PATH}" "${LUA_ROOT}"
                    $ENV{LUA_DIR}
                    PATH_SUFFIXES "include/lua${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                    "include/lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                    "include/lua-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                    include/lua include
                    PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
                    )
            FIND_LIBRARY(LUA_LIBRARY
                    NAMES lua
                    "lua${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                    "lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                    "lua-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                    HINTS
                    "${RSPAMD_SEARCH_PATH}" "${LUA_ROOT}"
                    $ENV{LUA_DIR}
                    PATH_SUFFIXES lib64 lib
                    PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
                    DOC "Lua library"
                    )
        ELSE()
            SET(WITH_LUAJIT 1)
        ENDIF()
    ELSE(ENABLE_LUAJIT MATCHES "ON")
        MESSAGE(STATUS "Check for lua ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
        FIND_PATH(LUA_INCLUDE_DIR lua.h
                HINTS
                "${RSPAMD_SEARCH_PATH}" "${LUA_ROOT}"
                $ENV{LUA_DIR}
                PATH_SUFFIXES "include/lua${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                "include/lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                "include/lua-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                include/lua include
                PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
                )
        FIND_LIBRARY(LUA_LIBRARY
                NAMES lua
                "lua${LUA_VERSION_MAJOR}${LUA_VERSION_MINOR}"
                "lua${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                "lua-${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}"
                HINTS
                "${RSPAMD_SEARCH_PATH}" "${LUA_ROOT}"
                $ENV{LUA_DIR}
                PATH_SUFFIXES lib64 lib
                PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
                DOC "Lua library"
                )
    ENDIF(ENABLE_LUAJIT MATCHES "ON")

    IF(LUA_LIBRARY AND LUA_INCLUDE_DIR)
        SET(LUA_FOUND 1)
        IF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
            SET(LUA_VERSION_MAJOR ${LUA_VERSION_MAJOR})
            SET(LUA_VERSION_MINOR ${LUA_VERSION_MINOR})
        ENDIF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
        IF(ENABLE_LUAJIT MATCHES "ON")
            MESSAGE(STATUS "Found luajit ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR} in lib:${LUA_LIBRARY}, headers:${LUA_INCLUDE_DIR}")
        ELSE(ENABLE_LUAJIT MATCHES "ON")
            MESSAGE(STATUS "Found lua ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR} in lib:${LUA_LIBRARY}, headers:${LUA_INCLUDE_DIR}")
        ENDIF(ENABLE_LUAJIT MATCHES "ON")
    ENDIF(LUA_LIBRARY AND LUA_INCLUDE_DIR)
ENDMACRO()