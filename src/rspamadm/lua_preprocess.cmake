FOREACH(_LUA_SRC ${RSPAMADMLUASRC})
    GET_FILENAME_COMPONENT(_LUA_BASE ${_LUA_SRC} NAME_WE)
    FILE(READ ${_LUA_SRC} _FILE_DATA)
    STRING(REPLACE \" \\\" _OUT1 ${_FILE_DATA})
    # Convert into cmake list
    STRING(REGEX REPLACE ";" "\\\\;" _OUT2 "${_OUT1}")
    STRING(REPLACE "\n" ";" _OUT3 "${_OUT2}")
    FILE(WRITE "${CMAKE_CURRENT_BINARY_DIR}/${_LUA_BASE}.lua.h" "
#ifndef ${_LUA_BASE}_H
#define ${_LUA_BASE}_H

static const char rspamadm_script_${_LUA_BASE}[] = \"\"
")
    FOREACH(_LINE ${_OUT3})
        STRING(REGEX REPLACE "^(.+)$" "\"\\1\\\\n\"\n" _OUT4 "${_LINE}")
        FILE(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${_LUA_BASE}.lua.h" ${_OUT4})
    ENDFOREACH()

    FILE(APPEND "${CMAKE_CURRENT_BINARY_DIR}/${_LUA_BASE}.lua.h" "\"\";
#endif
")
ENDFOREACH()
