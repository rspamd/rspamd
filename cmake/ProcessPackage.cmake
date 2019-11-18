# Process required package by using FindPackage and calling for INCLUDE_DIRECTORIES and
# setting list of required libraries
# Usage:
# ProcessPackage(VAR [OPTIONAL] [ROOT path] [INCLUDE path]
#	[LIBRARY path] [INCLUDE_SUFFIXES path1 path2 ...] [LIB_SUFFIXES path1 path2 ...]
#	[MODULES module1 module2 ...])
# params:
# OPTIONAL - do not fail if a package has not been found
# ROOT - defines root directory for a package
# INCLUDE - name of the include file to check
# LIBRARY - name of the library to check
# INCLUDE_SUFFIXES - list of include suffixes (relative to ROOT)
# LIB_SUFFIXES - list of library suffixes
# MODULES - modules to search using pkg_config
MACRO(ProcessPackage PKG_NAME)

    CMAKE_PARSE_ARGUMENTS(PKG "OPTIONAL;OPTIONAL_INCLUDE" "ROOT;INCLUDE"
            "LIBRARY;INCLUDE_SUFFIXES;LIB_SUFFIXES;MODULES;LIB_OUTPUT" ${ARGN})

    IF(NOT PKG_LIBRARY)
        SET(PKG_LIBRARY "${PKG_NAME}")
    ENDIF()
    IF(NOT PKG_INCLUDE)
        SET(PKG_INCLUDE "${PKG_NAME}.h")
    ENDIF()
    IF(NOT PKG_LIB_OUTPUT)
        SET(PKG_LIB_OUTPUT RSPAMD_REQUIRED_LIBRARIES)
    ENDIF()

    IF(NOT PKG_ROOT AND PKG_MODULES)
        PKG_SEARCH_MODULE(${PKG_NAME} ${PKG_MODULES})
    ENDIF()

    IF(${PKG_NAME}_FOUND)
        MESSAGE(STATUS "Found package ${PKG_NAME} in pkg-config modules ${PKG_MODULES}")
        SET(WITH_${PKG_NAME} 1 CACHE INTERNAL "")
        IF(ENABLE_STATIC MATCHES "ON")
            SET(_XPREFIX "${PKG_NAME}_STATIC")
        ELSE(ENABLE_STATIC MATCHES "ON")
            SET(_XPREFIX "${PKG_NAME}")
        ENDIF(ENABLE_STATIC MATCHES "ON")
        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
            INCLUDE_DIRECTORIES("${_arg}")
            SET(${PKG_NAME}_INCLUDE "${_arg}" CACHE INTERNAL "")
        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
            LINK_DIRECTORIES("${_arg}")
            SET(${PKG_NAME}_LIBRARY_PATH "${_arg}" CACHE INTERNAL "")
        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
        # Handle other CFLAGS and LDFLAGS
        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
        LIST(APPEND ${PKG_LIB_OUTPUT} "${${_XPREFIX}_LIBRARIES}")
        INCLUDE_DIRECTORIES(${${_XPREFIX}_INCLUDEDIR})
    ELSE()
        IF(NOT ${PKG_NAME}_GUESSED)
            # Try some more heuristic
            FIND_LIBRARY(_lib NAMES ${PKG_LIBRARY}
                    HINTS ${PKG_ROOT} ${RSPAMD_SEARCH_PATH}
                    PATH_SUFFIXES ${PKG_LIB_SUFFIXES} lib64 lib
                    PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS})
            IF(NOT _lib)
                IF(PKG_OPTIONAL)
                    MESSAGE(STATUS "Cannot find library ${PKG_LIBRARY} for package ${PKG_NAME}, ignoring")
                ELSE()
                    MESSAGE(FATAL_ERROR "Cannot find library ${PKG_LIBRARY} for package ${PKG_NAME}")
                ENDIF()
            ENDIF(NOT _lib)

            FIND_PATH(_incl ${PKG_INCLUDE}
                    HINTS ${PKG_ROOT} ${RSPAMD_SEARCH_PATH}
                    PATH_SUFFIXES ${PKG_INCLUDE_SUFFIXES} include
                    PATHS 	{RSPAMD_DEFAULT_INCLUDE_PATHS})
            IF(NOT _incl)
                IF(PKG_OPTIONAL OR PKG_OPTIONAL_INCLUDE)
                    MESSAGE(STATUS "Cannot find header ${PKG_INCLUDE} for package ${PKG_NAME}")
                ELSE()
                    MESSAGE(FATAL_ERROR "Cannot find header ${PKG_INCLUDE} for package ${PKG_NAME}")
                ENDIF()
            ELSE()
                STRING(REGEX REPLACE "/[^/]+$" "" _incl_path "${PKG_INCLUDE}")
                STRING(REGEX REPLACE "${_incl_path}/$" "" _stripped_incl "${_incl}")
                INCLUDE_DIRECTORIES("${_stripped_incl}")
                SET(${PKG_NAME}_INCLUDE "${_stripped_incl}" CACHE INTERNAL "")
            ENDIF(NOT _incl)

            IF(_lib)
                # We need to apply heuristic to find the real dir name
                GET_FILENAME_COMPONENT(_lib_path "${_lib}" PATH)
                LINK_DIRECTORIES("${_lib_path}")
                LIST(APPEND ${PKG_LIB_OUTPUT} ${_lib})
                SET(${PKG_NAME}_LIBRARY_PATH "${_lib_path}" CACHE INTERNAL "")
                SET(${PKG_NAME}_LIBRARY "${_lib}" CACHE INTERNAL "")
            ENDIF()

            IF(_incl AND _lib)
                MESSAGE(STATUS "Found package ${PKG_NAME} in '${_lib_path}' (${_lib}) and '${_stripped_incl}' (${PKG_INCLUDE}).")
                SET(${PKG_NAME}_GUESSED 1 CACHE INTERNAL "")
                SET(WITH_${PKG_NAME} 1 CACHE INTERNAL "")
            ELSEIF(_lib)
                IF(PKG_OPTIONAL_INCLUDE)
                    SET(${PKG_NAME}_GUESSED 1 INTERNAL "")
                    SET(WITH_${PKG_NAME} 1 INTERNAL "")
                ENDIF()
                MESSAGE(STATUS "Found incomplete package ${PKG_NAME} in '${_lib_path}' (${_lib}); no includes.")
            ENDIF()
        ELSE()
            MESSAGE(STATUS "Found package ${PKG_NAME} (cached)")
            INCLUDE_DIRECTORIES("${${PKG_NAME}_INCLUDE}")
            LINK_DIRECTORIES("${${PKG_NAME}_LIBRARY_PATH}")
            LIST(APPEND ${PKG_LIB_OUTPUT} "${${PKG_NAME}_LIBRARY}")
        ENDIF()
    ENDIF(${PKG_NAME}_FOUND)

    UNSET(_lib CACHE)
    UNSET(_incl CACHE)
ENDMACRO(ProcessPackage name)