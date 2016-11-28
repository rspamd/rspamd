# - Try to find LuaJIT
# Once done this will define
#
#  LUAJIT_FOUND - system has LuaJIT
#  LUAJIT_INCLUDE_DIR - the LuaJIT include directory
#  LUAJIT_LIBRARIES - Link these to use LuaJIT
#  LUAJIT_DEFINITIONS - Compiler switches required for using LuaJIT
#
#=============================================================================
#  Copyright (c) 2016 Andrea Schneider <asn@cryptomilk.org>
#
#  Distributed under the OSI-approved BSD License (the "License");
#  see accompanying file Copyright.txt for details.
#
#  This software is distributed WITHOUT ANY WARRANTY; without even the
#  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the License for more information.
#=============================================================================
#

if (UNIX)
  find_package(PkgConfig)
  if (PKG_CONFIG_FOUND)
    pkg_check_modules(_LUAJIT luajit)
  endif (PKG_CONFIG_FOUND)
endif (UNIX)

set(_LUAJIT_ROOT_HINTS
    ${RSPAMD_SEARCH_PATH}
    ${LUAJIT_ROOT_DIR}
    ENV LUAJIT_ROOT_DIR
)

find_path(LUAJIT_INCLUDE_DIR
    NAMES
        luajit.h
    PATHS
        ${_LUAJIT_INCLUDEDIR}
    HINTS
        ${_LUAJIT_ROOT_HINTS}
    PATH_SUFFIXES
        luajit-5_1-2.0
        luajit-5_2-2.0
        luajit-5_3-2.0
)

find_library(LUAJIT_LIBRARY
    NAMES
        luajit
        luajit-5.1
        luajit-5.2
        luajit-5.3
    HINTS
        ${_LUAJIT_ROOT_HINTS}
    PATHS
        ${_LUAJIT_LIBDIR}
)

if (LUAJIT_LIBRARY)
    set(LUAJIT_LIBRARIES
        ${LUAJIT_LIBRARIES}
        ${LUAJIT_LIBRARY}
    )
endif (LUAJIT_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LuaJIT DEFAULT_MSG LUAJIT_LIBRARIES LUAJIT_INCLUDE_DIR)

# show the LUAJIT_INCLUDE_DIR and LUAJIT_LIBRARIES variables only in the advanced view
mark_as_advanced(LUAJIT_INCLUDE_DIR LUAJIT_LIBRARIES)

