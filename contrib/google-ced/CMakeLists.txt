# Copyright 2016 Google Inc.  All Rights Reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

project(CED CXX)
set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS 1 CACHE INTERNAL "No dev warnings")

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-narrowing")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-c++11-narrowing")
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CED_LIBRARY_SOURCES
    compact_enc_det.cc
    compact_enc_det_hint_code.cc
    util/encodings/encodings.cc
    util/languages/languages.cc
    ced_c.cc
    )

add_library(rspamd-ced STATIC ${CED_LIBRARY_SOURCES})
