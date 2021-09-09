cmake_minimum_required(VERSION 3.0)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

################################################################################
## DOCTEST
################################################################################

project(doctest VERSION 2.4.6 LANGUAGES CXX)

# Determine if doctest is built as a subproject (using add_subdirectory) or if it is the main project.
set(MAIN_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MAIN_PROJECT ON)
endif()

option(DOCTEST_WITH_TESTS               "Build tests/examples" ${MAIN_PROJECT})
option(DOCTEST_WITH_MAIN_IN_STATIC_LIB  "Build a static lib (cmake target) with a default main entry point" ON)
option(DOCTEST_NO_INSTALL  "Skip the installation process" OFF)
option(DOCTEST_USE_STD_HEADERS  "Use std headers" OFF)

add_library(${PROJECT_NAME} INTERFACE)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

if(NOT CMAKE_VERSION VERSION_LESS 3.8)
    target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_11)
endif()

set(doctest_parts_folder "${CMAKE_CURRENT_SOURCE_DIR}/doctest/parts")
set(doctest_folder "${CMAKE_CURRENT_SOURCE_DIR}/") # in order to have the mpi extension files, not included into the doctest.h single header

if(MAIN_PROJECT)
    # use a special hidden version of the header which directly includes the 2 parts - proper reporting of file/line locations during dev
    target_include_directories(${PROJECT_NAME} INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/scripts/development_only/>
        $<BUILD_INTERFACE:${doctest_parts_folder}>
        $<BUILD_INTERFACE:${doctest_folder}>)

    # add a custom target that assembles the single header when any of the parts are touched
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/doctest/doctest.h
        DEPENDS
            ${doctest_parts_folder}/doctest_fwd.h
            ${doctest_parts_folder}/doctest.cpp
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/assemble_single_header.cmake
        COMMENT "assembling the single header")

    add_custom_target(assemble_single_header ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/doctest/doctest.h)
else()
    target_include_directories(${PROJECT_NAME} INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>)
endif()

# hack to support building on XCode 6 and 7 - propagate the definition to everything
if(DEFINED DOCTEST_THREAD_LOCAL)
    target_compile_definitions(${PROJECT_NAME} INTERFACE
        DOCTEST_THREAD_LOCAL=${DOCTEST_THREAD_LOCAL})
endif()

if(DOCTEST_USE_STD_HEADERS)
    target_compile_definitions(${PROJECT_NAME} INTERFACE DOCTEST_CONFIG_USE_STD_HEADERS)
endif()
