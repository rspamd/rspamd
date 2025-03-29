#
# Rspamd - rapid antispam system
#
# Cmake configuration file
#

############################# INITIAL SECTION #############################################
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# Define version variables
set(RSPAMD_VERSION_MAJOR 3)
set(RSPAMD_VERSION_MINOR 11)
set(RSPAMD_VERSION_PATCH 2)

# Keep two digits all the time
set(RSPAMD_VERSION_MAJOR_NUM ${RSPAMD_VERSION_MAJOR}0)
set(RSPAMD_VERSION_MINOR_NUM ${RSPAMD_VERSION_MINOR}0)
set(RSPAMD_VERSION_PATCH_NUM ${RSPAMD_VERSION_PATCH}0)

if (GIT_ID)
    set(GIT_VERSION 1)
    set(RSPAMD_ID "${GIT_ID}")
endif ()

set(RSPAMD_VERSION "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}")

project(rspamd
        VERSION "${RSPAMD_VERSION}"
        LANGUAGES C CXX ASM
        DESCRIPTION "Rapid spam filtering system"
        HOMEPAGE_URL "https://rspamd.com"
)

cmake_policy(SET CMP0075 NEW)

# Language standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

set(RSPAMD_MASTER_SITE_URL "https://rspamd.com")

if (NOT RSPAMD_USER)
    set(RSPAMD_USER "nobody")
    set(RSPAMD_GROUP "nobody")
endif ()

# Default for SysV Init
set(RSPAMD_WORKER_NORMAL "*:11333")
set(RSPAMD_WORKER_CONTROLLER "*:11334")

############################# OPTIONS SECTION #############################################
option(ENABLE_LUAJIT "Link with libluajit" ON)
option(ENABLE_URL_INCLUDE "Enable URLs in UCL includes (requires libcurl or libfetch)" OFF)
option(NO_SHARED "Build internal libs static" ON)
option(INSTALL_WEBUI "Install web interface" ON)
option(INSTALL_EXAMPLES "Install examples of the configuration and Lua" ON)
option(WANT_SYSTEMD_UNITS "Install systemd unit files on Linux" OFF)
option(ENABLE_SNOWBALL "Enable snowball stemmer" ON)
option(ENABLE_CLANG_PLUGIN "Enable clang static analysing plugin" OFF)
option(ENABLE_PCRE2 "Enable pcre2 instead of pcre" ON)
option(ENABLE_JEMALLOC "Build rspamd with jemalloc allocator" OFF)
option(ENABLE_UTILS "Build rspamd internal utils" OFF)
option(ENABLE_LIBUNWIND "Obsoleted" OFF) # Deprecated option
option(ENABLE_LUA_TRACE "Trace all Lua C API invocations" OFF)
option(ENABLE_FASTTEXT "Link with FastText library" OFF)
option(ENABLE_BACKWARD "Build rspamd with backward-cpp stacktrace" ON)
option(SYSTEM_ZSTD "Use system zstd instead of bundled one" OFF)
option(SYSTEM_DOCTEST "Use system doctest instead of bundled one" OFF)
option(SYSTEM_XXHASH "Use system xxhash instead of bundled one" OFF)

############################# INCLUDE SECTION #############################################

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckLibraryExists)
include(CheckCCompilerFlag)
include(CMakeParseArguments)
include(FindArch)
include(AsmOp)
include(FindRagel)
include(ProcessPackage)

if (NOT RAGEL_FOUND)
    message(FATAL_ERROR "Ragel is required to build rspamd")
endif ()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Perl REQUIRED)

# Sanitizer setup
option(SANITIZE "Enable sanitizer: address, memory, undefined, leak (comma separated list)" "")
include(Toolset)
include(Sanitizer)

include(ArchDep)
include(Paths)

include(OSDep)
ConfigurePlatformSpecifics()

if (ENABLE_PCRE2)
    set(WITH_PCRE2 1)
    # For utf8 API
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-DPCRE2_CODE_UNIT_WIDTH=8")
endif ()

############################# CONFIG SECTION #############################################
# Include directories
# Prefer local include dirs to system ones
include_directories(
        "${CMAKE_SOURCE_DIR}/"
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/src/libutil"
        "${CMAKE_SOURCE_DIR}/src/libserver"
        "${CMAKE_SOURCE_DIR}/src/libmime"
        "${CMAKE_SOURCE_DIR}/src/libstat"
        "${CMAKE_SOURCE_DIR}/src/libcryptobox"
        "${CMAKE_SOURCE_DIR}/contrib/libucl"
        "${CMAKE_SOURCE_DIR}/contrib/replxx/include"
        "${CMAKE_SOURCE_DIR}/contrib/uthash"
        "${CMAKE_SOURCE_DIR}/contrib/http-parser"
        "${CMAKE_SOURCE_DIR}/contrib/fpconv"
        "${CMAKE_SOURCE_DIR}/contrib/libottery"
        "${CMAKE_SOURCE_DIR}/contrib/cdb"
        "${CMAKE_SOURCE_DIR}/contrib/snowball/include"
        "${CMAKE_SOURCE_DIR}/contrib/librdns"
        "${CMAKE_SOURCE_DIR}/contrib/aho-corasick"
        "${CMAKE_SOURCE_DIR}/contrib/lc-btrie"
        "${CMAKE_SOURCE_DIR}/contrib/lua-lpeg"
        "${CMAKE_SOURCE_DIR}/contrib/frozen/include"
        "${CMAKE_SOURCE_DIR}/contrib/fu2/include"
        "${CMAKE_BINARY_DIR}/src" # Stored in the binary dir
        "${CMAKE_BINARY_DIR}/src/libcryptobox"
)

set(TAR "tar")
include(OSDep)

# Now find libraries and headers
list(APPEND RSPAMD_REQUIRED_LIBRARIES "m")
list(APPEND RSPAMD_REQUIRED_LIBRARIES "pthread")

# Lua setup
if (ENABLE_LUAJIT)
    ProcessPackage(LIBLUAJIT LIBRARY "luajit"
            "luajit-2.1"
            "luajit2.1"
            "luajit-2.0"
            "luajit2.0"
            "luajit-5.1"
            INCLUDE luajit.h INCLUDE_SUFFIXES
            "include/luajit-2.1"
            "include/luajit-2.0"
            "include/luajit"
            ROOT ${LUA_ROOT}
            MODULES luajit)
    set(WITH_LUAJIT 1)
else ()
    # Try to find Lua (5.3, 5.4, 5.2, or 5.1 in that order)
    ProcessPackage(LIBLUA LIBRARY "lua"
            "lua-5.3"
            LIB_SUFFIXES "lua5.3"
            INCLUDE lua.h INCLUDE_SUFFIXES
            "include/lua-5.3"
            "include/lua5.3"
            "include/lua53"
            "include/lua"
            ROOT ${LUA_ROOT}
            MODULES lua53
            OPTIONAL)

    if (NOT WITH_LIBLUA)
        ProcessPackage(LIBLUA LIBRARY "lua"
                "lua-5.4"
                LIB_SUFFIXES "lua5.4"
                INCLUDE lua.h INCLUDE_SUFFIXES
                "include/lua-5.4"
                "include/lua5.4"
                "include/lua54"
                "include/lua"
                ROOT ${LUA_ROOT}
                MODULES lua54
                OPTIONAL)
        if (NOT WITH_LIBLUA)
            ProcessPackage(LIBLUA LIBRARY "lua"
                    "lua-5.2"
                    LIB_SUFFIXES "lua5.2"
                    INCLUDE lua.h INCLUDE_SUFFIXES
                    "include/lua-5.2"
                    "include/lua5.2"
                    "include/lua52"
                    "include/lua"
                    ROOT ${LUA_ROOT}
                    MODULES lua52
                    OPTIONAL)

            if (NOT WITH_LIBLUA)
                ProcessPackage(LIBLUA LIBRARY "lua"
                        "lua-5.1"
                        INCLUDE lua.h INCLUDE_SUFFIXES
                        "include/lua-5.1"
                        "include/lua5.1"
                        "include/lua51"
                        "include/lua"
                        ROOT ${LUA_ROOT}
                        MODULES lua51)
            endif ()
        endif ()
    endif ()
endif ()

# Memory allocator
if (ENABLE_JEMALLOC AND NOT SANITIZE)
    ProcessPackage(JEMALLOC LIBRARY jemalloc_pic jemalloc INCLUDE jemalloc/jemalloc.h
            ROOT ${JEMALLOC_ROOT_DIR})
    set(WITH_JEMALLOC "1")
endif ()

# Required libraries
ProcessPackage(GLIB2 LIBRARY glib-2.0 INCLUDE glib.h
        INCLUDE_SUFFIXES include/glib include/glib-2.0
        ROOT ${GLIB_ROOT_DIR} MODULES glib-2.0>=2.28)

# PCRE setup
if (ENABLE_PCRE2)
    ProcessPackage(PCRE LIBRARY pcre2 pcre2-8 INCLUDE pcre2.h INCLUDE_SUFFIXES include/pcre2
            ROOT ${PCRE_ROOT_DIR} MODULES pcre2 pcre2-8 libpcre2 libpcre2-8)
else ()
    ProcessPackage(PCRE LIBRARY pcre INCLUDE pcre.h INCLUDE_SUFFIXES include/pcre
            ROOT ${PCRE_ROOT_DIR} MODULES pcre libpcre pcre3 libpcre3)
endif ()

# Other dependencies
ProcessPackage(SQLITE3 LIBRARY sqlite3 INCLUDE sqlite3.h INCLUDE_SUFFIXES include/sqlite3 include/sqlite
        ROOT ${SQLITE3_ROOT_DIR} MODULES sqlite3 sqlite)
ProcessPackage(ICUDATA LIBRARY icudata INCLUDE unicode/ucnv.h
        ROOT ${ICU_ROOT_DIR} MODULES icu-uc)
ProcessPackage(ICUC LIBRARY icuuc INCLUDE unicode/ucnv.h
        ROOT ${ICU_ROOT_DIR} MODULES icu-uc)
ProcessPackage(ICUIO LIBRARY icuio INCLUDE unicode/ucnv.h
        ROOT ${ICU_ROOT_DIR} MODULES icu-io)
ProcessPackage(ICUI18N LIBRARY icui18n INCLUDE unicode/ucnv.h
        ROOT ${ICU_ROOT_DIR} MODULES icu-i18n)
ProcessPackage(LIBCRYPT LIBRARY crypto INCLUDE openssl/evp.h
        ROOT ${OPENSSL_ROOT_DIR} MODULES openssl libcrypt)
ProcessPackage(LIBSSL LIBRARY ssl INCLUDE openssl/ssl.h
        ROOT ${OPENSSL_ROOT_DIR} MODULES openssl libssl)
ProcessPackage(LIBZ LIBRARY z INCLUDE zlib.h INCLUDE_SUFFIXES include/zlib
        ROOT ${LIBZ_ROOT_DIR} MODULES z)
ProcessPackage(SODIUM LIBRARY sodium INCLUDE sodium.h
        INCLUDE_SUFFIXES include/libsodium include/sodium
        ROOT ${LIBSODIUM_ROOT_DIR} MODULES libsodium>=1.0.0)
ProcessPackage(LIBARCHIVE LIBRARY archive INCLUDE archive.h
        ROOT ${LIBARCHIVE_ROOT_DIR} MODULES libarchive>=3.0.0)

if (ENABLE_FASTTEXT)
    ProcessPackage(FASTTEXT LIBRARY fasttext INCLUDE fasttext/fasttext.h
            ROOT ${FASTTEXT_ROOT_DIR} MODULES fasttext)
    set(WITH_FASTTEXT "1")
endif ()

# Include common compiler and platform specific configurations
include(CompilerWarnings)
include(Hyperscan)
include(Openblas)

# Lua tracing
if (ENABLE_LUA_TRACE)
    set(WITH_LUA_TRACE 1)
endif ()

# Configure compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_CXX_FLAGS}")

# Define macros for compilation
add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DDOCTEST_CONFIG_NO_MULTI_LANE_ATOMICS)
add_definitions(-DFMT_HEADER_ONLY)
# Workaround for https://github.com/onqtam/doctest/issues/356
add_definitions(-DDOCTEST_CONFIG_USE_STD_HEADERS)
add_definitions(-DU_CHARSET_IS_UTF8)
# Disable zstd deprecation warnings, as they are not relevant for us
add_definitions(-DZSTD_DISABLE_DEPRECATE_WARNINGS)

# Check platform specific includes
include(CheckSystemHeaders)

# Check macros, functions, and features
include(CheckSystemFeatures)

# Check symbols and functions
include(CheckSymbols)

# Configure PIC support
check_c_compiler_flag(-fPIC SUPPORT_FPIC)
if (SUPPORT_FPIC)
    add_compile_options("-fPIC")
endif ()

# Support for URL includes
include(CheckURLInclude)
if (ENABLE_URL_INCLUDE)
    CheckURLIncludeSupport()
endif ()

# Ensure DESTDIR is set
if (NOT DESTDIR)
    set(DESTDIR $ENV{DESTDIR})
endif ()

################################ SUBDIRS SECTION ###########################
# Add required subdirectories for dependencies
include(AddDependencySubdirectories)
AddDependencySubdirectories()

############################ TARGETS SECTION ###############################

# Generate config.h
configure_file(config.h.in src/config.h)

##################### INSTALLATION ##########################################
# Setup installation targets
include(InstallRspamdFiles)
InstallRspamdFiles()

# Build distribution and testing targets
add_custom_target(dist ${CMAKE_SOURCE_DIR}/dist.sh
        "${CMAKE_BINARY_DIR}/rspamd-${RSPAMD_VERSION}.tar.xz" "${TAR}"
        COMMENT "Create source distribution"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Tests
# Include CTest for testing support
include(CTest)
enable_testing()
add_subdirectory(test)

add_custom_target(check DEPENDS rspamd-test-cxx rspamd-test)
add_custom_target(run-test DEPENDS check
        COMMAND test/rspamd-test-cxx
        COMMAND sh -c 'LUA_PATH="${CMAKE_SOURCE_DIR}/lualib/?.lua\;${CMAKE_SOURCE_DIR}/lualib/?/?.lua\;${CMAKE_SOURCE_DIR}/lualib/?/init.lua\;${CMAKE_SOURCE_DIR}/contrib/lua-?/?.lua"
        test/rspamd-test -p /rspamd/lua')

# Setup PVS Studio if available
include(SetupPVSStudio)
SetupPVSStudio()
