#
# Rspamd - rambler antispam system
#
# Cmake configuration file
#

############################# INITIAL SECTION #############################################

PROJECT(rspamd C)

SET(RSPAMD_VERSION_MAJOR 0)
SET(RSPAMD_VERSION_MINOR 7)
SET(RSPAMD_VERSION_PATCH 0)

SET(RSPAMD_VERSION         "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}")
SET(RSPAMD_MASTER_SITE_URL "https://rspamd.com")

IF(NOT RSPAMD_USER)
	SET(RSPAMD_USER "nobody")
	SET(RSPAMD_GROUP "nobody")
ENDIF(NOT RSPAMD_USER)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)

############################# OPTIONS SECTION #############################################

OPTION(DEBUG_MODE          "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(SKIP_RELINK_RPATH   "Skip relinking and full RPATH for the install tree" OFF)
OPTION(ENABLE_REDIRECTOR   "Enable redirector install [default: OFF]"           OFF)
OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]"             OFF)
OPTION(ENABLE_STATIC       "Enable static compiling [default: OFF]"             OFF)
OPTION(ENABLE_LUAJIT       "Link with libluajit [default: OFF]"                 OFF)
OPTION(ENABLE_DB           "Find and link with DB library [default: OFF]"       OFF)
OPTION(ENABLE_SQLITE       "Find and link with sqlite3 library [default: OFF]"  OFF)
OPTION(ENABLE_HIREDIS      "Find and link with external redis library [default: OFF]"  OFF)
OPTION(ENABLE_URL_INCLUDE  "Enable urls in ucl includes (requires libcurl or libfetch) [default: OFF]" OFF)
OPTION(NO_SHARED           "Build internal libs static [default: OFF]"          OFF)
OPTION(FORCE_GMIME24       "Link with gmime2.4 [default: OFF]"                  OFF)
OPTION(INSTALL_EXAMPLES    "Install examples [default: OFF]"                    OFF)

# Build optimized code for following CPU (default i386)
#SET(CPU_TUNE               "i686")

# Now CMAKE_INSTALL_PREFIX is a base prefix for everything
# CONFDIR - for configuration
# MANDIR - for manual pages
# RUNDIR - for runtime files
# DBDIR - for static files
# LOGDIR - for log files
# EXAMPLESDIR - for examples files

IF(NOT CONFDIR)
	SET(CONFDIR "${CMAKE_INSTALL_PREFIX}/etc/rspamd")
ENDIF(NOT CONFDIR)

IF(NOT MANDIR)
	SET(MANDIR "${CMAKE_INSTALL_PREFIX}/share/man")
ENDIF(NOT MANDIR)

IF(NOT RUNDIR)
	SET(RUNDIR "${CMAKE_INSTALL_PREFIX}/var/run/rspamd")
ENDIF(NOT RUNDIR)

IF(NOT DBDIR)
	SET(DBDIR "${CMAKE_INSTALL_PREFIX}/var/lib/rspamd")
ENDIF(NOT DBDIR)

IF(NOT LOGDIR)
	SET(LOGDIR "${CMAKE_INSTALL_PREFIX}/var/log/rspamd")
ENDIF(NOT LOGDIR)

IF(NOT EXAMPLESDIR)
	SET(EXAMPLESDIR "${CMAKE_INSTALL_PREFIX}/share/examples/rspamd")
ENDIF(NOT EXAMPLESDIR)

IF(NOT PLUGINSDIR)
	SET(PLUGINSDIR "${CMAKE_INSTALL_PREFIX}/share/rspamd")
ENDIF(NOT PLUGINSDIR)

# Set libdir
IF(NOT LIBDIR)
	SET(LIBDIR lib/rspamd)
	IF(NOT CMAKE_INSTALL_RPATH)
		SET(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${LIBDIR})
	ENDIF(NOT CMAKE_INSTALL_RPATH)
ENDIF(NOT LIBDIR)

# Set includedir
IF(NOT INCLUDEDIR)
	SET(INCLUDEDIR include/rspamd)
ENDIF(NOT INCLUDEDIR)

IF(NOT SYSTEMDDIR)
	SET(SYSTEMDDIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
ENDIF(NOT SYSTEMDDIR)

############################# INCLUDE SECTION #############################################

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)
INCLUDE(FindPkgConfig)
INCLUDE(CheckCCompilerFlag)
INCLUDE(FindPerl)
INCLUDE(FindOpenSSL)

############################# MODULES SECTION #############################################

MACRO(_AddModulesForced MLIST WLIST)
# Generate unique string for this build
	STRING(RANDOM LENGTH 8 _MODULES_ID)
	SET(MODULES_ID ${_MODULES_ID} CACHE INTERNAL "Modules ID" FORCE)
	FILE(WRITE "src/modules.c" "/* ${MODULES_ID} */\n#include \"config.h\"\n")
	
	# Handle even old cmake
	LIST(LENGTH ${MLIST} MLIST_COUNT)
	LIST(LENGTH ${WLIST} WLIST_COUNT)
	MATH(EXPR MLIST_MAX ${MLIST_COUNT}-1)
	MATH(EXPR WLIST_MAX ${WLIST_COUNT}-1)
	
	FOREACH(MOD_IDX RANGE ${MLIST_MAX})
		LIST(GET ${MLIST} ${MOD_IDX} MOD)
		FILE(APPEND "src/modules.c" "extern module_t ${MOD}_module;\n")
	ENDFOREACH(MOD_IDX RANGE ${MLIST_MAX})
		 
	FILE(APPEND "src/modules.c" "\n\nmodule_t *modules[] = {\n")
	
	FOREACH(MOD_IDX RANGE ${MLIST_MAX})
		LIST(GET ${MLIST} ${MOD_IDX} MOD)
		FILE(APPEND "src/modules.c" "&${MOD}_module,\n")
	ENDFOREACH(MOD_IDX RANGE ${MLIST_MAX})
	
	FILE(APPEND "src/modules.c" "NULL\n};\n")
	
	FOREACH(MOD_IDX RANGE ${WLIST_MAX})
		LIST(GET ${WLIST} ${MOD_IDX} WRK)
		FILE(APPEND "src/modules.c" "extern worker_t ${WRK}_worker;\n")
	ENDFOREACH(MOD_IDX RANGE ${WLIST_MAX})
	 
	FILE(APPEND "src/modules.c" "\n\nworker_t *workers[] = {\n")
	
	FOREACH(MOD_IDX RANGE ${WLIST_MAX})
		LIST(GET ${WLIST} ${MOD_IDX} WRK)
		FILE(APPEND "src/modules.c" "&${WRK}_worker,\n")
	ENDFOREACH(MOD_IDX RANGE ${WLIST_MAX})
	FILE(APPEND "src/modules.c" "NULL\n};\n")
ENDMACRO(_AddModulesForced MLIST WLIST)

MACRO(AddModules MLIST WLIST)
	_AddModulesForced(${MLIST} ${WLIST})
	#IF(NOT EXISTS "src/modules.c")
	#	_AddModulesForced(${MLIST} ${WLIST})
	#ELSE(NOT EXISTS "src/modules.c")
	#	FILE(STRINGS "src/modules.c" FILE_ID_RAW REGEX "^/.*[a-zA-Z0-9]+.*/$")
	#	STRING(REGEX MATCH "[a-zA-Z0-9]+" FILE_ID "${FILE_ID_RAW}")
	#	IF(NOT FILE_ID STREQUAL MODULES_ID)
	#		MESSAGE("Regenerate modules info")
	#		_AddModulesForced(${MLIST} ${WLIST})
	#	ENDIF(NOT FILE_ID STREQUAL MODULES_ID)
	#ENDIF(NOT EXISTS "src/modules.c")
ENDMACRO(AddModules MLIST WLIST)

# Find lua installation
MACRO(FindLua _major _minor)
	# Find lua libraries
	MESSAGE(STATUS "Check for lua ${_major}.${_minor}")
	
	FIND_PATH(LUA_INCLUDE_DIR lua.h
	  HINTS
	  $ENV{LUA_DIR}
	  PATH_SUFFIXES "include/lua${_major}${_minor}" 
	  				"include/lua${_major}.${_minor}" 
	  				include/lua include
	  PATHS
	  /usr/local
	  /usr
	  ~/Library/Frameworks
	  /Library/Frameworks
	  /sw # Fink
	  /opt/local # DarwinPorts
	  /opt/csw # Blastwave
	  /opt
	)
	
	FIND_LIBRARY(LUA_LIBRARY 
	  NAMES lua 
	  		"lua${_major}${_minor}"
	  		"lua${_major}.${_minor}" 
	  		"lua-${_major}.${_minor}"
	  HINTS
	  $ENV{LUA_DIR}
	  PATH_SUFFIXES lib64 lib
	  PATHS
	  /usr/local
	  /usr
	  ~/Library/Frameworks
	  /Library/Frameworks
	  /sw
	  /opt/local
	  /opt/csw
	  /opt
	  DOC "Lua library"
	)
	
	IF(LUA_LIBRARY AND LUA_INCLUDE_DIR)
		SET(LUA_FOUND 1)
		IF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
			SET(LUA_VERSION_MAJOR ${_major})
			SET(LUA_VERSION_MINOR ${_minor})
		ENDIF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
		MESSAGE(STATUS "Found lua ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
	ENDIF(LUA_LIBRARY AND LUA_INCLUDE_DIR)
	
	# Check for luajit
	IF(ENABLE_LUAJIT MATCHES "ON")
	    FIND_LIBRARY(LUAJIT_LIBRARY NAMES
	    			"luajit${_major}${_minor}"
	    			"luajit${_major}.${_minor}"
	    			"luajit-${_major}.${_minor}"
	    			 luajit
	                  HINTS
	                  $ENV{LUA_DIR}
	                  PATH_SUFFIXES lib64 lib
	                  PATHS
	                      ~/Library/Frameworks
	                      /Library/Frameworks
	                      /usr/local
	                      /usr
	                      /sw
	                      /opt/local
	                      /opt/csw
	                      /opt
	                )
	     IF(NOT LUAJIT_LIBRARY)
	         MESSAGE(FATAL_ERROR "Luajit not found but enabled in configuration")
	     ENDIF(NOT LUAJIT_LIBRARY)
	ENDIF(ENABLE_LUAJIT MATCHES "ON")
ENDMACRO(FindLua _major _minor)

FUNCTION(INSTALL_IF_NOT_EXISTS src dest suffix)
  IF(NOT IS_ABSOLUTE "${src}")
    SET(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  ENDIF()
  GET_FILENAME_COMPONENT(src_name "${src}" NAME)
  IF(NOT IS_ABSOLUTE "${dest}")
    SET(dest "${CMAKE_INSTALL_PREFIX}/${dest}")
  ENDIF()
  INSTALL(CODE "
    IF(NOT EXISTS \"\$ENV{DESTDIR}${dest}/${src_name}${suffix}\")
      #FILE(INSTALL \"${src}\" DESTINATION \"${dest}\")
      MESSAGE(STATUS \"Installing: \$ENV{DESTDIR}${dest}/${src_name}${suffix}\")
      EXECUTE_PROCESS(COMMAND \${CMAKE_COMMAND} -E copy \"${src}\"
                      \"\$ENV{DESTDIR}${dest}/${src_name}${suffix}\"
                      RESULT_VARIABLE copy_result
                      ERROR_VARIABLE error_output)
      IF(copy_result)
        MESSAGE(FATAL_ERROR \${error_output})
      ENDIF()
    ELSE()
      MESSAGE(STATUS \"Skipping  : \$ENV{DESTDIR}${dest}/${src_name}${suffix}\")
    ENDIF()
  ")
ENDFUNCTION(INSTALL_IF_NOT_EXISTS)

# Process required package by using FindPackage and calling for INCLUDE_DIRECTORIES and
# setting list of required libraries
MACRO(ProcessPackage var _name0)
    PKG_SEARCH_MODULE(${var} REQUIRED "${_name0}" ${ARGN})
    IF(${var}_FOUND)
        SET(WITH_${var} 1)
        IF(ENABLE_STATIC MATCHES "ON")
            SET(_XPREFIX "${var}_STATIC")
        ELSE(ENABLE_STATIC MATCHES "ON")
            SET(_XPREFIX "${var}")
        ENDIF(ENABLE_STATIC MATCHES "ON")
        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
            INCLUDE_DIRECTORIES("${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
            LINK_DIRECTORIES("${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
        # Handle other CFLAGS and LDFLAGS
        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
        LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
    ENDIF(${var}_FOUND)
ENDMACRO(ProcessPackage name)

############################# CONFIG SECTION #############################################
# Initial set

IF(CMAKE_INSTALL_PREFIX)
    SET(PREFIX ${CMAKE_INSTALL_PREFIX})
ENDIF(CMAKE_INSTALL_PREFIX)

LIST(APPEND CMAKE_REQUIRED_LIBRARIES m)

# Try to detect platform for further configuration
CHECK_C_SOURCE_COMPILES ("#if !defined(__x86_64) && !defined(__amd64) && !defined(_M_X64)
					#error assume 32 bit arch
					#endif
					int main() { return 0;}" AMD_64)
IF(NOT BUILD_CPU_MODE)
	IF(AMD_64)
		SET (BUILD_CPU_MODE "64")
	ELSE(AMD_64)
		SET (BUILD_CPU_MODE "32")
	ENDIF(AMD_64)
ENDIF(NOT BUILD_CPU_MODE)

# Platform specific configuration
IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DFREEBSD")
	CONFIGURE_FILE(freebsd/rspamd.sh.in freebsd/rspamd @ONLY)

	IF(ENABLE_REDIRECTOR MATCHES "ON")
		CONFIGURE_FILE(freebsd/redirector.sh.in freebsd/redirector @ONLY)
	ENDIF(ENABLE_REDIRECTOR MATCHES "ON")
    FIND_LIBRARY(LIBINTL_LIBRARY NAMES intl PATHS   /lib
                                               /opt/lib
                                               /usr/lib
                                               /usr/local/lib
                 DOC "Path where the libintl library can be found")
    LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ${LIBINTL_LIBRARY})
	MESSAGE(STATUS "Configuring for FreeBSD")
 
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DDARWIN")
    SET(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")

    FIND_LIBRARY(LIBINTL_LIBRARY NAMES intl PATHS   /lib
                                               /opt/lib
                                               /usr/lib
                                               /usr/local/lib
                 DOC "Path where the libintl library can be found")
    LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ${LIBINTL_LIBRARY})
	MESSAGE(STATUS "Configuring for Darwin")

ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DLINUX")
    IF(BUILD_CPU_MODE STREQUAL "32")
    	SET(CMAKE_C_FLAGS  "-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE ${CMAKE_C_FLAGS}")
    ENDIF(BUILD_CPU_MODE STREQUAL "32")
    # Workaround with architecture specific includes
    IF(IS_DIRECTORY "/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/") 
    	INCLUDE_DIRECTORIES("/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/")
    	SET(CMAKE_REQUIRED_INCLUDES "/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/")
    ENDIF(IS_DIRECTORY "/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/")
    
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES rt)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES dl)
	#XXX: gio bug workaround
	IF(ENABLE_STATIC MATCHES "ON")
	    LIST(APPEND CMAKE_REQUIRED_LIBRARIES selinux)
	ENDIF(ENABLE_STATIC MATCHES "ON")
	MESSAGE(STATUS "Configuring for Linux")
	IF(EXISTS "/etc/debian_version")
		SET(LINUX_START_SCRIPT "rspamd_debian.in")
	ELSE(EXISTS "/etc/debian_version")
		SET(LINUX_START_SCRIPT "rspamd_rh.in")
	ENDIF(EXISTS "/etc/debian_version")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

IF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
 	IF(NOT BUILD_CPU_MODE)
	 	SET (BUILD_CPU_MODE "32")
	ENDIF(NOT BUILD_CPU_MODE)
	
	IF("${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Xa -xregs=no%frameptr -xstrconst -xc99")
		SET(SUN_BUILD32 "-xtarget=generic")
		SET(SUN_BUILD64 "-xtarget=generic64")
		IF(ENABLE_OPTIMIZATION MATCHES "ON")
			SET(CMAKE_C_OPT_FLAGS "-fast -xdepend")
		ELSE(ENABLE_OPTIMIZATION MATCHES "ON")
			SET(CMAKE_C_OPT_FLAGS "-xO0")
		ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")
	ELSE("${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
		set(SUN_BUILD32 "-m32")
		set(SUN_BUILD64 "-m64")		
	ENDIF("${CMAKE_C_COMPILER_ID}" MATCHES SunPro)

 	IF (BUILD_CPU_MODE STREQUAL "32")
       message (STATUS "Building 32-bit mode on Solaris")
       # If we are asked to build 32 bit mode
       	set(CMAKE_C_FLAGS  "${SUN_BUILD32} ${CMAKE_C_FLAGS}")
       	set(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SUN_BUILD32}")
 	ELSE (BUILD_CPU_MODE STREQUAL "32")
       # solaris 64-bit mode
		message (STATUS "Building 64-bit mode on Solaris")
       	set(CMAKE_C_FLAGS  "${SUN_BUILD64} ${CMAKE_C_FLAGS}")
       	set(CMAKE_SHARED_LINKER_FLAGS  "${CMAKE_SHARED_LINKER_FLAGS} ${SUN_BUILD64}")
    ENDIF (BUILD_CPU_MODE STREQUAL "32")

 	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__EXTENSIONS__ -DSOLARIS -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L")
    
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES rt)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES dl)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES resolv)
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES nsl)
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES socket)
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES umem)
 	# Ugly hack, but FindOpenSSL on Solaris does not link with libcrypto
 	LIST(APPEND CMAKE_REQUIRED_LIBRARIES crypto)
  	SET(CMAKE_VERBOSE_MAKEFILE ON)
  	SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
  	SET(CMAKE_INSTALL_RPATH "${PREFIX}/lib")	
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")

# Now find libraries and headers

# Find lua libraries
FindLua(5 2)
IF(NOT LUA_FOUND)
	FindLua(5 1)
ENDIF(NOT LUA_FOUND)

IF(NOT LUA_FOUND)
	MESSAGE(FATAL_ERROR "Lua not found, lua support is required for working")
ELSE(NOT LUA_FOUND)
    SET(WITH_LUA 1)
    INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
ENDIF(NOT LUA_FOUND)

IF(ENABLE_SQLITE MATCHES "ON")
	# Find optional sqlite3 support
	ProcessPackage(SQLITE sqlite3>=3.6.0)
ENDIF(ENABLE_SQLITE MATCHES "ON")

#Check for openssl (required for dkim)
IF(OPENSSL_FOUND)
	SET(HAVE_OPENSSL 1)
	INCLUDE_DIRECTORIES("${OPENSSL_INCLUDE_DIR}")
ENDIF(OPENSSL_FOUND)

ProcessPackage(GLIB2 glib-2.0>=2.16)
ProcessPackage(GTHREAD gthread-2.0)

IF(ENABLE_HIREDIS MATCHES "ON")
	# Try to find hiredis library
	ProcessPackage(HIREDIS hiredis libhiredis)
ENDIF(ENABLE_HIREDIS MATCHES "ON")

ProcessPackage(GMIME2 gmime-2.6 gmime-2.4 gmime-2.0)
IF(GMIME2_VERSION VERSION_GREATER "2.4.0")
    SET(GMIME24 1)
ENDIF(GMIME2_VERSION VERSION_GREATER "2.4.0")

# Check for libevent

FIND_LIBRARY(LIBEVENT_LIBRARY NAMES event PATH_SUFFIXES lib64 lib
                  PATHS
                      ~/Library/Frameworks
                      /Library/Frameworks
                      /usr/local
                      /usr
                      /sw
                      /opt/local
                      /opt/csw
                      /opt
                 DOC "Path where the libevent library can be found")
IF(NOT LIBEVENT_LIBRARY)
	MESSAGE(FATAL_ERROR "libevent is required for building rspamd")
ENDIF(NOT LIBEVENT_LIBRARY)

FIND_PATH(LIBEVENT_INCLUDE event.h PATHS 	/opt/include
										/usr/include
										/usr/local/include
										DOC "Path where the libevent header files can be found")

FIND_PATH(LIBEVENT_EVHTTP evhttp.h PATHS /opt/include
										/usr/include
										/usr/local/include
										DOC "Path where the libevhttp header files can be found")

GET_FILENAME_COMPONENT(LIBEVENT_PATH "${LIBEVENT_LIBRARY}" PATH)
INCLUDE_DIRECTORIES("${LIBEVENT_INCLUDE}")
LINK_DIRECTORIES("${LIBEVENT_PATH}")

# Find libbd
IF(ENABLE_DB MATCHES "ON")
	FIND_LIBRARY(LIBDB_LIBRARY NAMES db PATHS PATH_SUFFIXES lib64 lib
	                  PATHS
	                      ~/Library/Frameworks
	                      /Library/Frameworks
	                      /usr/local
	                      /usr
	                      /sw
	                      /opt/local
	                      /opt/csw
	                      /opt
	                 DOC "Path where the libdb library can be found")
	IF(LIBDB_LIBRARY)
		FIND_PATH(LIBDB_INCLUDE db.h PATHS 	/opt/include
												/usr/include
												/usr/local/include
												DOC "Path where the bdb header files can be found")
	
		GET_FILENAME_COMPONENT(LIBDB_PATH "${LIBDB_LIBRARY}" PATH)
		INCLUDE_DIRECTORIES("${LIBDB_INCLUDE}")
		LINK_DIRECTORIES("${LIBDB_PATH}")
		SET(WITH_DB 1)
	ENDIF(LIBDB_LIBRARY)
ENDIF(ENABLE_DB MATCHES "ON")

# Google performance tools

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	FIND_PATH(GPERF_INCLUDE google/profiler.h PATHS /opt/include
													/usr/include
													/usr/local/include
											  DOC "Path where google perftools includes can be found")
	INCLUDE_DIRECTORIES("${GPERF_INCLUDE}")
	FIND_LIBRARY(GPERF_LIBRARY NAMES profiler PATH_SUFFIXES lib64 lib
                  PATHS
                      ~/Library/Frameworks
                      /Library/Frameworks
                      /usr/local
                      /usr
                      /sw
                      /opt/local
                      /opt/csw
                      /opt
					DOC "Path where the gperf library can be found")
	IF(NOT GPERF_LIBRARY)
		MESSAGE(FATAL_ERROR "gperf tools support is enabled but not found in system")
	ENDIF(NOT GPERF_LIBRARY)
	GET_FILENAME_COMPONENT(GPERF_PATH "${GPERF_LIBRARY}" PATH)
	LINK_DIRECTORIES("${GPERF_PATH}")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
	SET(WITH_GPERF_TOOLS 1)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

# Find util library

FIND_LIBRARY(LIBUTIL_LIBRARY NAMES util PATHS	PATH_SUFFIXES lib64 lib
                  PATHS
                      ~/Library/Frameworks
                      /Library/Frameworks
                      /usr/local
                      /usr
                      /sw
                      /opt/local
                      /opt/csw
                      /opt
                 DOC "Path where the libutil library can be found")
IF(LIBUTIL_LIBRARY)
	FIND_FILE(HAVE_LIBUTIL_H NAMES libutil.h PATHS /usr/include
											   /opt/include
											   /usr/local/include
				DOC "Path to libutil header")
	IF(HAVE_LIBUTIL_H)
		LIST(APPEND RSPAMD_REQUIRED_LIBRARIES util)
		CHECK_FUNCTION_EXISTS(pidfile_open HAVE_PIDFILE)
		CHECK_FUNCTION_EXISTS(pidfile_fileno HAVE_PIDFILE_FILENO)
	ENDIF(HAVE_LIBUTIL_H)
ENDIF(LIBUTIL_LIBRARY)

# Find libfetch (for FreeBSD)

IF(ENABLE_URL_INCLUDE MATCHES "ON")
    FIND_LIBRARY(LIBFETCH_LIBRARY NAMES fetch PATHS	PATH_SUFFIXES lib64 lib
                      PATHS
                          ~/Library/Frameworks
                          /Library/Frameworks
                          /usr/local
                          /usr
                          /sw
                          /opt/local
                          /opt/csw
                          /opt
                     DOC "Path where the libfetch library can be found")
    IF(LIBFETCH_LIBRARY)
    	FIND_FILE(HAVE_FETCH_H NAMES fetch.h PATHS /usr/include
    											   /opt/include
    											   /usr/local/include
    				DOC "Path to libfetch header")
    ELSE(LIBFETCH_LIBRARY)
    	# Try to find libcurl
    	ProcessPackage(CURL libcurl)
    	IF(NOT CURL_FOUND)
    		MESSAGE(WARNING "Neither libcurl nor libfetch were found, no support of URL includes in configuration")
    	ENDIF(NOT CURL_FOUND)
    ENDIF(LIBFETCH_LIBRARY)
ENDIF(ENABLE_URL_INCLUDE MATCHES "ON")

# Static build

IF(ENABLE_STATIC MATCHES "ON")
	SET(BUILD_STATIC 1)
	SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -pthread")
	MESSAGE(STATUS "Static build of rspamd, no custom plugins support")
	SET(LINK_TYPE "STATIC")
	SET(NO_SHARED "ON")
ELSE(ENABLE_STATIC MATCHES "ON")
    IF(NO_SHARED MATCHES "OFF")
        SET(LINK_TYPE "SHARED")
    ELSE(NO_SHARED MATCHES "OFF")
        SET(LINK_TYPE "STATIC")
    ENDIF(NO_SHARED MATCHES "OFF")
ENDIF(ENABLE_STATIC MATCHES "ON")

LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")

# Process with warn flags
SET(CMAKE_C_WARN_FLAGS "")
CHECK_C_COMPILER_FLAG(-Wall SUPPORT_WALL)
CHECK_C_COMPILER_FLAG(-W SUPPORT_W)
CHECK_C_COMPILER_FLAG(-Wpointer-arith SUPPORT_WPOINTER)
CHECK_C_COMPILER_FLAG(-Wno-unused-parameter SUPPORT_WPARAM)
CHECK_C_COMPILER_FLAG(-Wno-unused-function SUPPORT_WFUNCTION)
CHECK_C_COMPILER_FLAG(-Wunused-variable SUPPORT_WUNUSED_VAR)
CHECK_C_COMPILER_FLAG(-Wno-pointer-sign SUPPORT_WPOINTER_SIGN)
CHECK_C_COMPILER_FLAG(-Wstrict-prototypes SUPPORT_WSTRICT_PROTOTYPES)
CHECK_C_COMPILER_FLAG(-pedantic SUPPORT_PEDANTIC_FLAG)
IF(NOT "${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
	CHECK_C_COMPILER_FLAG("-std=c99" SUPPORT_STD_FLAG)
ENDIF(NOT "${CMAKE_C_COMPILER_ID}" MATCHES SunPro)
IF(SUPPORT_W)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -W")
ENDIF(SUPPORT_W)
IF(SUPPORT_WALL)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wall")
ENDIF(SUPPORT_WALL)
IF(SUPPORT_WPOINTER)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wpointer-arith")
ENDIF(SUPPORT_WPOINTER)
IF(SUPPORT_WPARAM)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-parameter")
ENDIF(SUPPORT_WPARAM)
IF(SUPPORT_WFUNCTION)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-unused-function")
ENDIF(SUPPORT_WFUNCTION)
IF(SUPPORT_WUNUSED_VAR)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wunused-variable")
ENDIF(SUPPORT_WUNUSED_VAR)
IF(SUPPORT_WPOINTER_SIGN)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-pointer-sign")
ENDIF(SUPPORT_WPOINTER_SIGN)
IF(SUPPORT_WSTRICT_PROTOTYPES)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wstrict-prototypes")
ENDIF(SUPPORT_WSTRICT_PROTOTYPES)
IF(SUPPORT_PEDANTIC_FLAG)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -pedantic")
ENDIF(SUPPORT_PEDANTIC_FLAG)
IF(SUPPORT_STD_FLAG)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -std=c99")
ENDIF(SUPPORT_STD_FLAG)
 
CHECK_C_COMPILER_FLAG(-fPIC SUPPORT_FPIC)
IF(SUPPORT_FPIC)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
ENDIF(SUPPORT_FPIC)
 
 # Optimization flags
IF(NOT CMAKE_C_OPT_FLAGS)
	IF(ENABLE_OPTIMIZATION MATCHES "ON")
		SET(CMAKE_C_OPT_FLAGS "-O3 -fstrict-aliasing")
	ELSE(ENABLE_OPTIMIZATION MATCHES "ON")
		SET(CMAKE_C_OPT_FLAGS "-O0 -fstrict-aliasing")
	ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")
ENDIF(NOT CMAKE_C_OPT_FLAGS)

IF(DEBUG_MODE MATCHES "ON")
	SET(CMAKE_BUILD_TYPE "Debug")
ENDIF(DEBUG_MODE MATCHES "ON")

SET(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_C_WARN_FLAGS}")
 
# Check platform specific includes
CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES(sys/time.h  HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(sys/uio.h   HAVE_SYS_UIO_H)

CHECK_INCLUDE_FILES(fcntl.h     HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(math.h      HAVE_MATH_H)
CHECK_INCLUDE_FILES(stdio.h     HAVE_STDIO_H)
CHECK_INCLUDE_FILES(stdlib.h    HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(string.h    HAVE_STRING_H)
CHECK_INCLUDE_FILES(strings.h   HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(time.h      HAVE_TIME_H)
CHECK_INCLUDE_FILES(unistd.h    HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(sysexits.h  HAVE_SYSEXITS_H)
CHECK_INCLUDE_FILES(stdint.h  HAVE_STDINT_H)
CHECK_INCLUDE_FILES(inttypes.h  HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES(endian.h  HAVE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/endian.h  HAVE_SYS_ENDIAN_H)
CHECK_INCLUDE_FILES(machine/endian.h  HAVE_MACHINE_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/queue.h  HAVE_SYS_QUEUE_H)
CHECK_INCLUDE_FILES(sys/socket.h  HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES(sys/mman.h  HAVE_SYS_MMAN_H)
CHECK_INCLUDE_FILES(sys/un.h  HAVE_SYS_UN_H)
CHECK_INCLUDE_FILES(sys/stat.h  HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES(sys/wait.h  HAVE_SYS_WAIT_H)
CHECK_INCLUDE_FILES(sys/param.h  HAVE_SYS_PARAM_H)
CHECK_INCLUDE_FILES(sys/cdefs.h  HAVE_SYS_CDEFS_H)
CHECK_INCLUDE_FILES(sys/file.h  HAVE_SYS_FILE_H)
CHECK_INCLUDE_FILES(sys/utsname.h  HAVE_SYS_UTSNAME_H)
CHECK_INCLUDE_FILES(sys/resource.h  HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILES(netinet/in.h  HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(arpa/inet.h  HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(netdb.h  HAVE_NETDB_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(siginfo.h HAVE_SIGINFO_H)
CHECK_INCLUDE_FILES(locale.h HAVE_LOCALE_H)
CHECK_INCLUDE_FILES(libgen.h HAVE_LIBGEN_H)
CHECK_INCLUDE_FILES(search.h HAVE_SEARCH_H)
CHECK_INCLUDE_FILES(pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES(grp.h HAVE_GRP_H)
CHECK_INCLUDE_FILES(glob.h HAVE_GLOB_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)
CHECK_INCLUDE_FILES(readpassphrase.h HAVE_READPASSPHRASE_H)
CHECK_INCLUDE_FILES(termios.h HAVE_TERMIOS_H)
CHECK_INCLUDE_FILES(paths.h HAVE_PATHS_H)
CHECK_INCLUDE_FILES(sys/sendfile.h HAVE_SYS_SENDFILE_H)
CHECK_INCLUDE_FILES(linux/falloc.h HAVE_LINUX_FALLOC_H)
CHECK_INCLUDE_FILES(sys/eventfd.h HAVE_SYS_EVENTFD_H)
CHECK_INCLUDE_FILES(aio.h HAVE_AIO_H)
CHECK_INCLUDE_FILES(libaio.h HAVE_LIBAIO_H)

# Some dependencies
IF(HAVE_SYS_WAIT_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/wait.h)
ENDIF(HAVE_SYS_WAIT_H)
IF(HAVE_TIME_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES time.h)
ENDIF(HAVE_TIME_H)
IF(HAVE_SYS_TIME_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/time.h)
ENDIF(HAVE_SYS_TIME_H)

# Check platform API
CHECK_FUNCTION_EXISTS(setproctitle HAVE_SETPROCTITLE)
CHECK_FUNCTION_EXISTS(getpagesize HAVE_GETPAGESIZE)
CHECK_FUNCTION_EXISTS(nanosleep HAVE_NANOSLEEP)
CHECK_FUNCTION_EXISTS(vfork HAVE_VFORK)
CHECK_FUNCTION_EXISTS(wait4 HAVE_WAIT4)
CHECK_FUNCTION_EXISTS(waitpid HAVE_WAITPID)
CHECK_FUNCTION_EXISTS(flock HAVE_FLOCK)
CHECK_FUNCTION_EXISTS(tanhl HAVE_TANHL)
CHECK_FUNCTION_EXISTS(tanh HAVE_TANH)
CHECK_FUNCTION_EXISTS(expl HAVE_EXPL)
CHECK_FUNCTION_EXISTS(exp2l HAVE_EXP2L)
CHECK_FUNCTION_EXISTS(sendfile HAVE_SENDFILE)
CHECK_FUNCTION_EXISTS(mkstemp HAVE_MKSTEMP)
CHECK_FUNCTION_EXISTS(setitimer HAVE_SETITIMER)
CHECK_FUNCTION_EXISTS(inet_pton HAVE_INET_PTON)
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)

# 

# Check macros
CHECK_SYMBOL_EXISTS(PATH_MAX limits.h HAVE_PATH_MAX)
CHECK_SYMBOL_EXISTS(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
CHECK_SYMBOL_EXISTS(MAP_SHARED sys/mman.h HAVE_MMAP_SHARED)
CHECK_SYMBOL_EXISTS(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
CHECK_SYMBOL_EXISTS(MAP_NOCORE sys/mman.h HAVE_MMAP_NOCORE)
CHECK_SYMBOL_EXISTS(O_DIRECT fcntl.h HAVE_O_DIRECT)
CHECK_SYMBOL_EXISTS(IPV6_V6ONLY "sys/socket.h;netinet/in.h" HAVE_IPV6_V6ONLY)
CHECK_SYMBOL_EXISTS(posix_fadvise fcntl.h HAVE_FADVISE)
CHECK_SYMBOL_EXISTS(posix_fallocate fcntl.h HAVE_POSIX_FALLOCATE)
CHECK_SYMBOL_EXISTS(fallocate fcntl.h HAVE_FALLOCATE)
CHECK_SYMBOL_EXISTS(fdatasync unistd.h HAVE_FDATASYNC)
CHECK_SYMBOL_EXISTS(_SC_NPROCESSORS_ONLN unistd.h HAVE_SC_NPROCESSORS_ONLN)
CHECK_SYMBOL_EXISTS(setbit sys/param.h PARAM_H_HAS_BITSET)
CHECK_SYMBOL_EXISTS(getaddrinfo "sys/types.h;sys/socket.h;netdb.h" HAVE_GETADDRINFO)

IF(NOT HAVE_GETADDRINFO)
	MESSAGE(FATAL_ERROR "Your system does not support getaddrinfo call, please consider upgrading it to run rspamd")
ENDIF(NOT HAVE_GETADDRINFO)
IF(HAVE_SIGINFO_H)
	CHECK_SYMBOL_EXISTS(SA_SIGINFO "signal.h;siginfo.h" HAVE_SA_SIGINFO)
ELSE(HAVE_SIGINFO_H)
	CHECK_SYMBOL_EXISTS(SA_SIGINFO "signal.h" HAVE_SA_SIGINFO)
ENDIF(HAVE_SIGINFO_H)

# Some hack for libevent 2.0
CHECK_C_SOURCE_COMPILES ("#include <event.h>
					#if _EVENT_NUMERIC_VERSION < 0x02000000
					#error Unsupported
					#endif
					int main() { return 0;}" HAVE_LIBEVENT2)

IF(NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS")
IF(HAVE_CLOCK_GETTIME)
	CHECK_SYMBOL_EXISTS(CLOCK_PROCESS_CPUTIME_ID time.h HAVE_CLOCK_PROCESS_CPUTIME_ID)
	CHECK_SYMBOL_EXISTS(CLOCK_VIRTUAL time.h HAVE_CLOCK_VIRTUAL)
ELSE(HAVE_CLOCK_GETTIME)
	CHECK_INCLUDE_FILES(sys/timeb.h HAVE_SYS_TIMEB_H)
ENDIF(HAVE_CLOCK_GETTIME)

# Check asm pause instruction
CHECK_C_SOURCE_COMPILES ("#include <sys/types.h>
                          int main (int argc, char **argv) {
						  	__asm __volatile(\"pause\");
							return 0;
						  }" HAVE_ASM_PAUSE)
ENDIF(NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS")

# Check queue.h compatibility
IF(NOT HAVE_COMPATIBLE_QUEUE_H)
	INCLUDE_DIRECTORIES(compat)
ENDIF(NOT HAVE_COMPATIBLE_QUEUE_H)

IF(NOT DESTDIR)
    SET(DESTDIR $ENV{DESTDIR})
ENDIF(NOT DESTDIR)

# Try to detect tip version from hg
SET(ID "unknown")
FIND_PROGRAM(HG "hg")

IF(HG)
    EXECUTE_PROCESS(COMMAND "${HG}" id OUTPUT_VARIABLE HG_ID ERROR_QUIET)   
    IF(HG_ID)
        STRING(REGEX MATCH ^[0-9a-z]+ RSPAMD_ID "${HG_ID}")
    ELSE(HG_ID)
        FIND_FILE(HG_ARCH ".hg_archival.txt" "${CMAKE_CURRENT_SOURCE_DIR}")   
        IF(HG_ARCH)
            FILE(READ ${HG_ARCH} HG_ID)
            IF(HG_ID)
                STRING(REGEX MATCH "node: [0-9a-z]+" _tmp "${HG_ID}")
                STRING(SUBSTRING "${_tmp}" 6 12 RSPAMD_ID)
			ENDIF(HG_ID)
    	ENDIF(HG_ARCH)
    ENDIF(HG_ID)
ELSE(HG)
# Now check .hg_archival.txt
    FIND_FILE(HG_ARCH ".hg_archival.txt" "${CMAKE_CURRENT_SOURCE_DIR}")   
    IF(HG_ARCH)
        FILE(READ ${HG_ARCH} HG_ID)
        IF(HG_ID)
            STRING(REGEX MATCH "node: [0-9a-z]+" _tmp "${HG_ID}")
            STRING(SUBSTRING "${_tmp}" 6 12 RSPAMD_ID)
        ENDIF(HG_ID)
    ENDIF(HG_ARCH)
ENDIF(HG)
 

################################ SOURCES SECTION ###########################

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/src" 
					"${CMAKE_BINARY_DIR}/src" 
					"${CMAKE_SOURCE_DIR}/src/ucl/include"
					"${CMAKE_SOURCE_DIR}/contrib/uthash"
					"${CMAKE_SOURCE_DIR}/contrib/http-parser"
					"${CMAKE_SOURCE_DIR}/contrib/libottery"
					"${CMAKE_SOURCE_DIR}/contrib/xxhash"
					"${CMAKE_SOURCE_DIR}/src/rdns/include")

SET(RSPAMDSRC	src/modules.c
				src/controller.c
				src/fuzzy_storage.c
				src/lua_worker.c
				src/main.c
				src/map.c
				src/smtp_proxy.c
				src/webui.c
				src/worker.c)

SET(PLUGINSSRC	src/plugins/surbl.c
				src/plugins/regexp.c
				src/plugins/chartable.c
				src/plugins/fuzzy_check.c
				src/plugins/spf.c
				src/plugins/dkim_check.c)
				
SET(MODULES_LIST surbl regexp chartable fuzzy_check spf dkim)
SET(WORKERS_LIST normal controller smtp_proxy fuzzy lua webui)

AddModules(MODULES_LIST WORKERS_LIST)

################################ SUBDIRS SECTION ###########################

ADD_SUBDIRECTORY(contrib/lgpl)
IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
ENDIF(GLIB_COMPAT)

IF(NOT HIREDIS_FOUND)
    ADD_SUBDIRECTORY(contrib/hiredis)
    INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/hiredis")
ENDIF(NOT HIREDIS_FOUND)

ADD_SUBDIRECTORY(contrib/xxhash)
ADD_SUBDIRECTORY(contrib/http-parser)
ADD_SUBDIRECTORY(contrib/libottery)
ADD_SUBDIRECTORY(src/lua)
ADD_SUBDIRECTORY(src/json)
ADD_SUBDIRECTORY(src/cdb)
ADD_SUBDIRECTORY(src/ucl)
ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(src/client)

SET(SLAVE_BUILD 1)
ADD_SUBDIRECTORY(src/rdns)
UNSET(SLAVE_BUILD)

ADD_SUBDIRECTORY(test)

LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)

############################ TARGETS SECTION ###############################


CONFIGURE_FILE(config.h.in src/config.h)
CONFIGURE_FILE(contrib/exim/local_scan.c.in contrib/exim/local_scan_rspamd.c @ONLY)

SET(CONFFILES 
	conf/composites.conf
	conf/logging.conf
	conf/metrics.conf
	conf/modules.conf
	conf/options.conf
	conf/rspamd.conf
	conf/statistic.conf
	conf/workers.conf
	conf/2tld.inc
	conf/surbl-whitelist.inc)

######################### LINK SECTION ###############################

ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${PLUGINSSRC})
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS "-DRSPAMD_MAIN")
IF(NOT DEBIAN_BUILD)
SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})
ENDIF(NOT DEBIAN_BUILD)

TARGET_LINK_LIBRARIES(rspamd rspamd-mime)
TARGET_LINK_LIBRARIES(rspamd rspamd-server)
TARGET_LINK_LIBRARIES(rspamd rspamd-util)
TARGET_LINK_LIBRARIES(rspamd rspamd-lua)

TARGET_LINK_LIBRARIES(rspamd event)
IF(HAVE_LIBEVENT2)
	TARGET_LINK_LIBRARIES(rspamd event_pthreads)
ENDIF(HAVE_LIBEVENT2)
IF(WITH_DB)
	TARGET_LINK_LIBRARIES(rspamd db)
ENDIF(WITH_DB)

IF(OPENSSL_FOUND)
	TARGET_LINK_LIBRARIES(rspamd ${OPENSSL_LIBRARIES})
ENDIF(OPENSSL_FOUND)
IF(HAVE_FETCH_H)
	TARGET_LINK_LIBRARIES(rspamd fetch)
ENDIF(HAVE_FETCH_H)
TARGET_LINK_LIBRARIES(rspamd ${RSPAMD_REQUIRED_LIBRARIES})

IF(ENABLE_LUAJIT MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd "${LUAJIT_LIBRARY}")
ELSE(ENABLE_LUAJIT MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd "${LUA_LIBRARY}")
ENDIF(ENABLE_LUAJIT MATCHES "ON")

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd profiler)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")
TARGET_LINK_LIBRARIES(rspamd hiredis)
IF(GLIB_COMPAT)
	TARGET_LINK_LIBRARIES(rspamd glibadditions)
ENDIF(GLIB_COMPAT)

##################### INSTALLATION ##########################################

# Binaries
INSTALL(TARGETS rspamd RUNTIME DESTINATION bin)

# Configs
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR})")
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${EXAMPLESDIR})")
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR}/lua)")

# Install configs only if they are unchanged
LIST(LENGTH CONFFILES CONFLIST_COUNT)
MATH(EXPR CONFLIST_MAX ${CONFLIST_COUNT}-1)
	
FOREACH(CONF_IDX RANGE ${CONFLIST_MAX})
	LIST(GET CONFFILES ${CONF_IDX} CONF_FILE)
	IF(BUILD_PORT)
		INSTALL_IF_NOT_EXISTS(${CONF_FILE} ${CONFDIR} ".sample")
	ELSE(BUILD_PORT)
		INSTALL_IF_NOT_EXISTS(${CONF_FILE} ${CONFDIR} "")
	ENDIF(BUILD_PORT)
	IF(INSTALL_EXAMPLES MATCHES "ON")
		INSTALL(FILES ${CONF_FILE} DESTINATION ${EXAMPLESDIR})
	ENDIF(INSTALL_EXAMPLES MATCHES "ON")
ENDFOREACH(CONF_IDX RANGE ${CONFLIST_MAX})

# Lua plugins

FILE(GLOB LUA_PLUGINS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua" 
	"${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua/*.lua" )
FOREACH(LUA_PLUGIN ${LUA_PLUGINS})
	GET_FILENAME_COMPONENT(_rp ${LUA_PLUGIN} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR}/lua/${_rp})")
	INSTALL(FILES "src/plugins/lua/${LUA_PLUGIN}" DESTINATION ${PLUGINSDIR}/lua/${_rp})
ENDFOREACH(LUA_PLUGIN)

# Lua config
INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR}/lua)")
FILE(GLOB_RECURSE LUA_CONFIGS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/conf/lua" 
	"${CMAKE_CURRENT_SOURCE_DIR}/conf/lua/*.lua")
FOREACH(LUA_CONF ${LUA_CONFIGS})
	GET_FILENAME_COMPONENT(_rp ${LUA_CONF} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${CONFDIR}/lua/${_rp})")
	INSTALL(FILES "conf/lua/${LUA_CONF}" DESTINATION ${CONFDIR}/lua/${_rp})
ENDFOREACH(LUA_CONF)

# systemd unit

INSTALL(FILES "rspamd.service" DESTINATION ${SYSTEMDDIR})
INSTALL(FILES "rspamd.socket" DESTINATION ${SYSTEMDDIR})

# Manual pages
INSTALL(FILES "doc/rspamd.8" DESTINATION ${MANDIR}/man8)
INSTALL(FILES "doc/rspamc.1" DESTINATION ${MANDIR}/man1)
