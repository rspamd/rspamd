#
# Rspamd - rapid antispam system
#
# Cmake configuration file
#

############################# INITIAL SECTION #############################################

PROJECT(rspamd C)
ENABLE_LANGUAGE(ASM)

SET(RSPAMD_VERSION_MAJOR 0)
SET(RSPAMD_VERSION_MINOR 9)
SET(RSPAMD_VERSION_PATCH 4)

SET(RSPAMD_VERSION         "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}")
SET(RSPAMD_MASTER_SITE_URL "https://rspamd.com")

IF(NOT RSPAMD_USER)
	SET(RSPAMD_USER "nobody")
	SET(RSPAMD_GROUP "nobody")
ENDIF(NOT RSPAMD_USER)

# Default for SysV Init
SET(RSPAMD_WORKER_NORMAL "*:11333")
SET(RSPAMD_WORKER_CONTROLLER "*:11334")
CMAKE_MINIMUM_REQUIRED(VERSION 2.8.0 FATAL_ERROR)
SET_PROPERTY(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS 1)

############################# OPTIONS SECTION #############################################

OPTION(DEBUG_MODE          "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(SKIP_RELINK_RPATH   "Skip relinking and full RPATH for the install tree" OFF)
OPTION(ENABLE_REDIRECTOR   "Enable redirector install [default: OFF]"           OFF)
OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]"             OFF)
OPTION(ENABLE_STATIC       "Enable static compiling [default: OFF]"             OFF)
OPTION(ENABLE_LUAJIT       "Link with libluajit [default: ON]"                  ON)
OPTION(ENABLE_DB           "Find and link with DB library [default: OFF]"       OFF)
OPTION(ENABLE_SQLITE       "Find and link with sqlite3 library [default: OFF]"  OFF)
OPTION(ENABLE_HIREDIS      "Find and link with external redis library [default: ON]"  ON)
OPTION(ENABLE_URL_INCLUDE  "Enable urls in ucl includes (requires libcurl or libfetch) [default: OFF]" OFF)
OPTION(NO_SHARED           "Build internal libs static [default: ON]"          ON)
OPTION(FORCE_GMIME24       "Link with gmime2.4 [default: OFF]"                  OFF)
OPTION(INSTALL_EXAMPLES    "Install examples [default: OFF]"                    OFF)
OPTION(INSTALL_WEBUI       "Install web interface [default: ON]"                ON)
OPTION(WANT_SYSTEMD_UNITS  "Install systemd unit files on Linux [default: OFF]" OFF)

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

IF(NOT WWWDIR)
	SET(WWWDIR "${CMAKE_INSTALL_PREFIX}/share/rspamd/www")
ENDIF(NOT WWWDIR)

# Set libdir
IF(NOT LIBDIR)
	SET(RSPAMD_LIBDIR "${CMAKE_INSTALL_PREFIX}/lib/rspamd")
ELSE(NOT LIBDIR)
	SET(RSPAMD_LIBDIR "${LIBDIR}")
ENDIF(NOT LIBDIR)
SET(CMAKE_MACOSX_RPATH ON)
SET(CMAKE_INSTALL_RPATH "${RSPAMD_LIBDIR}")

# Set includedir
IF(NOT INCLUDEDIR)
	SET(INCLUDEDIR include/rspamd)
ENDIF(NOT INCLUDEDIR)

IF(NOT SYSTEMDDIR)
	SET(SYSTEMDDIR ${CMAKE_INSTALL_PREFIX}/lib/systemd/system)
ENDIF(NOT SYSTEMDDIR)

SET(RSPAMD_DEFAULT_INCLUDE_PATHS "/opt;/usr;/usr/local;/opt/local;/usr/pkg;/opt/csw;/sw")
SET(RSPAMD_DEFAULT_LIBRARY_PATHS "/usr/local;/usr/pkg;/usr;~/Library/Frameworks;/Library/Frameworks;/sw;/opt/local;/opt/csw;/opt")

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

############################# MACRO SECTION #############################################

# Find lua installation
MACRO(FindLua _major _minor)
	# Find lua libraries
	UNSET(LUA_INCLUDE_DIR CACHE)
	UNSET(LUA_LIBRARY CACHE)
	
	IF(ENABLE_LUAJIT MATCHES "ON")
		MESSAGE(STATUS "Check for luajit ${_major}.${_minor}")
		FIND_PATH(LUA_INCLUDE_DIR lua.h
		  HINTS
		  "${RSPAMD_SEARCH_PATH}"
		  $ENV{LUA_DIR}
		  PATH_SUFFIXES "include/luajit-2.0" 
		  				"include/luajit${_major}${_minor}" 
		  				"include/luajit${_major}.${_minor}" 
		  				"include/luajit-${_major}.${_minor}"
		  				"include/luajit" 
		  				"include/lua${_major}${_minor}" 
		  				"include/lua${_major}.${_minor}" 
		  				"include/lua-${_major}.${_minor}"
		  				include/lua include
		  PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
		)
		FIND_LIBRARY(LUA_LIBRARY 
		 	NAMES luajit 
		  		"luajit-2.0"
		  		"luajit2.0"
		  		"luajit${_major}${_minor}"
		  		"luajit${_major}.${_minor}" 
		  		"luajit-${_major}.${_minor}"
			HINTS
				"${RSPAMD_SEARCH_PATH}"
		  		$ENV{LUA_DIR}
		  	PATH_SUFFIXES lib64 lib
		  	PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
		 	DOC "Lua library"
		)
		
		IF(NOT LUA_LIBRARY OR NOT LUA_INCLUDE_DIR)
			MESSAGE(STATUS "Fallback from luajit to plain lua")
			SET(ENABLE_LUAJIT "OFF")
			MESSAGE(STATUS "Check for lua ${_major}.${_minor}")
			FIND_PATH(LUA_INCLUDE_DIR lua.h
			  HINTS
			  "${RSPAMD_SEARCH_PATH}"
			  $ENV{LUA_DIR}
			  PATH_SUFFIXES "include/lua${_major}${_minor}" 
			  				"include/lua${_major}.${_minor}" 
			  				"include/lua-${_major}.${_minor}"
			  				include/lua include
			  PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
			)
			FIND_LIBRARY(LUA_LIBRARY 
			 	NAMES lua 
			  		"lua${_major}${_minor}"
			  		"lua${_major}.${_minor}" 
			  		"lua-${_major}.${_minor}"
				HINTS
					"${RSPAMD_SEARCH_PATH}"
			  		$ENV{LUA_DIR}
			  	PATH_SUFFIXES lib64 lib
			  	PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
			 	DOC "Lua library"
			)
		ENDIF()
	ELSE(ENABLE_LUAJIT MATCHES "ON")
		MESSAGE(STATUS "Check for lua ${_major}.${_minor}")
		FIND_PATH(LUA_INCLUDE_DIR lua.h
		  HINTS
		  "${RSPAMD_SEARCH_PATH}"
		  $ENV{LUA_DIR}
		  PATH_SUFFIXES "include/lua${_major}${_minor}" 
		  				"include/lua${_major}.${_minor}" 
		  				"include/lua-${_major}.${_minor}"
		  				include/lua include
		  PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
		)
		FIND_LIBRARY(LUA_LIBRARY 
		 	NAMES lua 
		  		"lua${_major}${_minor}"
		  		"lua${_major}.${_minor}" 
		  		"lua-${_major}.${_minor}"
			HINTS
				"${RSPAMD_SEARCH_PATH}"
		  		$ENV{LUA_DIR}
		  	PATH_SUFFIXES lib64 lib
		  	PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
		 	DOC "Lua library"
		)
	ENDIF(ENABLE_LUAJIT MATCHES "ON")

	IF(LUA_LIBRARY AND LUA_INCLUDE_DIR)
		SET(LUA_FOUND 1)
		IF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
			SET(LUA_VERSION_MAJOR ${_major})
			SET(LUA_VERSION_MINOR ${_minor})
		ENDIF(NOT LUA_VERSION_MAJOR OR NOT LUA_VERSION_MINOR)
		IF(ENABLE_LUAJIT MATCHES "ON")
			MESSAGE(STATUS "Found luajit ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
		ELSE(ENABLE_LUAJIT MATCHES "ON")
			MESSAGE(STATUS "Found lua ${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}")
		ENDIF(ENABLE_LUAJIT MATCHES "ON")
	ENDIF(LUA_LIBRARY AND LUA_INCLUDE_DIR)
ENDMACRO(FindLua _major _minor)

FUNCTION(INSTALL_IF_NOT_EXISTS src dest destname suffix)
  IF(NOT IS_ABSOLUTE "${src}")
    SET(src "${CMAKE_CURRENT_SOURCE_DIR}/${src}")
  ENDIF()
  GET_FILENAME_COMPONENT(src_name "${src}" NAME)
  GET_FILENAME_COMPONENT(dest_name "${destname}" NAME)
  IF(NOT IS_ABSOLUTE "${dest}")
    SET(dest "${CMAKE_INSTALL_PREFIX}/${dest}")
  ENDIF()
  INSTALL(CODE "
    IF(NOT EXISTS \"\$ENV{DESTDIR}${dest}/${dest_name}${suffix}\")
      #FILE(INSTALL \"${src}\" DESTINATION \"${dest}\")
      MESSAGE(STATUS \"Installing: \$ENV{DESTDIR}${dest}/${dest_name}${suffix}\")
      EXECUTE_PROCESS(COMMAND \${CMAKE_COMMAND} -E copy \"${src}\"
                      \"\$ENV{DESTDIR}${dest}/${dest_name}${suffix}\"
                      RESULT_VARIABLE copy_result
                      ERROR_VARIABLE error_output)
      IF(copy_result)
        MESSAGE(FATAL_ERROR \${error_output})
      ENDIF()
    ELSE()
      MESSAGE(STATUS \"Skipping  : \$ENV{DESTDIR}${dest}/${dest_name}${suffix}\")
    ENDIF()
  ")
ENDFUNCTION(INSTALL_IF_NOT_EXISTS)

# Process required package by using FindPackage and calling for INCLUDE_DIRECTORIES and
# setting list of required libraries
MACRO(ProcessPackage var _name0)
	IF(NOT RSPAMD_SEARCH_PATH)
	    PKG_SEARCH_MODULE(${var} "${_name0}" ${ARGN})
	    IF(${var}_FOUND)
	        SET(WITH_${var} 1)
	        IF(ENABLE_STATIC MATCHES "ON")
	            SET(_XPREFIX "${var}_STATIC")
	        ELSE(ENABLE_STATIC MATCHES "ON")
	            SET(_XPREFIX "${var}")
	        ENDIF(ENABLE_STATIC MATCHES "ON")
	        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
	            INCLUDE_DIRECTORIES("${_arg}")
	            SET(${var}_INCLUDE "${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
	        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
	            LINK_DIRECTORIES("${_arg}")
	            SET(${var}_LIBRARY "${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
	        # Handle other CFLAGS and LDFLAGS
	        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
	            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
	        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
	            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
	        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
	        LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
	    ELSE(${var}_FOUND)
	 		# Try some more heuristic
			FIND_LIBRARY(_lib NAMES "${_name0}" ${ARGN}
						HINTS
						"${RSPAMD_SEARCH_PATH}"
						PATH_SUFFIXES lib64 lib
						PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS})
			IF(NOT _lib)
				MESSAGE(FATAL_ERROR "Packages ${_name0} ${ARGN} could not be found, no library")
			ENDIF(NOT _lib)
			
			FIND_PATH(_incl "${_name0}.h" 
							HINTS "${RSPAMD_SEARCH_PATH}"
							PATH_SUFFIXES "include" "include/${_name0}" ${ARGN}
							PATHS 	${RSPAMD_DEFAULT_INCLUDE_PATHS})
			IF(NOT _incl)
				MESSAGE(FATAL_ERROR "Packages ${_name0} ${ARGN} could not be found, no header")
			ENDIF(NOT _incl)
			
			GET_FILENAME_COMPONENT(_lib_path "${_lib}" PATH)
			INCLUDE_DIRECTORIES("${_incl}")
			LINK_DIRECTORIES("${_lib_path}")
			LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ${_lib})
			SET(${var}_INCLUDE "${_incl}")
			SET(${var}_LIBRARY "${_lib_path}")
			MESSAGE(STATUS "Found ${_name0} ${ARGN} in '${_lib_path}' (library) and '${_incl}' (include).")
		ENDIF(${var}_FOUND)
	ELSE(NOT RSPAMD_SEARCH_PATH)
 		# Try heuristic first
		FIND_LIBRARY(_lib NAMES "${_name0}" ${ARGN}
					HINTS
					"${RSPAMD_SEARCH_PATH}"
					PATH_SUFFIXES lib64 lib
					PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS})
		IF(_lib)
			FIND_PATH(_incl "${_name0}.h" 
							HINTS "${RSPAMD_SEARCH_PATH}"
							PATH_SUFFIXES "include" "include/${_name0}" ${ARGN}
							PATHS 	${RSPAMD_DEFAULT_INCLUDE_PATHS})
			IF(_incl)
				GET_FILENAME_COMPONENT(_lib_path "${_lib}" PATH)
				INCLUDE_DIRECTORIES("${_incl}")
				LINK_DIRECTORIES("${_lib_path}")
				MESSAGE(STATUS "Found ${_name0} ${ARGN} in '${_lib_path}' (library) and '${_incl}' (include).")
				SET(${var}_INCLUDE "${_incl}")
				SET(${var}_LIBRARY "${_lib_path}")
				LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ${_lib})
			ENDIF(_incl)
		ENDIF(_lib)
		
		IF(NOT _incl OR NOT _lib)
			PKG_SEARCH_MODULE(${var} "${_name0}" ${ARGN})
		    IF(${var}_FOUND)
		        SET(WITH_${var} 1)
		        IF(ENABLE_STATIC MATCHES "ON")
		            SET(_XPREFIX "${var}_STATIC")
		        ELSE(ENABLE_STATIC MATCHES "ON")
		            SET(_XPREFIX "${var}")
		        ENDIF(ENABLE_STATIC MATCHES "ON")
		        FOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
		            INCLUDE_DIRECTORIES("${_arg}")
		            SET(${var}_INCLUDE "${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_INCLUDE_DIRS})
		        FOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
		            LINK_DIRECTORIES("${_arg}")
		            SET(${var}_LIBRARY "${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_LIBRARY_DIRS})
		        # Handle other CFLAGS and LDFLAGS
		        FOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
		            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_CFLAGS_OTHER})
		        FOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
		            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${_arg}")
		        ENDFOREACH(_arg ${${_XPREFIX}_LDFLAGS_OTHER})
		        LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${${_XPREFIX}_LIBRARIES}")
			ELSE(${var}_FOUND)
				MESSAGE(FATAL_ERROR "Packages ${_name0} ${ARGN} could not be found")
			ENDIF(${var}_FOUND)
		ENDIF(NOT _incl OR NOT _lib)
	ENDIF(NOT RSPAMD_SEARCH_PATH)
	# Cleanup
	UNSET(_lib CACHE)
	UNSET(_incl CACHE)
ENDMACRO(ProcessPackage name)

MACRO(ADD_PRECOMPILED_HEADER _target _input)
	GET_FILENAME_COMPONENT(_name ${_input} NAME)
	SET(_outdir "${CMAKE_BINARY_DIR}/${_name}.pch")
	MAKE_DIRECTORY(${_outdir})
	SET(_output "${_outdir}/${_name}.pch")
	STRING(TOUPPER "CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}" _flags_var_name)
	SET(_compiler_FLAGS ${${_flags_var_name}})
	GET_DIRECTORY_PROPERTY(_directory_flags INCLUDE_DIRECTORIES)
	FOREACH(item ${_directory_flags})
		LIST(APPEND _compiler_FLAGS "-I${item}")
	ENDFOREACH(item)

	INCLUDE_DIRECTORIES(${_outdir})
	IF("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
		IF(NOT TARGET ${_name}_pch)
			MESSAGE("${CMAKE_C_COMPILER} -DPCHCOMPILE ${CMAKE_C_FLAGS} -x c-header -o ${_output} ${_input}")
			ADD_CUSTOM_COMMAND(OUTPUT ${_output}
				COMMAND ${CMAKE_C_COMPILER} -DPCHCOMPILE ${_compiler_FLAGS} -x c-header -o ${_output} ${_input}
				DEPENDS ${_input})
			ADD_CUSTOM_TARGET(${_name}_pch DEPENDS ${_output})
		ENDIF()

		ADD_CUSTOM_TARGET(${_target}_pch DEPENDS ${_name}_pch)
		ADD_DEPENDENCIES(${_target} ${_target}_pch)
		SET_TARGET_PROPERTIES(${_target} PROPERTIES COMPILE_FLAGS "-include ${_name} -Winvalid-pch")
	ENDIF()
ENDMACRO()

############################# CONFIG SECTION #############################################
# Initial set

INCLUDE_DIRECTORIES(src/libutil src/libserver src/libmime src/libstat src/libcryptobox)

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

SET(POE_LOOP "POE::Loop::IO_Poll")

# Platform specific configuration
IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DFREEBSD")
	CONFIGURE_FILE(freebsd/rspamd.sh.in freebsd/rspamd @ONLY)

	IF(ENABLE_REDIRECTOR MATCHES "ON")
		CONFIGURE_FILE(freebsd/redirector.sh.in freebsd/redirector @ONLY)
	ENDIF(ENABLE_REDIRECTOR MATCHES "ON")
	MESSAGE(STATUS "Configuring for FreeBSD")
	# Find util library

	FIND_LIBRARY(LIBUTIL_LIBRARY NAMES util 
					HINTS "${RSPAMD_SEARCH_PATH}"
						PATH_SUFFIXES lib64 lib
	                  PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
	                 DOC "Path where the libutil library can be found")
	IF(LIBUTIL_LIBRARY)
		FIND_FILE(_LIBUTIL_H 
					HINTS "${RSPAMD_SEARCH_PATH}" 
					NAMES libutil.h PATH ${RSPAMD_DEFAULT_INCLUDE_PATHS}
					PATH_SUFFIXES include
					DOC "Path to libutil header")
		IF(_LIBUTIL_H)
			SET(HAVE_LIBUTIL_H 1)
			LIST(APPEND RSPAMD_REQUIRED_LIBRARIES util)
			CHECK_FUNCTION_EXISTS(pidfile_open HAVE_PIDFILE)
			CHECK_FUNCTION_EXISTS(pidfile_fileno HAVE_PIDFILE_FILENO)
		ENDIF(_LIBUTIL_H)
	ENDIF(LIBUTIL_LIBRARY)
	SET(POE_LOOP "POE::Loop::Kqueue")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DDARWIN")
    SET(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
	IF(ENABLE_LUAJIT MATCHES "ON")
		SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pagezero_size 10000 -image_base 100000000")
	ENDIF(ENABLE_LUAJIT MATCHES "ON")
	MESSAGE(STATUS "Configuring for Darwin")
	SET(POE_LOOP "POE::Loop::Kqueue")

ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DLINUX")
    IF(BUILD_CPU_MODE STREQUAL "32")
    	SET(CMAKE_C_FLAGS  "-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE ${CMAKE_C_FLAGS}")
    ENDIF(BUILD_CPU_MODE STREQUAL "32")
    # Workaround with architecture specific includes
    IF(IS_DIRECTORY "/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/") 
    	INCLUDE_DIRECTORIES("/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/")
    	LIST(APPEND CMAKE_REQUIRED_INCLUDES "/usr/include/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/")
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
	SET(POE_LOOP "POE::XS::Loop::EPoll")
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
  	SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib:${RSPAMD_LIBDIR}")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")

# Now find libraries and headers

IF(ENABLE_LUAJIT MATCHES "ON")
	#ProcessPackage(LUAJIT luajit)
	SET(WITH_LUA 1)
	FindLua(5 1)
	IF(NOT LUA_FOUND)
        MESSAGE(FATAL_ERROR "Lua not found, lua support is required")
	ELSE(NOT LUA_FOUND)
    	SET(WITH_LUA 1)
    	INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
	ENDIF(NOT LUA_FOUND)
ELSE(ENABLE_LUAJIT MATCHES "ON")
	FindLua(5 2)
	IF(NOT LUA_FOUND)
        	FindLua(5 1)
	ENDIF(NOT LUA_FOUND)
	IF(NOT LUA_FOUND)
        	MESSAGE(FATAL_ERROR "Lua not found, lua support is required")
	ELSE(NOT LUA_FOUND)
    		SET(WITH_LUA 1)
    		INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
	ENDIF(NOT LUA_FOUND)
ENDIF(ENABLE_LUAJIT MATCHES "ON")

#Check for openssl (required for dkim)
IF(OPENSSL_FOUND)
	SET(HAVE_OPENSSL 1)
	INCLUDE_DIRECTORIES("${OPENSSL_INCLUDE_DIR}")
ENDIF(OPENSSL_FOUND)

ProcessPackage(GLIB2 glib-2.0>=2.28)
ProcessPackage(GTHREAD gthread-2.0)
ProcessPackage(PCRE pcre libpcre pcre3 libpcre3)
ProcessPackage(GMIME2 gmime-2.6 gmime-2.4 gmime-2.0)
ProcessPackage(LIBEVENT event libevent)
ProcessPackage(SQLITE sqlite3>=3.6.0)
IF(GMIME2_VERSION VERSION_GREATER "2.4.0")
    SET(GMIME24 1)
ENDIF(GMIME2_VERSION VERSION_GREATER "2.4.0")
LIST(APPEND CMAKE_REQUIRED_INCLUDES "${PCRE_INCLUDE}")
IF(PCRE_LIBRARY)
	SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-L${PCRE_LIBRARY};-lpcre")
ELSE(PCRE_LIBRARY)
	SET(CMAKE_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES};-lpcre")
ENDIF(PCRE_LIBRARY)
# Libhiredis pc file is so special
IF(ENABLE_HIREDIS MATCHES "ON")
	ProcessPackage(HIREDIS hiredis libhiredis)
	SET(WITH_HIREDIS 1)
	FIND_PATH(LIBHIREDIS_INCLUDE hiredis.h 
		HINTS "${RSPAMD_SEARCH_PATH}"
		PATH_SUFFIXES "include" "include/hiredis"
		PATHS	${RSPAMD_DEFAULT_INCLUDE_PATHS}
		DOC "Path where the hiredis header files can be found")

	IF(LIBHIREDIS_INCLUDE)
	       INCLUDE_DIRECTORIES("${LIBHIREDIS_INCLUDE}")
	ENDIF(LIBHIREDIS_INCLUDE)
ENDIF(ENABLE_HIREDIS MATCHES "ON")


# Google performance tools

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	FIND_PATH(GPERF_INCLUDE google/profiler.h
			PATH_SUFFIXES "include" "include/google"
			PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
			DOC "Path where google perftools includes can be found")
	INCLUDE_DIRECTORIES("${GPERF_INCLUDE}")
	FIND_LIBRARY(GPERF_LIBRARY NAMES profiler 
	              HINTS "${RSPAMD_SEARCH_PATH}"
                  PATH_SUFFIXES lib64 lib "lib/google"
                  PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
				  DOC "Path where the gperf library can be found")
	IF(NOT GPERF_LIBRARY)
		MESSAGE(FATAL_ERROR "gperf tools support is enabled but not found in system")
	ENDIF(NOT GPERF_LIBRARY)
	GET_FILENAME_COMPONENT(GPERF_PATH "${GPERF_LIBRARY}" PATH)
	LINK_DIRECTORIES("${GPERF_PATH}")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
	SET(WITH_GPERF_TOOLS 1)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

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
CHECK_INCLUDE_FILES(stdbool.h  HAVE_STDBOOL_H)
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
CHECK_INCLUDE_FILES(ctype.h HAVE_CTYPE_H)
CHECK_INCLUDE_FILES(sys/sendfile.h HAVE_SYS_SENDFILE_H)
CHECK_INCLUDE_FILES(linux/falloc.h HAVE_LINUX_FALLOC_H)
CHECK_INCLUDE_FILES(sys/eventfd.h HAVE_SYS_EVENTFD_H)
CHECK_INCLUDE_FILES(aio.h HAVE_AIO_H)
CHECK_INCLUDE_FILES(libaio.h HAVE_LIBAIO_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(cpuid.h HAVE_CPUID_H)

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
CHECK_FUNCTION_EXISTS(memset_s HAVE_MEMSET_S)
CHECK_FUNCTION_EXISTS(explicit_bzero HAVE_EXPLICIT_BZERO)
CHECK_C_SOURCE_COMPILES(
"#include <stddef.h>
void cmkcheckweak() __attribute__((weak));
int main(int argc, char** argv) {
  return cmkcheckweak == NULL;
}" HAVE_WEAK_SYMBOLS)

IF(NOT ICONV_ROOT_DIR)
	FIND_PATH(ICONV_INCLUDE_DIR iconv.h 
			HINTS "${RSPAMD_SEARCH_PATH}"
			PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
            PATH_SUFFIXES include include/libiconv
            DOC "Path where the libiconv headers can be found")
	FIND_LIBRARY(ICONV_LIBRARIES NAMES iconv libiconv libiconv-2 c
			HINTS "${RSPAMD_SEARCH_PATH}"
            PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
            PATH_SUFFIXES lib64 lib
            DOC "Path where the libiconv library can be found")
ELSE(NOT ICONV_ROOT_DIR)
	FIND_PATH(ICONV_INCLUDE_DIR iconv.h 
				HINTS "${RSPAMD_SEARCH_PATH}"
			     PATHS "${ICONV_ROOT_DIR}"
			     PATH_SUFFIXES include include/libiconv
                 DOC "Path where the libiconv headers can be found"
                 NO_DEFAULT_PATH)
	FIND_LIBRARY(ICONV_LIBRARIES NAMES iconv libiconv libiconv-2 c
				HINTS "${RSPAMD_SEARCH_PATH}"
                 PATHS "${ICONV_ROOT_DIR}"
                 PATH_SUFFIXES lib64 lib
                 DOC "Path where the libiconv library can be found"
                 NO_DEFAULT_PATH)
ENDIF(NOT ICONV_ROOT_DIR)
IF(ICONV_INCLUDE_DIR AND ICONV_LIBRARIES)
	SET(ICONV_FOUND TRUE)
ENDIF(ICONV_INCLUDE_DIR AND ICONV_LIBRARIES)
INCLUDE_DIRECTORIES(${ICONV_INCLUDE_DIR})
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ${ICONV_LIBRARIES})

IF(ICONV_FOUND)
	CHECK_C_SOURCE_COMPILES("
#include <iconv.h>
int main(){
	iconv_t conv = 0;
	const char* in = 0;
	size_t ilen = 0;
	char* out = 0;
	size_t olen = 0;
	iconv(conv, &in, &ilen, &out, &olen);
	return 0;
}
" ICONV_SECOND_ARGUMENT_IS_CONST)
ENDIF(ICONV_FOUND)

IF(ICONV_FOUND)
	MESSAGE(STATUS "Found Iconv: ${ICONV_LIBRARIES}")
ELSE(ICONV_FOUND)
	MESSAGE(FATAL_ERROR "Could not find Iconv")
ENDIF(ICONV_FOUND)

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
CHECK_SYMBOL_EXISTS(sched_yield "sched.h" HAVE_SCHED_YIELD)
CHECK_SYMBOL_EXISTS(__get_cpuid "cpuid.h" HAVE_GET_CPUID)
CHECK_SYMBOL_EXISTS(PCRE_CONFIG_JIT "pcre.h" HAVE_PCRE_JIT)

# Some PCRE implementations are lacking of pcre_jit_exec fast path
SET(_PCRE_FAST_TEST "
#include \"pcre.h\"
int main (void) 
{
	int rc;
	int ovector[30];
	pcre *re;
	pcre_extra *extra;
	pcre_jit_stack *jit_stack;
	
	re = pcre_compile(\"abc\", 0, NULL, NULL, NULL);
	extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, NULL);
	jit_stack = pcre_jit_stack_alloc(32*1024, 512*1024);
	pcre_assign_jit_stack(extra, NULL, jit_stack);
	rc = pcre_jit_exec(re, extra, \"abc\", 3, 0, 0, ovector, 30, jit_stack);
	
	return rc;
}
")

CHECK_C_SOURCE_COMPILES("${_PCRE_FAST_TEST}" HAVE_PCRE_JIT_FAST)
IF(HAVE_PCRE_JIT_FAST)
	MESSAGE(STATUS "pcre_jit_exec is supported")
ELSE(HAVE_PCRE_JIT_FAST)
	MESSAGE(STATUS "pcre_jit_exec is -NOT- supported")
ENDIF(HAVE_PCRE_JIT_FAST)

FILE(WRITE ${CMAKE_BINARY_DIR}/pthread_setpshared.c "
#include <pthread.h>
#include <stdlib.h>
int main (void)
{
	pthread_mutexattr_t mattr;
	if (pthread_mutexattr_init(&mattr) != 0) return 0;
	if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) != 0) return 0;
	if (pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST) != 0) return 0;
	return 1;
}
")
TRY_RUN(_CAN_RUN _CAN_COMPILE
	"${CMAKE_BINARY_DIR}" "${CMAKE_BINARY_DIR}/pthread_setpshared.c"
	CMAKE_FLAGS CMAKE_C_FLAGS="-pthread")
IF(_CAN_RUN EQUAL 1)
	SET(HAVE_PTHREAD_PROCESS_SHARED 1)
ENDIF(_CAN_RUN EQUAL 1)
IF(HAVE_PTHREAD_PROCESS_SHARED)
	MESSAGE(STATUS "pthread_mutexattr_setpshared is supported")
ELSE(HAVE_PTHREAD_PROCESS_SHARED)
	MESSAGE(STATUS "pthread_mutexattr_setpshared is -NOT- supported")
ENDIF(HAVE_PTHREAD_PROCESS_SHARED)

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

IF(ENABLE_URL_INCLUDE MATCHES "ON")
    FIND_LIBRARY(LIBFETCH_LIBRARY HINTS "${RSPAMD_SEARCH_PATH}"
    				NAMES fetch PATHS	PATH_SUFFIXES lib64 lib
                    PATHS ${RSPAMD_DEFAULT_LIBRARY_PATHS}
                    DOC "Path where the libfetch library can be found")
    IF(LIBFETCH_LIBRARY)
    	FIND_FILE(HAVE_FETCH_H HINTS "${RSPAMD_SEARCH_PATH}"
    		NAMES fetch.h 
    		PATH_SUFFIXES include
    		PATHS ${RSPAMD_DEFAULT_INCLUDE_PATHS}
    				DOC "Path to libfetch header")
    ELSE(LIBFETCH_LIBRARY)
    	# Try to find libcurl
    	ProcessPackage(CURL libcurl)
    	IF(NOT CURL_FOUND)
    		MESSAGE(WARNING "Neither libcurl nor libfetch were found, no support of URL includes in configuration")
    	ENDIF(NOT CURL_FOUND)
    ENDIF(LIBFETCH_LIBRARY)
ENDIF(ENABLE_URL_INCLUDE MATCHES "ON")

IF(NOT DESTDIR)
    SET(DESTDIR $ENV{DESTDIR})
ENDIF(NOT DESTDIR)

# Try to detect tip version from hg
SET(ID "unknown")
FIND_PROGRAM(HG "git")

IF(HG)
    EXECUTE_PROCESS(COMMAND "${HG}" rev-parse --verify HEAD 
    	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    	OUTPUT_VARIABLE HG_ID ERROR_QUIET)
    IF(HG_ID)
        STRING(SUBSTRING "${HG_ID}" 0 10 RSPAMD_ID)
        MESSAGE(STATUS "Git revision: ${RSPAMD_ID}")
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
					"${CMAKE_BINARY_DIR}/src/libcryptobox"
					"${CMAKE_SOURCE_DIR}/contrib/libucl"
					"${CMAKE_SOURCE_DIR}/contrib/uthash"
					"${CMAKE_SOURCE_DIR}/contrib/http-parser"
					"${CMAKE_SOURCE_DIR}/contrib/libottery"
					"${CMAKE_SOURCE_DIR}/contrib/xxhash"
					"${CMAKE_SOURCE_DIR}/contrib/cdb"
					"${CMAKE_SOURCE_DIR}/contrib/snowball/include"
					"${CMAKE_SOURCE_DIR}/contrib/blake2"
					"${CMAKE_SOURCE_DIR}/contrib/librdns"
					"${CMAKE_SOURCE_DIR}/contrib/aho-corasick")

################################ SUBDIRS SECTION ###########################

ADD_SUBDIRECTORY(contrib/lgpl)
IF(GLIB_COMPAT)
	INCLUDE_DIRECTORIES("${CMAKE_CURRENT_SOURCE_DIR}/contrib/lgpl")
ENDIF(GLIB_COMPAT)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}")
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ucl)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES rdns)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ottery)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES event)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES xxhash)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES blake2)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES sqlite3)
IF(OPENSSL_FOUND)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
ENDIF(OPENSSL_FOUND)
IF(HAVE_FETCH_H)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES fetch)
ENDIF(HAVE_FETCH_H)
LIST(APPEND RSPAMD_REQUIRED_LIBRARIES event)
IF(HAVE_LIBEVENT2)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES event_pthreads)
ENDIF(HAVE_LIBEVENT2)
IF(WITH_DB)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES db)
ENDIF(WITH_DB)


LIST(APPEND RSPAMD_REQUIRED_LIBRARIES "${LUA_LIBRARY}")

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES profiler)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

IF(ENABLE_HIREDIS MATCHES "ON")
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES hiredis)
ENDIF(ENABLE_HIREDIS MATCHES "ON")
IF(GLIB_COMPAT)
	LIST(APPEND RSPAMD_REQUIRED_LIBRARIES glibadditions)
ENDIF(GLIB_COMPAT)

ADD_SUBDIRECTORY(contrib/xxhash)
ADD_SUBDIRECTORY(contrib/cdb)
ADD_SUBDIRECTORY(contrib/http-parser)
ADD_SUBDIRECTORY(contrib/libottery)
ADD_SUBDIRECTORY(contrib/snowball)
ADD_SUBDIRECTORY(contrib/blake2)
ADD_SUBDIRECTORY(contrib/libucl)
ADD_SUBDIRECTORY(contrib/librdns)
ADD_SUBDIRECTORY(contrib/aho-corasick)
ADD_SUBDIRECTORY(src)

ADD_SUBDIRECTORY(test)

############################ TARGETS SECTION ###############################


CONFIGURE_FILE(config.h.in src/config.h)
CONFIGURE_FILE(contrib/exim/local_scan.c.in contrib/exim/local_scan_rspamd.c @ONLY)

SET(CONFFILES 
	conf/common.conf
	conf/composites.conf
	conf/metrics.conf
	conf/modules.conf
	conf/statistic.conf
	conf/2tld.inc
	conf/logging.inc
	conf/options.inc
	conf/surbl-whitelist.inc
	conf/worker-controller.inc
	conf/worker-normal.inc)

##################### INSTALLATION ##########################################

# Binaries

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
		INSTALL_IF_NOT_EXISTS(${CONF_FILE} ${CONFDIR} ${CONF_FILE} ".sample")
	ELSE(BUILD_PORT)
		INSTALL_IF_NOT_EXISTS(${CONF_FILE} ${CONFDIR} ${CONF_FILE} "")
	ENDIF(BUILD_PORT)
	IF(INSTALL_EXAMPLES MATCHES "ON")
		INSTALL(FILES ${CONF_FILE} DESTINATION ${EXAMPLESDIR})
	ENDIF(INSTALL_EXAMPLES MATCHES "ON")
ENDFOREACH(CONF_IDX RANGE ${CONFLIST_MAX})

# Main config is special due to systemd
IF(WANT_SYSTEMD_UNITS MATCHES "ON")
	SET(MAIN_CONF "conf/rspamd.systemd.conf")
ELSE(WANT_SYSTEMD_UNITS MATCHES "ON")
	SET(MAIN_CONF "conf/rspamd.sysvinit.conf")
ENDIF(WANT_SYSTEMD_UNITS MATCHES "ON")
IF(BUILD_PORT)
	INSTALL_IF_NOT_EXISTS(${MAIN_CONF} ${CONFDIR} "rspamd.conf" ".sample")
ELSE(BUILD_PORT)
	INSTALL_IF_NOT_EXISTS(${MAIN_CONF} ${CONFDIR} "rspamd.conf" "")
ENDIF(BUILD_PORT)
# Debian is also special
IF(DEBIAN_BUILD)
	INSTALL_IF_NOT_EXISTS("conf/rspamd.sysvinit.conf" ${CONFDIR} "rspamd.sysvinit.conf" "")
ENDIF(DEBIAN_BUILD)
IF(INSTALL_EXAMPLES MATCHES "ON")
	INSTALL(FILES ${MAIN_CONF} DESTINATION ${EXAMPLESDIR})
ENDIF(INSTALL_EXAMPLES MATCHES "ON")

# Lua plugins

FILE(GLOB LUA_PLUGINS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua" 
	"${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua/*.lua" )
FOREACH(LUA_PLUGIN ${LUA_PLUGINS})
	GET_FILENAME_COMPONENT(_rp ${LUA_PLUGIN} PATH)
	INSTALL(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}${PLUGINSDIR}/lua/${_rp})")
	INSTALL(FILES "src/plugins/lua/${LUA_PLUGIN}" DESTINATION ${PLUGINSDIR}/lua/${_rp})
ENDFOREACH(LUA_PLUGIN)

# Install lua fun library
INSTALL(FILES "contrib/lua-fun/fun.lua" DESTINATION ${PLUGINSDIR}/lua)

# Install TLD list
INSTALL(FILES "contrib/publicsuffix/effective_tld_names.dat" DESTINATION 
	"${PLUGINSDIR}")

# Redirector
IF(ENABLE_REDIRECTOR MATCHES "ON")
	CONFIGURE_FILE(utils/redirector.pl.in utils/redirector.pl @ONLY)
	INSTALL(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/utils/redirector.pl"
		DESTINATION bin RENAME rspamd-redirector)
ENDIF(ENABLE_REDIRECTOR MATCHES "ON")

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
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WANT_SYSTEMD_UNITS MATCHES "ON")
	INSTALL(FILES "rspamd.service" DESTINATION ${SYSTEMDDIR})
	INSTALL(FILES "rspamd.socket" DESTINATION ${SYSTEMDDIR})
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WANT_SYSTEMD_UNITS MATCHES "ON")

# Manual pages
INSTALL(FILES "doc/rspamd.8" DESTINATION ${MANDIR}/man8)
INSTALL(FILES "doc/rspamc.1" DESTINATION ${MANDIR}/man1)

# Install webui
IF(INSTALL_WEBUI MATCHES "ON")
	INSTALL(DIRECTORY "interface/" DESTINATION ${WWWDIR} PATTERN ".git" EXCLUDE)
ENDIF(INSTALL_WEBUI MATCHES "ON")

ADD_CUSTOM_TARGET(dist ${CMAKE_SOURCE_DIR}/dist.sh
	"${CMAKE_BINARY_DIR}/rspamd-${RSPAMD_VERSION}.tar.xz"
	COMMENT "Create source distribution"
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

IF(NOT DEBIAN_BUILD)
	ADD_CUSTOM_TARGET(check DEPENDS rspamd-test)
	ADD_CUSTOM_TARGET(run-test DEPENDS check COMMAND test/rspamd-test)
ENDIF(NOT DEBIAN_BUILD)
