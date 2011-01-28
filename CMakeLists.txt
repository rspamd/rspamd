#
# Rspamd - rambler antispam system
#
# Cmake configuration file
#
PROJECT(rspamd C)

SET(RSPAMD_VERSION_MAJOR 0)
SET(RSPAMD_VERSION_MINOR 3)
SET(RSPAMD_VERSION_PATCH 4)


SET(RSPAMD_VERSION         "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}")
SET(RSPAMD_MASTER_SITE_URL "http://bitbucket.org/vstakhov/rspamd")
SET(RSPAMD_USER "nobody")
SET(RSPAMD_GROUP "nobody")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.3 FATAL_ERROR)

OPTION(DEBUG_MODE          "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(SKIP_RELINK_RPATH   "Skip relinking and full RPATH for the install tree" OFF)
OPTION(ENABLE_REDIRECTOR   "Enable redirector install [default: OFF]"           OFF)
OPTION(ENABLE_PROFILING    "Enable profiling [default: OFF]"                    OFF)
OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]"             OFF)
OPTION(ENABLE_STATIC       "Enable static compiling [default: OFF]"             OFF)

# Build optimized code for following CPU (default i386)
#SET(CPU_TUNE               "i686")

############################# CONFIG SECTION #############################################

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CheckLibraryExists)
INCLUDE(FindPkgConfig)
INCLUDE(CheckCCompilerFlag)
INCLUDE(FindPerl)

# Initial set
SET(CMAKE_REQUIRED_LIBRARIES m)
SET(CMAKE_REQUIRED_INCLUDES sys/mman.h stdlib.h stdio.h unistd.h time.h sched.h)

IF(CMAKE_INSTALL_PREFIX)
    SET(PREFIX ${CMAKE_INSTALL_PREFIX})
ENDIF(CMAKE_INSTALL_PREFIX)

# Platform specific routines
IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DFREEBSD")
	CONFIGURE_FILE(freebsd/rspamd.sh.in freebsd/rspamd.sh @ONLY)

	IF(ENABLE_REDIRECTOR MATCHES "ON")
		CONFIGURE_FILE(freebsd/redirector.sh.in freebsd/redirector.sh @ONLY)
	ENDIF(ENABLE_REDIRECTOR MATCHES "ON")
	IF(CMAKE_INSTALL_PREFIX)
	    SET(ETC_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(MAN_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(PREFIX "${CMAKE_INSTALL_PREFIX}")
	ELSE(CMAKE_INSTALL_PREFIX)
    	IF(NOT ETC_PREFIX)
    		SET(ETC_PREFIX /usr/local/etc)
    	ENDIF(NOT ETC_PREFIX)
    	IF(NOT MAN_PREFIX)
    		SET(MAN_PREFIX /usr/local/man)
    	ENDIF(NOT MAN_PREFIX)
    	IF(NOT PREFIX)
    		SET(PREFIX /usr/local)
    	ENDIF(NOT PREFIX)
	ENDIF(CMAKE_INSTALL_PREFIX)
    FIND_LIBRARY(LIBINTL_LIBRARY NAMES intl PATHS   /lib
                                               /opt/lib
                                               /usr/lib
                                               /usr/local/lib
                 DOC "Path where the libintl library can be found")
    LIST(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBINTL_LIBRARY})
	MESSAGE(STATUS "Configuring for FreeBSD")
 
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DDARWIN")
    
    IF(CMAKE_INSTALL_PREFIX)
	    SET(ETC_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(MAN_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(PREFIX "${CMAKE_INSTALL_PREFIX}")
	ELSE(CMAKE_INSTALL_PREFIX)    	
    	IF(NOT ETC_PREFIX)
    		SET(ETC_PREFIX /usr/local/etc)
    	ENDIF(NOT ETC_PREFIX)
    	IF(NOT MAN_PREFIX)
    		SET(MAN_PREFIX /usr/local/man)
    	ENDIF(NOT MAN_PREFIX)
    	IF(NOT PREFIX)
    		SET(PREFIX /usr/local)
    	ENDIF(NOT PREFIX)
    ENDIF(CMAKE_INSTALL_PREFIX)

    FIND_LIBRARY(LIBINTL_LIBRARY NAMES intl PATHS   /lib
                                               /opt/lib
                                               /usr/lib
                                               /usr/local/lib
                 DOC "Path where the libintl library can be found")
    LIST(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBINTL_LIBRARY})
	MESSAGE(STATUS "Configuring for Darwin")

ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DLINUX")
	IF(CMAKE_INSTALL_PREFIX)
	    SET(ETC_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(MAN_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(PREFIX "${CMAKE_INSTALL_PREFIX}")
	ELSE(CMAKE_INSTALL_PREFIX)    	
    	IF(NOT ETC_PREFIX)
    		SET(ETC_PREFIX /etc)
    	ENDIF(NOT ETC_PREFIX)
    	IF(NOT PREFIX)
    		SET(PREFIX /usr)
    	ENDIF(NOT PREFIX)
    	IF(NOT MAN_PREFIX)
    		SET(MAN_PREFIX /usr/share/man)
    	ENDIF(NOT MAN_PREFIX)
    ENDIF(CMAKE_INSTALL_PREFIX)    
    
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES rt)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES dl)
	MESSAGE(STATUS "Configuring for Linux")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

IF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DSOLARIS")
	IF(CMAKE_INSTALL_PREFIX)
	    SET(ETC_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(MAN_PREFIX "${CMAKE_INSTALL_PREFIX}/etc")
	    SET(PREFIX "${CMAKE_INSTALL_PREFIX}")
	ELSE(CMAKE_INSTALL_PREFIX)    
    	IF(NOT ETC_PREFIX)
    		SET(ETC_PREFIX /etc)
    	ENDIF(NOT ETC_PREFIX)
    	IF(NOT PREFIX)
    		SET(PREFIX /opt/rspamd)
    	ENDIF(NOT PREFIX)
    	IF(NOT MAN_PREFIX)
    		SET(MAN_PREFIX /usr/share/man)
    	ENDIF(NOT MAN_PREFIX)
    ENDIF(CMAKE_INSTALL_PREFIX)
    
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES rt)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES dl)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES resolv)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES m)
	MESSAGE(STATUS "Configuring for Solaris")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "SunOS")

IF(ENABLE_PERL MATCHES "ON")

	IF(NOT PERL_EXECUTABLE)
		MESSAGE(FATAL_ERROR "Error: Perl is not found but is required")
	ENDIF(NOT PERL_EXECUTABLE)

	# Find perl libraries and cflags
	EXECUTE_PROCESS(COMMAND ${PERL_EXECUTABLE} -MExtUtils::Embed -e ccopts OUTPUT_VARIABLE PERL_CFLAGS)
	EXECUTE_PROCESS(COMMAND ${PERL_EXECUTABLE} -MExtUtils::Embed -e ldopts OUTPUT_VARIABLE PERL_LDFLAGS)
	STRING(REGEX REPLACE "[\r\n]" " " PERL_CFLAGS ${PERL_CFLAGS})
	STRING(REGEX REPLACE " +$" "" PERL_CFLAGS ${PERL_CFLAGS})
	STRING(REGEX REPLACE "[\r\n]" " " PERL_LDFLAGS ${PERL_LDFLAGS})
	STRING(REGEX REPLACE " +$" "" PERL_LDFLAGS ${PERL_LDFLAGS})
	# Handle DynaLoader
	STRING(REGEX MATCH "/[^ ]*/DynaLoader.a" PERL_DYNALOADER ${PERL_LDFLAGS})
	STRING(REGEX REPLACE "/[^ ]*/DynaLoader.a " "" PERL_LDFLAGS ${PERL_LDFLAGS})

	IF(PERL_DYNALOADER)
		EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E copy ${PERL_DYNALOADER} ${rspamd_BINARY_DIR}/compat/libdynaloader.so)
		LINK_DIRECTORIES(${rspamd_BINARY_DIR}/compat/)
	ENDIF(PERL_DYNALOADER)
ELSE(ENABLE_PERL MATCHES "ON")
	SET(WITHOUT_PERL 1)
ENDIF(ENABLE_PERL MATCHES "ON")


INCLUDE(FindLua51)
IF(NOT LUA_FOUND)
    # Automatic check failed, check passed variable
    IF(LUA_INCLUDE_DIR)
        INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
        SET(WITH_LUA 1)
    ELSE(LUA_INCLUDE_DIR)
        MESSAGE(FATAL_ERROR "Lua not found, lua support is required for working")
    ENDIF(LUA_INCLUDE_DIR)
ELSE(NOT LUA_FOUND)
    SET(WITH_LUA 1)
    INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
ENDIF(NOT LUA_FOUND)

IF(ENABLE_STATIC MATCHES "ON")
	pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.16)
	pkg_check_modules(PCRE REQUIRED libpcre)
ELSE(ENABLE_STATIC MATCHES "ON")
	pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.16 gmodule-2.0)
ENDIF(ENABLE_STATIC MATCHES "ON")
pkg_check_modules(GMIME2 gmime-2.0)

# Try to link with gmime24
IF(NOT GMIME2_FOUND OR USE_GMIME24)
	pkg_check_modules(GMIME24 REQUIRED gmime-2.4)
	SET(GMIME24 "yes")
	# Gmime2
	FOREACH(arg ${GMIME24_CFLAGS})
		SET(GMIME_CFLAGS "${GMIME_CFLAGS} ${arg}")
	ENDFOREACH(arg ${GMIME24_CFLAGS})

	IF(ENABLE_STATIC MATCHES "ON")
		FOREACH(arg ${GMIME24_STATIC_LDFLAGS})
			SET(GMIME_LDFLAGS "${GMIME_LDFLAGS} ${arg}")
		ENDFOREACH(arg ${GMIME24_LDFLAGS})
	ELSE(ENABLE_STATIC MATCHES "ON")
		FOREACH(arg ${GMIME24_LDFLAGS})
			SET(GMIME_LDFLAGS "${GMIME_LDFLAGS} ${arg}")
		ENDFOREACH(arg ${GMIME24_LDFLAGS})
	ENDIF(ENABLE_STATIC MATCHES "ON")
	INCLUDE_DIRECTORIES(${GMIME24_INCLUDE_DIRS})
	LINK_DIRECTORIES(${GMIME24_LIBRARY_DIRS})
ELSE(NOT GMIME2_FOUND OR USE_GMIME24)
	# Gmime2
	FOREACH(arg ${GMIME2_CFLAGS})
		SET(GMIME_CFLAGS "${GMIME_CFLAGS} ${arg}")
	ENDFOREACH(arg ${GMIME2_CFLAGS})

	IF(ENABLE_STATIC MATCHES "ON")
		FOREACH(arg ${GMIME2_STATIC_LDFLAGS})
			SET(GMIME_LDFLAGS "${GMIME_LDFLAGS} ${arg}")
		ENDFOREACH(arg ${GMIME2_LDFLAGS})
	ELSE(ENABLE_STATIC MATCHES "ON")
		FOREACH(arg ${GMIME2_LDFLAGS})
			SET(GMIME_LDFLAGS "${GMIME_LDFLAGS} ${arg}")
		ENDFOREACH(arg ${GMIME2_LDFLAGS})
	ENDIF(ENABLE_STATIC MATCHES "ON")
	INCLUDE_DIRECTORIES(${GMIME2_INCLUDE_DIRS})
	LINK_DIRECTORIES(${GMIME2_LIBRARY_DIRS})
ENDIF(NOT GMIME2_FOUND OR USE_GMIME24)

# Make from ; separated list normal space separated list
# Glib2
FOREACH(arg ${GLIB2_CFLAGS})
	SET(GLIB_CFLAGS "${GLIB_CFLAGS} ${arg}")
ENDFOREACH(arg ${GLIB2_CFLAGS})

IF(ENABLE_STATIC MATCHES "ON")
	FOREACH(arg ${GLIB2_STATIC_LDFLAGS})
		SET(GLIB_LDFLAGS "${GLIB_LDFLAGS} ${arg}")
	ENDFOREACH(arg ${GLIB2_LDFLAGS})
ELSE(ENABLE_STATIC MATCHES "ON")
	FOREACH(arg ${GLIB2_LDFLAGS})
		SET(GLIB_LDFLAGS "${GLIB_LDFLAGS} ${arg}")
	ENDFOREACH(arg ${GLIB2_LDFLAGS})
ENDIF(ENABLE_STATIC MATCHES "ON")


INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIRS})
LINK_DIRECTORIES(${GLIB2_LIBRARY_DIRS})


# Check for libevent

FIND_LIBRARY(LIBEVENT_LIBRARY NAMES event PATHS /lib
                                           		/opt/lib
                                            	/usr/lib
                                            	/usr/local/lib
                 DOC "Path where the libevent library can be found")
IF(NOT LIBEVENT_LIBRARY)
	MESSAGE(FATAL_ERROR "libevent is required for building rspamd")
ENDIF(NOT LIBEVENT_LIBRARY)

FIND_PATH(LIBEVENT_INCLUDE event.h PATHS 	/opt/include
										/usr/include
										/usr/local/include
										DOC "Path where the libevent header files can be found")

GET_FILENAME_COMPONENT(LIBEVENT_PATH "${LIBEVENT_LIBRARY}" PATH)
INCLUDE_DIRECTORIES("${LIBEVENT_INCLUDE}")
LINK_DIRECTORIES("${LIBEVENT_PATH}")

# Find libjudy
FIND_LIBRARY(LIBJUDY_LIBRARY NAMES Judy PATHS /lib
                                           		/opt/lib
                                            	/usr/lib
                                            	/usr/local/lib
                 DOC "Path where the libjudy library can be found")
IF(LIBJUDY_LIBRARY)
	FIND_PATH(LIBJUDY_INCLUDE Judy.h PATHS 	/opt/include
											/usr/include
											/usr/local/include
											DOC "Path where the judy header files can be found")

	GET_FILENAME_COMPONENT(LIBJUDY_PATH "${LIBJUDY_LIBRARY}" PATH)
	INCLUDE_DIRECTORIES("${LIBJUDY_INCLUDE}")
	LINK_DIRECTORIES("${LIBJUDY_PATH}")
	SET(WITH_JUDY 1)
ENDIF(LIBJUDY_LIBRARY)

IF(ENABLE_PROFILING MATCHES "ON")
	SET(WITH_PROFILER 1)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
	SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
ENDIF(ENABLE_PROFILING MATCHES "ON")

IF(ENABLE_STATIC MATCHES "ON")
	SET(BUILD_STATIC 1)
	SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
	MESSAGE(STATUS "Static build of rspamd, no custom plugins support")
ENDIF(ENABLE_STATIC MATCHES "ON")

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	FIND_PATH(GPERF_INCLUDE google/profiler.h PATHS /opt/include
													/usr/include
													/usr/local/include
											  DOC "Path where google perftools includes can be found")
	INCLUDE_DIRECTORIES("${GPERF_INCLUDE}")
	FIND_LIBRARY(GPERF_LIBRARY NAMES profiler PATHS /lib
													/opt/lib
													/usr/lib
													/usr/local/lib
					DOC "Path where the gperf library can be found")
	IF(NOT GPERF_LIBRARY)
		MESSAGE(FATAL_ERROR "gperf tools support is enabled but not found in system")
	ENDIF(NOT GPERF_LIBRARY)
	GET_FILENAME_COMPONENT(GPERF_PATH "${GPERF_LIBRARY}" PATH)
	LINK_DIRECTORIES("${GPERF_PATH}")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
	SET(WITH_GPERF_TOOLS 1)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")



FIND_LIBRARY(LIBUTIL_LIBRARY NAMES util PATHS	/lib
                                           		/opt/lib
                                            	/usr/lib
                                            	/usr/local/lib
                 DOC "Path where the libutil library can be found")
IF(LIBUTIL_LIBRARY)
	LIST(APPEND CMAKE_REQUIRED_LIBRARIES util)
	CHECK_FUNCTION_EXISTS(pidfile_open HAVE_PIDFILE)

	FIND_FILE(HAVE_LIBUTIL_H NAMES libutil.h PATHS /usr/include
											   /opt/include
											   /usr/local/include
				DOC "Path to libutil header")
ENDIF(LIBUTIL_LIBRARY)

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
CHECK_INCLUDE_FILES(locale.h HAVE_LOCALE_H)
CHECK_INCLUDE_FILES(libgen.h HAVE_LIBGEN_H)
CHECK_INCLUDE_FILES(search.h HAVE_SEARCH_H)
CHECK_INCLUDE_FILES(pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES(grp.h HAVE_GRP_H)
CHECK_INCLUDE_FILES(glob.h HAVE_GLOB_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)
CHECK_INCLUDE_FILES(sys/sendfile.h HAVE_SYS_SENDFILE_H)

IF(HAVE_SYS_WAIT_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/wait.h)
ENDIF(HAVE_SYS_WAIT_H)
IF(HAVE_TIME_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES time.h)
ENDIF(HAVE_TIME_H)

CHECK_FUNCTION_EXISTS(setproctitle HAVE_SETPROCTITLE)
CHECK_FUNCTION_EXISTS(getpagesize HAVE_GETPAGESIZE)
CHECK_FUNCTION_EXISTS(nanosleep HAVE_NANOSLEEP)
CHECK_FUNCTION_EXISTS(vfork HAVE_VFORK)
CHECK_FUNCTION_EXISTS(wait4 HAVE_WAIT4)
CHECK_FUNCTION_EXISTS(waitpid HAVE_WAITPID)
CHECK_FUNCTION_EXISTS(flock HAVE_FLOCK)
CHECK_FUNCTION_EXISTS(tanhl HAVE_TANHL)
CHECK_FUNCTION_EXISTS(sendfile HAVE_SENDFILE)
CHECK_FUNCTION_EXISTS(mkstemp HAVE_MKSTEMP)
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)

CHECK_SYMBOL_EXISTS(PATH_MAX limits.h HAVE_PATH_MAX)
CHECK_SYMBOL_EXISTS(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
CHECK_SYMBOL_EXISTS(MAP_SHARED sys/mman.h HAVE_MMAP_SHARED)
CHECK_SYMBOL_EXISTS(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
CHECK_SYMBOL_EXISTS(MAP_NOCORE sys/mman.h HAVE_MMAP_NOCORE)
CHECK_SYMBOL_EXISTS(_SC_NPROCESSORS_ONLN unistd.h HAVE_SC_NPROCESSORS_ONLN)
CHECK_SYMBOL_EXISTS(SA_SIGINFO signal.h HAVE_SA_SIGINFO)

IF(HAVE_CLOCK_GETTIME)
	CHECK_SYMBOL_EXISTS(CLOCK_PROCESS_CPUTIME_ID time.h HAVE_CLOCK_PROCESS_CPUTIME_ID)
	CHECK_SYMBOL_EXISTS(CLOCK_VIRTUAL time.h HAVE_CLOCK_VIRTUAL)
ELSE(HAVE_CLOCK_GETTIME)
	CHECK_INCLUDE_FILES(sys/timeb.h HAVE_SYS_TIMEB_H)
ENDIF(HAVE_CLOCK_GETTIME)

CHECK_C_SOURCE_COMPILES ("#include <sys/types.h>
                          int main (int argc, char **argv) {
						  	__asm __volatile(\"pause\");
							return 0;
						  }" HAVE_ASM_PAUSE)

IF(NOT HAVE_COMPATIBLE_QUEUE_H)
	INCLUDE_DIRECTORIES(compat)
ENDIF(NOT HAVE_COMPATIBLE_QUEUE_H)


SET(CONTRIBSRC "")

IF(ENABLE_OPTIMIZATION MATCHES "ON")
	SET(CMAKE_C_OPT_FLAGS "-O3")
ELSE(ENABLE_OPTIMIZATION MATCHES "ON")
	SET(CMAKE_C_OPT_FLAGS "-O0")
ENDIF(ENABLE_OPTIMIZATION MATCHES "ON")

# Process with warn flags
CHECK_C_COMPILER_FLAG(-Wall SUPPORT_WALL)
CHECK_C_COMPILER_FLAG(-Wall SUPPORT_W)
CHECK_C_COMPILER_FLAG(-Wpointer-arith SUPPORT_WPOINTER)
CHECK_C_COMPILER_FLAG(-Wno-unused-parameter SUPPORT_WPARAM)
CHECK_C_COMPILER_FLAG(-Wno-unused-function SUPPORT_WFUNCTION)
CHECK_C_COMPILER_FLAG(-Wno-sign-compare SUPPORT_WSIGNCOMPARE)
CHECK_C_COMPILER_FLAG(-Wunused-variable SUPPORT_WUNUSED_VAR)
CHECK_C_COMPILER_FLAG(-Wno-declaration-after-statement SUPPORT_WDECL)
CHECK_C_COMPILER_FLAG(-Wno-pointer-sign SUPPORT_WPOINTER_SIGN)
CHECK_C_COMPILER_FLAG(-pedantic SUPPORT_PEDANTIC_FLAG)
CHECK_C_COMPILER_FLAG("-std=c99" SUPPORT_STD_FLAG)

SET(CMAKE_C_WARN_FLAGS "")

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
IF(SUPPORT_WSIGNCOMPARE)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-sign-compare ")
ENDIF(SUPPORT_WSIGNCOMPARE)
IF(SUPPORT_WUNUSED_VAR)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wunused-variable")
ENDIF(SUPPORT_WUNUSED_VAR)
IF(SUPPORT_WDECL)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-declaration-after-statement")
ENDIF(SUPPORT_WDECL)
IF(SUPPORT_WPOINTER_SIGN)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -Wno-pointer-sign")
ENDIF(SUPPORT_WPOINTER_SIGN)
IF(SUPPORT_PEDANTIC_FLAG)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -pedantic")
ENDIF(SUPPORT_PEDANTIC_FLAG)
IF(SUPPORT_STD_FLAG)
	SET(CMAKE_C_WARN_FLAGS "${CMAKE_C_WARN_FLAGS} -std=c99")
ENDIF(SUPPORT_STD_FLAG)

SET(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_C_WARN_FLAGS}")


IF(ENABLE_REDIRECTOR MATCHES "ON")
	CONFIGURE_FILE(utils/redirector.pl.in utils/redirector.pl @ONLY)
ENDIF(ENABLE_REDIRECTOR MATCHES "ON")

IF(DEBUG_MODE MATCHES "ON")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
ENDIF(DEBUG_MODE MATCHES "ON")

IF(NOT DESTDIR)
    SET(DESTDIR $ENV{DESTDIR})
ENDIF(NOT DESTDIR)

# Try to detect tip version from hg
UNSET(ID CACHE)
SET(ID "unknown")
FIND_PROGRAM(HG "hg")

IF(HG)
    EXECUTE_PROCESS(COMMAND ${HG} "id" OUTPUT_VARIABLE HG_ID)   
    IF(HG_ID)
        STRING(REGEX MATCH ^[0-9a-z]+ ID "${HG_ID}")
    ENDIF(HG_ID)
ELSE(HG)
# Now check .hg_archival.txt
    FIND_FILE(HG_ARCH ".hg_archival.txt" "${CMAKE_CURRENT_SOURCE_DIR}")   
    IF(HG_ARCH)
        FILE(READ ${HG_ARCH} HG_ID)
        IF(HG_ID)
            STRING(REGEX MATCH "node: [0-9a-z]+" _tmp "${HG_ID}")
            STRING(SUBSTRING "${_tmp}" 6 12 ID)
        ENDIF(HG_ID)
    ENDIF(HG_ARCH)
ENDIF(HG)
 

################################ SOURCES SECTION ###########################

SET(RSPAMDSRC	src/modules.c
				src/binlog.c
                src/bloom.c
				src/buffer.c
				src/cfg_utils.c
				src/cfg_xml.c
				src/controller.c
				src/dns.c
				src/events.c
				src/expressions.c
				src/filter.c
				src/fstring.c
				src/fuzzy.c
				src/fuzzy_storage.c
				src/greylist_storage.c
				src/hash.c
				src/html.c
				src/images.c
				src/lmtp.c
				src/lmtp_proto.c
				src/logger.c
				src/main.c
				src/map.c
				src/memcached.c
				src/mem_pool.c
				src/message.c
				src/protocol.c
				src/radix.c
				src/settings.c
				src/spf.c
				src/smtp.c
				src/smtp_proto.c
				src/smtp_utils.c
				src/statfile.c
				src/statfile_sync.c
				src/symbols_cache.c
				src/trie.c
				src/upstream.c
				src/url.c
				src/util.c
				src/view.c
				src/worker.c)

IF(ENABLE_PERL MATCHES "ON")
	LIST(APPEND RSPAMDSRC src/perl.c)
ENDIF(ENABLE_PERL MATCHES "ON")
ADD_SUBDIRECTORY(src/lua)
ADD_SUBDIRECTORY(lib)

ADD_SUBDIRECTORY(src/json)
# ADD_SUBDIRECTORY(src/evdns)
ADD_SUBDIRECTORY(src/plugins/custom)

SET(TOKENIZERSSRC  src/tokenizers/tokenizers.c
				src/tokenizers/osb.c)

SET(CLASSIFIERSSRC src/classifiers/classifiers.c
                src/classifiers/bayes.c
				src/classifiers/winnow.c)

SET(PLUGINSSRC	src/plugins/surbl.c
				src/plugins/regexp.c
				src/plugins/chartable.c
				src/plugins/fuzzy_check.c
				src/plugins/spf.c)

SET(TESTSRC		test/rspamd_expression_test.c
				test/rspamd_memcached_test.c
				test/rspamd_mem_pool_test.c
				test/rspamd_statfile_test.c
				test/rspamd_fuzzy_test.c
				test/rspamd_test_suite.c
				test/rspamd_url_test.c
				test/rspamd_dns_test.c)

SET(TESTDEPENDS	src/mem_pool.c
				src/hash.c
				src/url.c
				src/trie.c
				src/util.c
				src/radix.c
				src/fuzzy.c
				src/map.c
				src/logger.c
				src/memcached.c
				src/message.c
				src/html.c
				src/expressions.c
				src/statfile.c
				src/events.c
				src/upstream.c
				src/dns.c)

SET(UTILSSRC	utils/url_extracter.c)
SET(EXPRSRC	utils/expression_parser.c)

SET(UTILSDEPENDS src/mem_pool.c
				src/hash.c
				src/url.c
				src/trie.c
				src/fuzzy.c
				src/expressions.c
				src/message.c
				src/html.c
				src/util.c
				src/radix.c)

LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)

############################ TARGETS SECTION ###############################

ADD_CUSTOM_COMMAND(OUTPUT src/modules.c
					COMMAND ../utils/gen-modules.sh ${PLUGINSSRC}
					WORKING_DIRECTORY src)

IF(PERL_EXECUTABLE)
	ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/perl/Makefile 
						DEPENDS ${CMAKE_SOURCE_DIR}/perl/Makefile.PL
						COMMAND ${PERL_EXECUTABLE} ./Makefile.PL DESTDIR=${DESTDIR} PREFIX=${PREFIX} INSTALLMAN3DIR=${MAN_PREFIX}/man3
						WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/perl)
	CONFIGURE_FILE(perl/Makefile.PL.in perl/Makefile.PL)
	ADD_CUSTOM_TARGET(perlmodule
						COMMAND ${CMAKE_MAKE_PROGRAM} DESTDIR=${DESTDIR}
						DEPENDS ${CMAKE_SOURCE_DIR}/perl/Makefile
						WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/perl
						VERBATIM)
	
ENDIF(PERL_EXECUTABLE)

CONFIGURE_FILE(config.h.in src/config.h)
CONFIGURE_FILE(contrib/exim/local_scan.c.in contrib/exim/local_scan_rspamd.c @ONLY)
CONFIGURE_FILE(rspamc.pl.in rspamc.pl @ONLY)
CONFIGURE_FILE(rspamd.xml.sample conf/rspamd.xml.sample @ONLY)

######################### LINK SECTION ###############################
ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${CONTRIBSRC} ${TOKENIZERSSRC} 
					  ${CLASSIFIERSSRC} ${PLUGINSSRC})
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS "-DRSPAMD_MAIN")
SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})

IF(ENABLE_PERL MATCHES "ON")

	SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS ${PERL_CFLAGS}
											LINK_FLAGS ${PERL_LDFLAGS})
	IF(PERL_DYNALOADER)
		TARGET_LINK_LIBRARIES(rspamd dynaloader)
	ENDIF(PERL_DYNALOADER)

ENDIF(ENABLE_PERL MATCHES "ON")
IF(PERL_EXECUTABLE)
	ADD_DEPENDENCIES(rspamd perlmodule)
ENDIF(PERL_EXECUTABLE)

TARGET_LINK_LIBRARIES(rspamd rspamd_lua)
TARGET_LINK_LIBRARIES(rspamd "${LUA_LIBRARY}")

IF(LIBJUDY_LIBRARY)
	TARGET_LINK_LIBRARIES(rspamd Judy)
ENDIF(LIBJUDY_LIBRARY)
# TARGET_LINK_LIBRARIES(rspamd rspamd_evdns)
TARGET_LINK_LIBRARIES(rspamd event)
TARGET_LINK_LIBRARIES(rspamd rspamd_json)
TARGET_LINK_LIBRARIES(rspamd ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd ${GLIB2_LIBRARIES})
IF(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(rspamd ${GMIME2_LIBRARIES})
ELSE(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(rspamd ${GMIME24_LIBRARIES})
ENDIF(GMIME2_FOUND)
IF(ENABLE_STATIC MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd ${PCRE_LIBRARIES})
ENDIF(ENABLE_STATIC MATCHES "ON")

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd profiler)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

ADD_EXECUTABLE(test/rspamd-test ${TESTDEPENDS} ${CONTRIBSRC} ${TESTSRC})
SET_TARGET_PROPERTIES(test/rspamd-test PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(test/rspamd-test PROPERTIES COMPILE_FLAGS "-DRSPAMD_TEST")
TARGET_LINK_LIBRARIES(test/rspamd-test event)
TARGET_LINK_LIBRARIES(test/rspamd-test ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(test/rspamd-test ${CMAKE_REQUIRED_LIBRARIES})
IF(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(test/rspamd-test ${GMIME2_LIBRARIES})
ELSE(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(test/rspamd-test ${GMIME24_LIBRARIES})
ENDIF(GMIME2_FOUND)
IF(ENABLE_STATIC MATCHES "ON")
	TARGET_LINK_LIBRARIES(test/rspamd-test ${PCRE_LIBRARIES})
ENDIF(ENABLE_STATIC MATCHES "ON")

ADD_EXECUTABLE(utils/url-extracter ${UTILSDEPENDS} ${CONTRIBSRC} ${UTILSSRC})
SET_TARGET_PROPERTIES(utils/url-extracter PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(utils/url-extracter ${CMAKE_REQUIRED_LIBRARIES})
TARGET_LINK_LIBRARIES(utils/url-extracter ${GLIB2_LIBRARIES})
IF(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(utils/url-extracter ${GMIME2_LIBRARIES})
ELSE(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(utils/url-extracter ${GMIME24_LIBRARIES})
ENDIF(GMIME2_FOUND)
IF(ENABLE_STATIC MATCHES "ON")
	TARGET_LINK_LIBRARIES(utils/url-extracter ${PCRE_LIBRARIES})
ENDIF(ENABLE_STATIC MATCHES "ON")

ADD_EXECUTABLE(utils/expression-parser ${UTILSDEPENDS} ${CONTRIBSRC} ${EXPRSRC})
SET_TARGET_PROPERTIES(utils/expression-parser PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(utils/expression-parser ${CMAKE_REQUIRED_LIBRARIES})
IF(LIBUTIL_LIBRARY)
	TARGET_LINK_LIBRARIES(utils/expression-parser util)
ENDIF(LIBUTIL_LIBRARY)
TARGET_LINK_LIBRARIES(utils/expression-parser ${GLIB2_LIBRARIES})
IF(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(utils/expression-parser ${GMIME2_LIBRARIES})
ELSE(GMIME2_FOUND)
	TARGET_LINK_LIBRARIES(utils/expression-parser ${GMIME24_LIBRARIES})
ENDIF(GMIME2_FOUND)
IF(ENABLE_STATIC MATCHES "ON")
	TARGET_LINK_LIBRARIES(utils/expression-parser ${PCRE_LIBRARIES})
ENDIF(ENABLE_STATIC MATCHES "ON")

##################### INSTALLATION ##########################################

# Binaries
INSTALL(PROGRAMS rspamd-${RSPAMD_VERSION} DESTINATION bin RENAME rspamd)
IF(PERL_EXECUTABLE)
	INSTALL(PROGRAMS rspamc.pl DESTINATION bin RENAME rspamc)
ENDIF(PERL_EXECUTABLE)


# Configs
IF(NOT EXISTS ${DESTDIR}/${ETC_PREFIX}/rspamd)
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/${ETC_PREFIX}/rspamd)")
ENDIF(NOT EXISTS ${DESTDIR}/${ETC_PREFIX}/rspamd)

INSTALL(FILES conf/2tld.inc RENAME 2tld.inc.orig DESTINATION etc/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/2tld.inc)
	INSTALL(FILES conf/2tld.inc DESTINATION etc/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/2tld.inc)

INSTALL(FILES conf/rspamd.xml.sample DESTINATION etc/)

# Lua plugins
IF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/lua)
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/lua)")
ENDIF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/lua)

FILE(GLOB LUA_PLUGINS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua" "${CMAKE_CURRENT_SOURCE_DIR}/src/plugins/lua/*.lua" )
FOREACH(LUA_PLUGIN ${LUA_PLUGINS})
	GET_FILENAME_COMPONENT(_rp ${LUA_PLUGIN} PATH)
	IF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/lua/${_rp})
		INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/lua/${_rp})")
	ENDIF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/lua/${_rp})
	IF(NOT EXISTS ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/${_rp}/${LUA_PLUGIN})
		INSTALL(FILES "src/plugins/lua/${LUA_PLUGIN}" DESTINATION etc/rspamd/plugins/lua/${_rp})
	ENDIF(NOT EXISTS ${DESTDIR}/${ETC_PREFIX}/rspamd/plugins/${_rp}/${LUA_PLUGIN})
ENDFOREACH(LUA_PLUGIN)

# Lua config
IF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/lua)
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/${ETC_PREFIX}/rspamd/lua)")
ENDIF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/lua)
FILE(GLOB_RECURSE LUA_CONFIGS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/conf/lua" "${CMAKE_CURRENT_SOURCE_DIR}/conf/lua/*.lua")
FOREACH(LUA_CONF ${LUA_CONFIGS})
	GET_FILENAME_COMPONENT(_rp ${LUA_CONF} PATH)
	IF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/lua/${_rp})
		INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/${ETC_PREFIX}/rspamd/lua/${_rp})")
	ENDIF(NOT IS_DIRECTORY ${DESTDIR}/${ETC_PREFIX}/rspamd/lua/${_rp})
	IF(NOT EXISTS ${DESTDIR}/${ETC_PREFIX}/rspamd/lua/${_rp}/${LUA_CONF})
		INSTALL(FILES "conf/lua/${LUA_CONF}" DESTINATION etc/rspamd/lua/${_rp})
	ENDIF(NOT EXISTS ${DESTDIR}/${ETC_PREFIX}/rspamd/lua/${_rp}/${LUA_CONF})
ENDFOREACH(LUA_CONF)

# Perl lib
IF(PERL_EXECUTABLE)
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND make install WORKING_DIRECTORY perl)")
ENDIF(PERL_EXECUTABLE)

# Redirector
IF(ENABLE_REDIRECTOR MATCHES "ON" AND PERL_EXECUTABLE)
	INSTALL(PROGRAMS utils/redirector.pl DESTINATION bin RENAME rspamd-redirector)
ENDIF(ENABLE_REDIRECTOR MATCHES "ON" AND PERL_EXECUTABLE)

# Start scripts
IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND NOT BUILD_PORT)
	INSTALL(PROGRAMS freebsd/rspamd.sh DESTINATION etc/rc.d)
	IF(ENABLE_REDIRECTOR MATCHES "ON")
		INSTALL(PROGRAMS freebsd/redirector.sh DESTINATION etc/rc.d)
	ENDIF(ENABLE_REDIRECTOR MATCHES "ON")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/var/run/rspamd/)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND chown ${RSPAMD_USER}:${RSPAMD_GROUP} ${DESTDIR}/var/run/rspamd/)")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND NOT BUILD_PORT)
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	INSTALL(PROGRAMS linux/rspamd DESTINATION etc/init.d)
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${DESTDIR}/var/run/rspamd/)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND chown ${RSPAMD_USER}:${RSPAMD_GROUP} ${DESTDIR}/var/run/rspamd/)")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

# CPack section
SET(CPACK_DEBIAN_PACKAGE_DEPENDS libevent1 libgmime-2.0-2a)
SET(CPACK_PACKAGE_CONTACT "vsevolod@highsecure.ru")
SET(CPACK_PACKAGE_NAME rspamd)
SET(CPACK_SOURCE_IGNORE_FILES "\\\\.swp$" "/\\\\.hg/")
SET(CPACK_PACKAGE_VERSION_MAJOR ${RSPAMD_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${RSPAMD_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${RSPAMD_VERSION_PATCH})
INCLUDE(CPack)

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    INCLUDE("linux/cmake/DpkgDeb.cmake")
    INCLUDE("linux/cmake/UseRPMTools.cmake")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    INCLUDE("freebsd/cmake/PkgCreate.cmake")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

SET(RPMNAME "rspamd")
SET(PACKAGE_NAME "rspamd")
SET(PACKAGE_RELEASE "1")
SET(PACKAGE_SECTION "mail")
SET(PACKAGE_PRIORITY "optional")
SET(PACKAGE_HOMEPAGE "http://bitbucket.org/vstakhov/rspamd")
SET(PACKAGE_MAINTAINER_NAME "vstakhov")
SET(PACKAGE_MAINTAINER_EMAIL "vsevolod@highsecure.ru")
SET(PACKAGE_DESCRIPTION_SUMMARY "rspamd - fast and modular antispam system written in C")
SET(PACKAGE_DESCRIPTION "Fast and modular antispam system written in C")
IF(GMIME24)
    SET(PACKAGE_DEPENDS "libc6, libevent-1.4-2, libgmime-2.4-2, liblua5.1-0, libxml-parser-perl, libterm-readkey-perl, libglib2.0-0")
ELSE(GMIME24)
    SET(PACKAGE_DEPENDS "libc6, libevent-1.4-2, libgmime-2.0-2, libxml-parser-perl, libterm-readkey-perl, libglib2.0-0")
ENDIF(GMIME24)

SET(PACKAGE_VERSION "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}_${ID}")


IF(RPMTools_FOUND)
    FILE(WRITE linux/rspamd.spec
"# -*- rpm-spec -*-
Summary:        ${RPMNAME}
Name:           ${RPMNAME}
Version:        ${PACKAGE_VERSION}
Release:        ${PACKAGE_RELEASE}
License:        BSD
Group:          Mail
Source:         ${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
#BuildRequires:	cmake, gmime-devel, glib2-devel, perl, libevent-devel, lua-devel

%define prefix /usr
%define rpmprefix $RPM_BUILD_ROOT%{prefix}
%define srcdirname %{name}-%{version}-Source

%description
${RPMNAME} : Fast and modular antispam system written in C

%prep
%setup -q -n %{srcdirname}

%build
cd ..
cd %{srcdirname}
rm -f CMakeCache.txt
cmake -DCMAKE_INSTALL_PREFIX=%{prefix} -DDESTDIR=%{rpmprefix} .
make clean
make DESTDIR=%{rpmprefix} CMAKE_INSTALL_PREFIX=%{prefix}

  
%install 
make DESTDIR=%{rpmprefix} CMAKE_INSTALL_PREFIX=%{prefix} install
cd ..

%clean
rm -rf %{srcdirname}

%files
%defattr(-,root,root,-)
%dir %{prefix}
%{prefix}/*

%changelog
* Wed Sep 15 2010 vstakhov <vsevolod@highsecure.ru>
  Release 0.3.2
")
    RPMTools_ADD_RPM_TARGETS("rspamd" "linux/rspamd.spec")
ENDIF(RPMTools_FOUND)

IF(DPKG_FOUND STREQUAL "YES")
    ADD_DEBIAN_PACKAGE("rspamd")    
ENDIF(DPKG_FOUND STREQUAL "YES")
IF(PKGCREATE_FOUND STREQUAL "YES")
    ADD_FREEBSD_PACKAGE("rspamd" "freebsd/rspamd.plist")    
ENDIF(PKGCREATE_FOUND STREQUAL "YES")