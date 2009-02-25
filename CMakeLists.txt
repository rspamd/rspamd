#
# Rspamd - rambler antispam system
#
# Cmake configuration file
#
PROJECT(rspamd C)

SET(RSPAMD_VERSION_MAJOR 0)
SET(RSPAMD_VERSION_MINOR 1)
SET(RSPAMD_VERSION_PATCH 0)

SET(RSPAMD_VERSION         "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}")
SET(RSPAMD_MASTER_SITE_URL "http://cebka.pp.ru/hg/rspamd")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)

OPTION(DEBUG_MODE          "Enable debug output [default: OFF]"                 OFF)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: ON]"                  ON)
OPTION(SKIP_RELINK_RPATH   "Skip relinking and full RPATH for the install tree" OFF)

# Build optimized code for following CPU (default i386)
#SET(CPU_TUNE               "i686")

# ################################################################################
# Check Includes
#
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckLibraryExists)
INCLUDE(FindPkgConfig)
INCLUDE(FindPerl)

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

# Lex and yacc
FIND_PROGRAM(LEX_EXECUTABLE lex)
FIND_PROGRAM(YACC_EXECUTABLE yacc)

IF(NOT LEX_EXECUTABLE OR NOT YACC_EXECUTABLE)
	MESSAGE(FATAL_ERROR "Error: yacc and lex are required for build")
ENDIF(NOT LEX_EXECUTABLE OR NOT YACC_EXECUTABLE)

pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.10)
pkg_check_modules(GMIME2 REQUIRED gmime-2.0)

IF(NOT GLIB2_FOUND OR NOT GMIME2_FOUND)
	MESSAGE(FATAL_ERROR "Error: gmime2 and glib2 are required for rspamd")
ENDIF(NOT GLIB2_FOUND OR NOT GMIME2_FOUND)

# Make from ; separated list normal space separated list
# Glib2
FOREACH(arg ${GLIB2_CFLAGS})
	SET(GLIB_CFLAGS "${GLIB_CFLAGS} ${arg}")
ENDFOREACH(arg ${GLIB2_CFLAGS})
FOREACH(arg ${GLIB2_LDFLAGS})
	SET(GLIB_LDFLAGS "${GLIB_LDFLAGS} ${arg}")
ENDFOREACH(arg ${GLIB2_LDFLAGS})
# Gmime2
FOREACH(arg ${GMIME2_CFLAGS})
	SET(GMIME_CFLAGS "${GMIME_CFLAGS} ${arg}")
ENDFOREACH(arg ${GMIME2_CFLAGS})
FOREACH(arg ${GMIME2_LDFLAGS})
	SET(GMIME_LDFLAGS "${GMIME_LDFLAGS} ${arg}")
ENDFOREACH(arg ${GMIME2_LDFLAGS})


INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${GMIME2_INCLUDE_DIRS})
LINK_DIRECTORIES(${GLIB2_LIBRARY_DIRS})
LINK_DIRECTORIES(${GMIME2_LIBRARY_DIRS})

SET(CMAKE_REQUIRED_LIBRARIES m)
SET(CMAKE_REQUIRED_INCLUDES sys/mman.h stdlib.h stdio.h unistd.h time.h sched.h)

FIND_LIBRARY(LIBEVENT_LIBRARY NAMES event PATHS /lib
                                           		/opt/lib
                                            	/usr/lib
                                            	/usr/local/lib
                 DOC "Path where the libevent library can be found")
IF(NOT LIBEVENT_LIBRARY)
	MESSAGE(FATAL_ERROR "libevent is required for building rspamd")
ENDIF(NOT LIBEVENT_LIBRARY)

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
CHECK_INCLUDE_FILES(netinet/in.h  HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(arpa/inet.h  HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(netdb.h  HAVE_NETDB_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(libgen.h HAVE_LIBGEN_H)

IF(HAVE_SYS_WAIT_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/wait.h)
ENDIF(HAVE_SYS_WAIT_H)

CHECK_FUNCTION_EXISTS(setproctitle HAVE_SETPROCTITLE)
CHECK_FUNCTION_EXISTS(getpagesize HAVE_GETPAGESIZE)
CHECK_FUNCTION_EXISTS(nanosleep HAVE_NANOSLEEP)
CHECK_FUNCTION_EXISTS(vfork HAVE_VFORK)
CHECK_FUNCTION_EXISTS(wait4 HAVE_WAIT4)
CHECK_FUNCTION_EXISTS(waitpid HAVE_WAITPID)

CHECK_SYMBOL_EXISTS(PATH_MAX limits.h HAVE_PATH_MAX)
CHECK_SYMBOL_EXISTS(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
CHECK_SYMBOL_EXISTS(MAP_SHARED sys/mman.h HAVE_MMAP_SHARED)
CHECK_SYMBOL_EXISTS(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
CHECK_SYMBOL_EXISTS(_SC_NPROCESSORS_ONLN unistd.h HAVE_SC_NPROCESSORS_ONLN)
CHECK_SYMBOL_EXISTS(SLIST_FOREACH_SAFE sys/queue.h HAVE_COMPATIBLE_QUEUE_H)

IF(NOT HAVE_COMPATIBLE_QUEUE_H)
	INCLUDE_DIRECTORIES(compat)
ENDIF(NOT HAVE_COMPATIBLE_QUEUE_H)


SET(CONTRIBSRC "")
FIND_PATH(MD5_INCLUDE md5.h PATHS 	/opt/include
									/usr/include
									/usr/local/include
									DOC "Path where the openssl header files can be found")
IF (MD5_INCLUDE)
	INCLUDE_DIRECTORIES(${MD5_INCLUDE})

	FIND_LIBRARY(MD5_LIBRARY NAMES md PATHS /lib
                                           	/opt/lib
                                            /usr/lib
                                            /usr/local/lib
                 DOC "Path where the md5 libraries can be found")
    IF (MD5_LIBRARY)
    	SET(PROJECT_LIBS "${PROJECT_LIBS} md")
		MESSAGE(STATUS "INFO: MD5 (libmd) hash function support enabled")
	ELSE (MD5_LIBRARY)
		MESSAGE(SEND_ERROR "ERROR: Cannot find libmd.so, aborting")
	ENDIF (MD5_LIBRARY)
ELSE (MD5_INCLUDE)
	SET(CONTRIBSRC compat/md5.c)
	MESSAGE(STATUS "WARNING: Using internal MD5 support")
ENDIF (MD5_INCLUDE)

IF("${CMAKE_COMPILER_IS_GNUC}" MATCHES "1")
	SET(CMAKE_C_WARN_FLAGS " -Wall -W -Wpointer-arith -Wno-unused-parameter -Wno-unused-function -Wunused-variable -Wno-sign-compare -Wunused-value")

	IF(DEBUG_MODE MATCHES "ON")
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb ")
	ENDIF(DEBUG_MODE MATCHES "ON")
ENDIF("${CMAKE_COMPILER_IS_GNUC}" MATCHES "1")

SET(RSPAMDSRC	src/modules.c
				src/hash.c
				src/worker.c
				src/util.c
				src/url.c
				src/upstream.c
				src/statfile.c
				src/protocol.c
				src/perl.c
				src/message.c
				src/mem_pool.c
				src/memcached.c
				src/main.c
				src/fstring.c
				src/filter.c
				src/controller.c
				src/cfg_utils.c
				src/buffer.c
				src/lmtp.c
				src/lmtp_proto.c)

SET(TOKENIZERSSRC  src/tokenizers/tokenizers.c
				src/tokenizers/osb.c)

SET(CLASSIFIERSSRC src/classifiers/classifiers.c
				src/classifiers/winnow.c)

SET(PLUGINSSRC	src/plugins/surbl.c
				src/plugins/regexp.c)

SET(TESTSRC		test/rspamd_expression_test.c
				test/rspamd_memcached_test.c
				test/rspamd_mem_pool_test.c
				test/rspamd_statfile_test.c
				test/rspamd_test_suite.c
				test/rspamd_url_test.c)

SET(TESTDEPENDS	src/mem_pool.c
				src/hash.c
				src/url.c
				src/util.c
				src/memcached.c
				src/statfile.c)

SET(UTILSSRC	utils/url_extracter.c)

SET(UTILSDEPENDS src/mem_pool.c
				src/hash.c
				src/url.c
				src/util.c
				src/memcached.c)

LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)

SET(YACC_SRC	src/cfg_file.y)
SET(LEX_SRC		src/cfg_file.l)

STRING(REPLACE "_file.y" "_yacc.c" YACC_OUTPUT ${YACC_SRC})
STRING(REPLACE "_file.l" "_lex.c" LEX_OUTPUT ${LEX_SRC})

ADD_CUSTOM_COMMAND(OUTPUT ${LEX_OUTPUT}
					COMMAND ${LEX_EXECUTABLE} -o${LEX_OUTPUT} ${LEX_SRC})
ADD_CUSTOM_COMMAND(OUTPUT ${YACC_OUTPUT}
					COMMAND ${YACC_EXECUTABLE} -d -o ${YACC_OUTPUT} ${YACC_SRC})
ADD_CUSTOM_COMMAND(OUTPUT src/modules.c
					COMMAND ../utils/gen-modules.sh ${PLUGINSSRC}
					WORKING_DIRECTORY src)

ADD_CUSTOM_TARGET(perlxs ALL
					COMMAND ${PERL_EXECUTABLE} ./Makefile.PL
					COMMAND make
					WORKING_DIRECTORY perl
					VERBATIM)

CONFIGURE_FILE(config.h.in src/config.h)
CONFIGURE_FILE(perl/Makefile.PL.in perl/Makefile.PL)

ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${CONTRIBSRC} ${TOKENIZERSSRC} 
					  ${CLASSIFIERSSRC} ${PLUGINSSRC} ${YACC_OUTPUT} 
					  ${LEX_OUTPUT})
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})
SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS ${PERL_CFLAGS}
										LINK_FLAGS ${PERL_LDFLAGS})
TARGET_LINK_LIBRARIES(rspamd ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd event)
IF(PERL_DYNALOADER)
	TARGET_LINK_LIBRARIES(rspamd dynaloader)
ENDIF(PERL_DYNALOADER)
TARGET_LINK_LIBRARIES(rspamd ${GMIME2_LIBRARIES})

ADD_EXECUTABLE(test/rspamd-test ${TESTDEPENDS} ${CONTRIBSRC} ${TESTSRC})
SET_TARGET_PROPERTIES(test/rspamd-test PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(test/rspamd-test PROPERTIES COMPILE_FLAGS ${PERL_CFLAGS}
										LINK_FLAGS ${PERL_LDFLAGS})
TARGET_LINK_LIBRARIES(test/rspamd-test ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(test/rspamd-test event)
TARGET_LINK_LIBRARIES(test/rspamd-test ${GMIME2_LIBRARIES})

ADD_EXECUTABLE(utils/url-extracter ${UTILSDEPENDS} ${CONTRIBSRC} ${UTILSSRC})
SET_TARGET_PROPERTIES(utils/url-extracter PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(utils/url-extracter PROPERTIES COMPILE_FLAGS ${PERL_CFLAGS}
										LINK_FLAGS ${PERL_LDFLAGS})
TARGET_LINK_LIBRARIES(utils/url-extracter ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(utils/url-extracter event)
TARGET_LINK_LIBRARIES(utils/url-extracter ${GMIME2_LIBRARIES})
