#
# Rspamd - rambler antispam system
#
# Cmake configuration file
#
PROJECT(rspamd C)

SET(RSPAMD_VERSION_MAJOR 0)
SET(RSPAMD_VERSION_MINOR 2)
SET(RSPAMD_VERSION_PATCH 7)

SET(RSPAMD_VERSION         "${RSPAMD_VERSION_MAJOR}.${RSPAMD_VERSION_MINOR}.${RSPAMD_VERSION_PATCH}")
SET(RSPAMD_MASTER_SITE_URL "http://cebka.pp.ru/hg/rspamd")
SET(RSPAMD_USER "nobody")
SET(RSPAMD_GROUP "nobody")

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)

OPTION(DEBUG_MODE          "Enable debug output [default: ON]"                  ON)
OPTION(ENABLE_OPTIMIZATION "Enable optimization [default: OFF]"                 OFF)
OPTION(ENABLE_PERL         "Enable perl support [default: OFF]"                 OFF)
OPTION(ENABLE_LUA          "Enable lua support [default: ON]"                  ON)
OPTION(SKIP_RELINK_RPATH   "Skip relinking and full RPATH for the install tree" OFF)
OPTION(ENABLE_REDIRECTOR   "Enable redirector install [default: OFF]"           OFF)
OPTION(ENABLE_PROFILING    "Enable profiling [default: OFF]"                    OFF)
OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]"             OFF)

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

IF(ENABLE_PERL MATCHES "ON")

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
ELSE(ENABLE_PERL MATCHES "ON")
	SET(WITHOUT_PERL 1)
ENDIF(ENABLE_PERL MATCHES "ON")

IF(ENABLE_LUA MATCHES "ON")
	IF (ENABLE_PERL MATCHES "ON")
		MESSAGE(FATAL_ERROR "Error: Perl and Lua support cannot be turned on together")
	ENDIF (ENABLE_PERL MATCHES "ON")

	INCLUDE(FindLua51)
	IF(NOT LUA_FOUND)
		# Automatic check failed, check passed variable
		IF(LUA_INCLUDE_DIR)
			INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
			SET(WITH_LUA 1)
		ELSE(LUA_INCLUDE_DIR)
			SET(ENABLE_LUA "OFF")
			MESSAGE(STATUS "Lua not found, lua support disabled")
		ENDIF(LUA_INCLUDE_DIR)
	ELSE(NOT LUA_FOUND)
		SET(WITH_LUA 1)
		INCLUDE_DIRECTORIES("${LUA_INCLUDE_DIR}")
	ENDIF(NOT LUA_FOUND)
ENDIF(ENABLE_LUA MATCHES "ON")

# Lex and yacc
FIND_PROGRAM(LEX_EXECUTABLE lex)
FIND_PROGRAM(YACC_EXECUTABLE yacc)

IF(NOT LEX_EXECUTABLE OR NOT YACC_EXECUTABLE)
	MESSAGE(FATAL_ERROR "Error: yacc and lex are required for build")
ENDIF(NOT LEX_EXECUTABLE OR NOT YACC_EXECUTABLE)

pkg_check_modules(GLIB2 REQUIRED glib-2.0>=2.16)
pkg_check_modules(GMIME2 gmime-2.0)

# Try to link with gmime24
IF(NOT GMIME2_FOUND)
	 pkg_check_modules(GMIME2 REQUIRED gmime-2.4)
	 SET(GMIME24 "yes")
ENDIF(NOT GMIME2_FOUND)

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

IF(ENABLE_PROFILING MATCHES "ON")
	SET(WITH_PROFILER 1)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
	SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
ENDIF(ENABLE_PROFILING MATCHES "ON")

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


FIND_PATH(LIBEVENT_INCLUDE event.h PATHS 	/opt/include
										/usr/include
										/usr/local/include
										DOC "Path where the libevent header files can be found")

GET_FILENAME_COMPONENT(LIBEVENT_PATH "${LIBEVENT_LIBRARY}" PATH)
INCLUDE_DIRECTORIES("${LIBEVENT_INCLUDE}")
LINK_DIRECTORIES("${LIBEVENT_PATH}")

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
CHECK_INCLUDE_FILES(sys/resource.h  HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILES(netinet/in.h  HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(arpa/inet.h  HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(netdb.h  HAVE_NETDB_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(locale.h HAVE_LOCALE_H)
CHECK_INCLUDE_FILES(libgen.h HAVE_LIBGEN_H)
CHECK_INCLUDE_FILES(pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES(grp.h HAVE_GRP_H)
CHECK_INCLUDE_FILES(glob.h HAVE_GLOB_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)

IF(HAVE_SYS_WAIT_H)
	LIST(APPEND CMAKE_REQUIRED_INCLUDES sys/wait.h)
ENDIF(HAVE_SYS_WAIT_H)

CHECK_FUNCTION_EXISTS(setproctitle HAVE_SETPROCTITLE)
CHECK_FUNCTION_EXISTS(getpagesize HAVE_GETPAGESIZE)
CHECK_FUNCTION_EXISTS(nanosleep HAVE_NANOSLEEP)
CHECK_FUNCTION_EXISTS(vfork HAVE_VFORK)
CHECK_FUNCTION_EXISTS(wait4 HAVE_WAIT4)
CHECK_FUNCTION_EXISTS(waitpid HAVE_WAITPID)
CHECK_FUNCTION_EXISTS(flock HAVE_FLOCK)

CHECK_SYMBOL_EXISTS(PATH_MAX limits.h HAVE_PATH_MAX)
CHECK_SYMBOL_EXISTS(MAXPATHLEN sys/param.h HAVE_MAXPATHLEN)
CHECK_SYMBOL_EXISTS(MAP_SHARED sys/mman.h HAVE_MMAP_SHARED)
CHECK_SYMBOL_EXISTS(MAP_ANON sys/mman.h HAVE_MMAP_ANON)
CHECK_SYMBOL_EXISTS(_SC_NPROCESSORS_ONLN unistd.h HAVE_SC_NPROCESSORS_ONLN)
CHECK_SYMBOL_EXISTS(CLOCK_PROCESS_CPUTIME_ID time.h HAVE_CLOCK_PROCESS_CPUTIME_ID)
CHECK_SYMBOL_EXISTS(SA_SIGINFO signal.h HAVE_SA_SIGINFO)
CHECK_SYMBOL_EXISTS(CLOCK_VIRTUAL time.h HAVE_CLOCK_VIRTUAL)

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
CHECK_C_COMPILER_FLAG(-Wpointer-arith SUPPORT_WPOINTER)
CHECK_C_COMPILER_FLAG(-Wno-unused-parameter SUPPORT_WPARAM)
CHECK_C_COMPILER_FLAG(-Wno-unused-function SUPPORT_WFUNCTION)
CHECK_C_COMPILER_FLAG(-Wno-sign-compare SUPPORT_WSIGNCOMPARE)
CHECK_C_COMPILER_FLAG(-Wunused-variable SUPPORT_WUNUSED_VAR)
CHECK_C_COMPILER_FLAG(-Wno-declaration-after-statement SUPPORT_WDECL)
CHECK_C_COMPILER_FLAG(-Wno-pointer-sign SUPPORT_WPOINTER_SIGN)

SET(CMAKE_C_WARN_FLAGS "-W")

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

SET(CMAKE_C_FLAGS "${CMAKE_C_OPT_FLAGS} ${CMAKE_C_FLAGS} ${CMAKE_C_WARN_FLAGS}")

# Platform specific routines
IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_BSD_SOURCE -DFREEBSD")
	CONFIGURE_FILE(freebsd/rspamd.sh.in freebsd/rspamd.sh @ONLY)

	IF(ENABLE_REDIRECTOR MATCHES "ON")
		CONFIGURE_FILE(freebsd/redirector.sh.in freebsd/redirector.sh @ONLY)
	ENDIF(ENABLE_REDIRECTOR MATCHES "ON")
	IF(NOT ETC_PREFIX)
		SET(ETC_PREFIX /usr/local/etc)
		SET(PREFIX /usr/local)
	ENDIF(NOT ETC_PREFIX)

ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -DLINUX")
	IF(NOT ETC_PREFIX)
		SET(ETC_PREFIX /etc)
		SET(PREFIX /usr)
	ENDIF(NOT ETC_PREFIX)
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")

IF(ENABLE_REDIRECTOR MATCHES "ON")
	CONFIGURE_FILE(utils/redirector.pl.in utils/redirector.pl @ONLY)
ENDIF(ENABLE_REDIRECTOR MATCHES "ON")

IF(DEBUG_MODE MATCHES "ON")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
ENDIF(DEBUG_MODE MATCHES "ON")

################################ SOURCES SECTION ###########################

SET(RSPAMDSRC	src/modules.c
				src/hash.c
				src/worker.c
				src/util.c
				src/url.c
				src/upstream.c
				src/statfile.c
				src/protocol.c
				src/message.c
				src/fuzzy.c
				src/expressions.c
				src/mem_pool.c
				src/memcached.c
				src/main.c
				src/fstring.c
				src/filter.c
				src/controller.c
				src/cfg_utils.c
				src/buffer.c
				src/events.c
				src/html.c
				src/lmtp.c
				src/spf.c
				src/lmtp_proto.c
				src/radix.c
				src/view.c
				src/map.c
                src/bloom.c
				src/settings.c
				src/symbols_cache.c
				src/fuzzy_storage.c)

IF(ENABLE_PERL MATCHES "ON")
	LIST(APPEND RSPAMDSRC src/perl.c)
ENDIF(ENABLE_PERL MATCHES "ON")
IF(ENABLE_LUA MATCHES "ON")
	ADD_SUBDIRECTORY(src/lua)
ENDIF(ENABLE_LUA MATCHES "ON")

ADD_SUBDIRECTORY(src/json)
ADD_SUBDIRECTORY(src/evdns)

SET(TOKENIZERSSRC  src/tokenizers/tokenizers.c
				src/tokenizers/osb.c)

SET(CLASSIFIERSSRC src/classifiers/classifiers.c
				src/classifiers/winnow.c)

SET(PLUGINSSRC	src/plugins/surbl.c
				src/plugins/regexp.c
				src/plugins/chartable.c
				src/plugins/emails.c
				src/plugins/fuzzy_check.c)

SET(TESTSRC		test/rspamd_expression_test.c
				test/rspamd_memcached_test.c
				test/rspamd_mem_pool_test.c
				test/rspamd_statfile_test.c
				test/rspamd_fuzzy_test.c
				test/rspamd_test_suite.c
				test/rspamd_url_test.c)

SET(TESTDEPENDS	src/mem_pool.c
				src/hash.c
				src/url.c
				src/util.c
				src/radix.c
				src/fuzzy.c
				src/memcached.c
				src/message.c
				src/html.c
				src/expressions.c
				src/statfile.c)

SET(UTILSSRC	utils/url_extracter.c)
SET(EXPRSRC	utils/expression_parser.c)

SET(UTILSDEPENDS src/mem_pool.c
				src/hash.c
				src/url.c
				src/fuzzy.c
				src/expressions.c
				src/message.c
				src/html.c
				src/util.c
				src/radix.c)

LIST(LENGTH PLUGINSSRC RSPAMD_MODULES_NUM)

SET(YACC_SRC	src/cfg_file.y)
SET(LEX_SRC		src/cfg_file.l)

STRING(REPLACE "_file.y" "_yacc.c" YACC_OUTPUT ${YACC_SRC})
STRING(REPLACE "_file.l" "_lex.c" LEX_OUTPUT ${LEX_SRC})

############################ TARGETS SECTION ###############################

ADD_CUSTOM_COMMAND(OUTPUT ${LEX_OUTPUT}
					COMMAND ${LEX_EXECUTABLE} -o${LEX_OUTPUT} ${LEX_SRC})
ADD_CUSTOM_COMMAND(OUTPUT ${YACC_OUTPUT}
					COMMAND ${YACC_EXECUTABLE} -d -o ${YACC_OUTPUT} ${YACC_SRC})
ADD_CUSTOM_COMMAND(OUTPUT src/modules.c
					COMMAND ../utils/gen-modules.sh ${PLUGINSSRC}
					WORKING_DIRECTORY src)

IF(ENABLE_PERL MATCHES "ON")
	ADD_CUSTOM_COMMAND(OUTPUT perl/Makefile 
						COMMAND ${PERL_EXECUTABLE} ./Makefile.PL
						WORKING_DIRECTORY perl)
	ADD_CUSTOM_TARGET(perlxs
						COMMAND make
						DEPENDS perl/Makefile
						WORKING_DIRECTORY perl
						VERBATIM)
	CONFIGURE_FILE(perl/Makefile.PL.in perl/Makefile.PL)
ENDIF(ENABLE_PERL MATCHES "ON")

CONFIGURE_FILE(config.h.in src/config.h)
CONFIGURE_FILE(rspamc.pl.in rspamc.pl @ONLY)
CONFIGURE_FILE(rspamd.conf.sample conf/rspamd.conf.sample @ONLY)

######################### LINK SECTION ###############################
ADD_EXECUTABLE(rspamd ${RSPAMDSRC} ${CONTRIBSRC} ${TOKENIZERSSRC} 
					  ${CLASSIFIERSSRC} ${PLUGINSSRC} ${YACC_OUTPUT} 
					  ${LEX_OUTPUT})
SET_TARGET_PROPERTIES(rspamd PROPERTIES LINKER_LANGUAGE C)
SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS "-DRSPAMD_MAIN")
SET_TARGET_PROPERTIES(rspamd PROPERTIES VERSION ${RSPAMD_VERSION})

IF(ENABLE_PERL MATCHES "ON")

	SET_TARGET_PROPERTIES(rspamd PROPERTIES COMPILE_FLAGS ${PERL_CFLAGS}
											LINK_FLAGS ${PERL_LDFLAGS})
	IF(PERL_DYNALOADER)
		TARGET_LINK_LIBRARIES(rspamd dynaloader)
	ENDIF(PERL_DYNALOADER)
	ADD_DEPENDENCIES(rspamd perlxs ${LEX_OUTPUT} ${YACC_OUTPUT})

ENDIF(ENABLE_PERL MATCHES "ON")

IF(ENABLE_LUA MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd "${LUA_LIBRARY}")
	TARGET_LINK_LIBRARIES(rspamd rspamd_lua)
ENDIF(ENABLE_LUA MATCHES "ON")

TARGET_LINK_LIBRARIES(rspamd m)
IF(LIBUTIL_LIBRARY)
	TARGET_LINK_LIBRARIES(rspamd util)
ENDIF(LIBUTIL_LIBRARY)
TARGET_LINK_LIBRARIES(rspamd rspamd_evdns)
TARGET_LINK_LIBRARIES(rspamd event)
TARGET_LINK_LIBRARIES(rspamd rspamd_json)
TARGET_LINK_LIBRARIES(rspamd ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(rspamd ${GMIME2_LIBRARIES})

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
	TARGET_LINK_LIBRARIES(rspamd profiler)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

ADD_EXECUTABLE(test/rspamd-test ${TESTDEPENDS} ${CONTRIBSRC} ${TESTSRC})
SET_TARGET_PROPERTIES(test/rspamd-test PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(test/rspamd-test m)
IF(LIBUTIL_LIBRARY)
	TARGET_LINK_LIBRARIES(test/rspamd-test util)
ENDIF(LIBUTIL_LIBRARY)
TARGET_LINK_LIBRARIES(test/rspamd-test event)
TARGET_LINK_LIBRARIES(test/rspamd-test ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(test/rspamd-test ${GMIME2_LIBRARIES})

ADD_EXECUTABLE(utils/url-extracter ${UTILSDEPENDS} ${CONTRIBSRC} ${UTILSSRC})
SET_TARGET_PROPERTIES(utils/url-extracter PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(utils/url-extracter m)
IF(LIBUTIL_LIBRARY)
	TARGET_LINK_LIBRARIES(utils/url-extracter util)
ENDIF(LIBUTIL_LIBRARY)
TARGET_LINK_LIBRARIES(utils/url-extracter ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(utils/url-extracter ${GMIME2_LIBRARIES})

ADD_EXECUTABLE(utils/expression-parser ${UTILSDEPENDS} ${CONTRIBSRC} ${EXPRSRC})
SET_TARGET_PROPERTIES(utils/expression-parser PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(utils/expression-parser m)
IF(LIBUTIL_LIBRARY)
	TARGET_LINK_LIBRARIES(utils/expression-parser util)
ENDIF(LIBUTIL_LIBRARY)
TARGET_LINK_LIBRARIES(utils/expression-parser ${GLIB2_LIBRARIES})
TARGET_LINK_LIBRARIES(utils/expression-parser ${GMIME2_LIBRARIES})

##################### INSTALLATION ##########################################

# Binaries
INSTALL(PROGRAMS rspamd-${RSPAMD_VERSION} DESTINATION bin RENAME rspamd)
INSTALL(PROGRAMS rspamc.pl DESTINATION bin RENAME rspamc)


# Configs
INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${ETC_PREFIX}/rspamd)")

INSTALL(FILES conf/2tld.inc RENAME 2tld.inc.orig DESTINATION ${ETC_PREFIX}/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/2tld.inc)
INSTALL(FILES conf/2tld.inc DESTINATION ${ETC_PREFIX}/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/2tld.inc)

INSTALL(FILES conf/drugs.inc RENAME drugs.inc.orig DESTINATION ${ETC_PREFIX}/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/drugs.inc)
INSTALL(FILES conf/drugs.inc DESTINATION ${ETC_PREFIX}/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/drugs.inc)

INSTALL(FILES conf/fraud.inc RENAME fraud.inc.orig DESTINATION ${ETC_PREFIX}/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/fraud.inc)
INSTALL(FILES conf/fraud.inc DESTINATION ${ETC_PREFIX}/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/fraud.inc)

INSTALL(FILES conf/html.inc RENAME html.inc.orig DESTINATION ${ETC_PREFIX}/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/html.inc)
INSTALL(FILES conf/html.inc DESTINATION ${ETC_PREFIX}/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/html.inc)

INSTALL(FILES conf/headers.inc RENAME headers.inc.orig DESTINATION ${ETC_PREFIX}/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/headers.inc)
INSTALL(FILES conf/headers.inc DESTINATION ${ETC_PREFIX}/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/headers.inc)

INSTALL(FILES conf/lotto.inc RENAME lotto.inc.orig DESTINATION ${ETC_PREFIX}/rspamd)
IF(NOT EXISTS ${ETC_PREFIX}/rspamd/lotto.inc)
INSTALL(FILES conf/lotto.inc DESTINATION ${ETC_PREFIX}/rspamd)
ENDIF(NOT EXISTS ${ETC_PREFIX}/rspamd/lotto.inc)

INSTALL(FILES conf/rspamd.conf.sample DESTINATION ${ETC_PREFIX}/)

# Lua plugins
IF(ENABLE_LUA MATCHES "ON")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory ${ETC_PREFIX}/rspamd/plugins)")
	INSTALL(DIRECTORY src/plugins/lua DESTINATION ${ETC_PREFIX}/rspamd/plugins PATTERN "*.lua")
ENDIF(ENABLE_LUA MATCHES "ON")

# Perl lib
IF(ENABLE_PERL MATCHES "ON")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND make install WORKING_DIRECTORY perl)")
ENDIF(ENABLE_PERL MATCHES "ON")

# Redirector
IF(ENABLE_REDIRECTOR MATCHES "ON")
	INSTALL(PROGRAMS utils/redirector.pl DESTINATION bin RENAME rspamd-redirector)
ENDIF(ENABLE_REDIRECTOR MATCHES "ON")

# Start scripts
IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	INSTALL(PROGRAMS freebsd/rspamd.sh DESTINATION etc/rc.d)
	IF(ENABLE_REDIRECTOR MATCHES "ON")
		INSTALL(PROGRAMS freebsd/redirector.sh DESTINATION etc/rc.d)
	ENDIF(ENABLE_REDIRECTOR MATCHES "ON")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E make_directory /var/run/rspamd/)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND chown ${RSPAMD_USER}:${RSPAMD_GROUP} /var/run/rspamd/)")
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")

# CPack section
SET(CPACK_DEBIAN_PACKAGE_DEPENDS libevent1 libgmime-2.0-2a)
SET(CPACK_PACKAGE_CONTACT "vsevolod@highsecure.ru")
SET(CPACK_PACKAGE_NAME rspamd)
SET(CPACK_SOURCE_IGNORE_FILES "\\\\.swp$" "/\\\\.hg/")
SET(CPACK_PACKAGE_VERSION_MAJOR ${RSPAMD_VERSION_MAJOR})
SET(CPACK_PACKAGE_VERSION_MINOR ${RSPAMD_VERSION_MINOR})
SET(CPACK_PACKAGE_VERSION_PATCH ${RSPAMD_VERSION_PATCH})
INCLUDE(CPack)
