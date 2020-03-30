# End of configuration
SET(LIBSTEM_ALGORITHMS arabic danish dutch english finnish french german greek hindi hungarian
	indonesian italian lithuanian nepali norwegian porter portuguese romanian
	russian serbian spanish swedish tamil turkish)
SET(ALL_ALGORITHMS ${LIBSTEM_ALGORITHMS})

SET(COMPILER_SOURCES compiler/space.c
		   compiler/tokeniser.c
		   compiler/analyser.c
		   compiler/generator.c
		   compiler/driver.c)

SET(SNOWBALL_RUNTIME runtime/api.c
		   runtime/utilities.c)
SET(LIBSTEMMER_SOURCES libstemmer/libstemmer.c)
SET(LIBSTEMMER_UTF8_SOURCES libstemmer/libstemmer_utf8.c)
#LIBSTEMMER_UTF8_SOURCES = libstemmer/libstemmer_utf8.c
#LIBSTEMMER_HEADERS = include/libstemmer.h libstemmer/modules.h libstemmer/modules_utf8.h
#LIBSTEMMER_EXTRA = libstemmer/modules.txt libstemmer/modules_utf8.txt libstemmer/libstemmer_c.in

SET(MODULES_H "modules.h")
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libstemmer/libstemmer_c.in ${CMAKE_CURRENT_BINARY_DIR}/libstemmer/libstemmer.c @ONLY)
ADD_DEFINITIONS("-DDISABLE_JS")
ADD_DEFINITIONS("-DDISABLE_GO")
ADD_DEFINITIONS("-DDISABLE_JAVA")
ADD_DEFINITIONS("-DDISABLE_PYTHON")
ADD_DEFINITIONS("-DDISABLE_CSHARP")
ADD_DEFINITIONS("-DDISABLE_PASCAL")
ADD_DEFINITIONS("-DDISABLE_RUST")

MACRO(gen_stem IN ENCODING)
	FOREACH(_it ${IN})
		SET(_base "${CMAKE_CURRENT_BINARY_DIR}/libstemmer/stem_${ENCODING}_${_it}")
		SET(_header "${_base}.h")
		SET(_source "${_base}.c")
		STRING(REPLACE "UTF_8" "Unicode" _in_enc "${ENCODING}")
		SET(_input "${CMAKE_CURRENT_SOURCE_DIR}/algorithms/${_it}.sbl")
		IF(${_in_enc} STREQUAL "Unicode" AND NOT EXISTS ${_input})
			ADD_CUSTOM_COMMAND(OUTPUT ${_source}
				COMMAND env "ASAN_OPTIONS=detect_leaks=0" ${CMAKE_CURRENT_BINARY_DIR}/snowball  "${CMAKE_CURRENT_SOURCE_DIR}/algorithms/${_it}/stem_ISO_8859_1.sbl" -o ${_base} -eprefix ${_it}_${ENCODING}_ -r ../runtime -u
				DEPENDS snowball)
			LIST(APPEND STEMMER_SOURCES ${_source})

		ELSE()
		IF(EXISTS "${_input}")
			ADD_CUSTOM_COMMAND(OUTPUT ${_source}
				COMMAND env "ASAN_OPTIONS=detect_leaks=0" ${CMAKE_CURRENT_BINARY_DIR}/snowball ${_input} -o ${_base} -eprefix ${_it}_${ENCODING}_ -r ../runtime -u
				DEPENDS snowball)
			LIST(APPEND STEMMER_SOURCES ${_source})
		ENDIF()
		ENDIF()
	ENDFOREACH()
ENDMACRO()

INCLUDE_DIRECTORIES("include")

ADD_EXECUTABLE(snowball ${COMPILER_SOURCES})

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libstemmer/modules.h
 COMMAND ${PERL_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/libstemmer/mkmodules.pl ${CMAKE_CURRENT_BINARY_DIR}/libstemmer/modules.h libstemmer ${CMAKE_CURRENT_SOURCE_DIR}/libstemmer/modules.txt ${CMAKE_CURRENT_BINARY_DIR}/libstemmer/mkinc.mak)
ADD_CUSTOM_TARGET(modules DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libstemmer/modules.h")

SET(STEMMER_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/libstemmer/libstemmer.c")
ADD_CUSTOM_TARGET(stemmer_deps ALL)
ADD_DEPENDENCIES(stemmer_deps modules)

gen_stem("${LIBSTEM_ALGORITHMS}" "UTF_8")

ADD_LIBRARY(stemmer ${LINK_TYPE} ${SNOWBALL_RUNTIME} ${STEMMER_SOURCES})
ADD_DEPENDENCIES(stemmer stemmer_deps)
