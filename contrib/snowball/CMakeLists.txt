# End of configuration
SET(LIBSTEM_ALGORITHMS danish dutch english finnish french german hungarian
	italian norwegian porter portuguese romanian
	russian spanish swedish turkish)
SET(KOI8_ALGORITHMS russian)
SET(ISO_8859_1_ALGORITHMS danish dutch english finnish french german italian
			norwegian porter portuguese spanish swedish)
SET(ISO_8859_2_ALGORITHMS hungarian romanian)
SET(OTHER_ALGORITHMS german2 kraaij_pohlmann lovins)
SET(ALL_ALGORITHMS ${LIBSTEM_ALGORITHMS} ${OTHER_ALGORITHMS})

SET(COMPILER_SOURCES compiler/space.c
		   compiler/tokeniser.c
		   compiler/analyser.c
		   compiler/generator.c
		   compiler/driver.c
		   compiler/generator_java.c)

SET(SNOWBALL_RUNTIME runtime/api.c
		   runtime/utilities.c)
SET(LIBSTEMMER_SOURCES libstemmer/libstemmer.c)
SET(LIBSTEMMER_UTF8_SOURCES libstemmer/libstemmer_utf8.c)
#LIBSTEMMER_UTF8_SOURCES = libstemmer/libstemmer_utf8.c
#LIBSTEMMER_HEADERS = include/libstemmer.h libstemmer/modules.h libstemmer/modules_utf8.h
#LIBSTEMMER_EXTRA = libstemmer/modules.txt libstemmer/modules_utf8.txt libstemmer/libstemmer_c.in

SET(STEMWORDS_SOURCES examples/stemwords.c)
SET(MODULES_H "modules.h")
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libstemmer/libstemmer_c.in ${CMAKE_CURRENT_BINARY_DIR}/libstemmer/libstemmer.c @ONLY)

MACRO(gen_stem IN ENCODING)
	FOREACH(_it ${IN})
		SET(_base "${CMAKE_CURRENT_BINARY_DIR}/libstemmer/stem_${ENCODING}_${_it}")
		SET(_header "${_base}.h")
		SET(_source "${_base}.c")
		STRING(REPLACE "UTF_8" "Unicode" _in_enc "${ENCODING}")
		SET(_input "${CMAKE_CURRENT_SOURCE_DIR}/algorithms/${_it}/stem_${_in_enc}.sbl")
		IF(${_in_enc} STREQUAL "Unicode" AND NOT EXISTS ${_input})
			ADD_CUSTOM_COMMAND(OUTPUT ${_source}
				COMMAND ${CMAKE_CURRENT_BINARY_DIR}/snowball  "${CMAKE_CURRENT_SOURCE_DIR}/algorithms/${_it}/stem_ISO_8859_1.sbl" -o ${_base} -eprefix ${_it}_${ENCODING}_ -r ../runtime -u
				DEPENDS snowball)
			LIST(APPEND STEMMER_SOURCES ${_source})

		ELSE()
		IF(EXISTS "${_input}")
			ADD_CUSTOM_COMMAND(OUTPUT ${_source}
				COMMAND ${CMAKE_CURRENT_BINARY_DIR}/snowball ${_input} -o ${_base} -eprefix ${_it}_${ENCODING}_ -r ../runtime -u
				DEPENDS snowball)
			LIST(APPEND STEMMER_SOURCES ${_source})
		ENDIF()
		ENDIF()
	ENDFOREACH()
ENDMACRO()

INCLUDE_DIRECTORIES("include")

ADD_EXECUTABLE(snowball ${COMPILER_SOURCES})

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libstemmer/modules.h
 COMMAND ${PERL_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/libstemmer/mkmodules.pl libstemmer/modules.h libstemmer ${CMAKE_CURRENT_SOURCE_DIR}/libstemmer/modules.txt libstemmer/mkinc.mak)
ADD_CUSTOM_TARGET(modules DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/libstemmer/modules.h")

SET(STEMMER_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/libstemmer/libstemmer.c")
ADD_CUSTOM_TARGET(stemmer_deps ALL)
ADD_DEPENDENCIES(stemmer_deps modules)

gen_stem("${LIBSTEM_ALGORITHMS}" "UTF_8")
gen_stem("${KOI8_ALGORITHMS}" "KOI8_R")
gen_stem("${ISO_8859_1_ALGORITHMS}" "ISO_8859_1")
gen_stem("${ISO_8859_2_ALGORITHMS}" "ISO_8859_2")


ADD_LIBRARY(stemmer ${LINK_TYPE} ${SNOWBALL_RUNTIME} ${STEMMER_SOURCES})
ADD_DEPENDENCIES(stemmer stemmer_deps)

ADD_EXECUTABLE(stemwords ${STEMWORDS_SOURCES})
TARGET_LINK_LIBRARIES(stemwords stemmer)
