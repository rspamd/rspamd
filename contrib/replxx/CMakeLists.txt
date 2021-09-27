# -*- mode: CMAKE; -*-
project( replxx VERSION 0.0.2 LANGUAGES CXX C )

# INFO
set(REPLXX_DISPLAY_NAME "replxx")
set(REPLXX_URL_INFO_ABOUT "https://github.com/AmokHuginnsson/replxx")
set(REPLXX_CONTACT "amok@codestation.org")
set(REPLXX_FRIENDLY_STRING "replxx - Read Evaluate Print Loop library")

# compiler options
if(CMAKE_COMPILER_IS_GNUCXX)
	message(STATUS "Compiler type GNU: ${CMAKE_CXX_COMPILER}")
	set(BASE_COMPILER_OPTIONS "-std=c++11 -Wall -D_GNU_SOURCE -pthread")
	set(CMAKE_CXX_FLAGS                "${CMAKE_CXX_FLAGS} ${BASE_COMPILER_OPTIONS}")
	set(CMAKE_CXX_FLAGS_COVERAGE       "${CMAKE_CXX_FLAGS} ${BASE_COMPILER_OPTIONS} -O0 --coverage -fno-inline -fno-default-inline -fno-inline-small-functions")
	set(CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} ${BASE_COMPILER_OPTIONS} -O0 -g -ggdb -g3 -ggdb3")
	set(CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} ${BASE_COMPILER_OPTIONS} -Os")
	set(CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} ${BASE_COMPILER_OPTIONS} -O3 -fomit-frame-pointer")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${BASE_COMPILER_OPTIONS} -O3 -g")
	set(CMAKE_C_FLAGS "-std=c99")
elseif(CMAKE_COMPILER_IS_CLANGCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	# using regular Clang or AppleClang
	message(STATUS "Compiler type CLANG: ${CMAKE_CXX_COMPILER}")
	set(BASE_COMPILER_OPTIONS "-std=c++11 -Wall -Wextra -D_GNU_SOURCE -pthread")
	set(CMAKE_CXX_FLAGS                "${CMAKE_CXX_FLAGS} ${BASE_COMPILER_OPTIONS}")
	set(CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} ${BASE_COMPILER_OPTIONS} -O0 -g")
	set(CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} ${BASE_COMPILER_OPTIONS} -Os")
	set(CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} ${BASE_COMPILER_OPTIONS} -O3 -fomit-frame-pointer")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${BASE_COMPILER_OPTIONS} -O3 -g")
	set(CMAKE_C_FLAGS "-std=c99")
elseif(MSVC)
	message(STATUS "Compiler type MSVC: ${CMAKE_CXX_COMPILER}")
	add_definitions("-D_CRT_SECURE_NO_WARNINGS=1")

	set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /INCREMENTAL:NO /SUBSYSTEM:CONSOLE /LTCG /ignore:4099")
	set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL} /SUBSYSTEM:CONSOLE /ignore:4099")
	set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /SUBSYSTEM:CONSOLE /ignore:4099")
	set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /SUBSYSTEM:CONSOLE /ignore:4099")
else()
	# unknown compiler
	message(STATUS "Compiler type UNKNOWN: ${CMAKE_CXX_COMPILER}")
	set(BASE_COMPILER_OPTIONS "-std=c++11 -Wall -pthread")
	set(CMAKE_CXX_FLAGS                "${CMAKE_CXX_FLAGS} ${BASE_COMPILER_OPTIONS}")
	set(CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} ${BASE_COMPILER_OPTIONS} -O0 -g")
	set(CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} ${BASE_COMPILER_OPTIONS} -Os")
	set(CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} ${BASE_COMPILER_OPTIONS} -O3 -fomit-frame-pointer")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${BASE_COMPILER_OPTIONS} -O3 -g")
	set(CMAKE_C_FLAGS "-std=c99")
endif()

# build libreplxx
set(
	REPLXX_SOURCES
	src/conversion.cxx
	src/escape.cxx
	src/history.cxx
	src/replxx_impl.cxx
	src/prompt.cxx
	src/replxx.cxx
	src/util.cxx
	src/wcwidth.cpp
	src/terminal.cxx
	src/windows.cxx
)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
if(ENABLE_STATIC MATCHES "ON")
	add_library(rspamd-replxx STATIC ${REPLXX_SOURCES})
else()
	add_library(rspamd-replxx SHARED ${REPLXX_SOURCES})
endif()

target_include_directories(
	rspamd-replxx
	PUBLIC ${PROJECT_SOURCE_DIR}/include
	PRIVATE ${PROJECT_SOURCE_DIR}/src
)
set( TARGETS ${TARGETS} rspamd-replxx )
target_compile_definitions(rspamd-replxx PRIVATE REPLXX_BUILDING_DLL)
target_link_libraries(rspamd-replxx "${RSPAMD_REQUIRED_LIBRARIES}")

install( TARGETS ${TARGETS} LIBRARY DESTINATION ${RSPAMD_LIBDIR})