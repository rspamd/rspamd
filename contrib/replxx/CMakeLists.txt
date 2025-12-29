# -*- mode: CMAKE; -*-
project(replxx VERSION 0.0.2 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
	add_definitions("-D_CRT_SECURE_NO_WARNINGS=1")
endif()

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
set(TARGETS ${TARGETS} rspamd-replxx)
target_compile_definitions(rspamd-replxx PRIVATE REPLXX_BUILDING_DLL)
target_link_libraries(rspamd-replxx "${RSPAMD_REQUIRED_LIBRARIES}")

install(TARGETS ${TARGETS} LIBRARY DESTINATION ${RSPAMD_LIBDIR})
