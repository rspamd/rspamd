set(FASTTEXT_SHIM_SRC fasttext_shim.cxx)
add_library(rspamd-fasttext STATIC ${FASTTEXT_SHIM_SRC})
target_include_directories(rspamd-fasttext PRIVATE
	"${CMAKE_SOURCE_DIR}/"
	"${CMAKE_SOURCE_DIR}/src"
	"${CMAKE_SOURCE_DIR}/src/libutil"
	"${CMAKE_SOURCE_DIR}/contrib/expected"
	"${CMAKE_SOURCE_DIR}/contrib/ankerl"
	"${CMAKE_SOURCE_DIR}/contrib/fmt/include"
	"${CMAKE_BINARY_DIR}/src")
set_target_properties(rspamd-fasttext PROPERTIES
	CXX_STANDARD 20
	CXX_STANDARD_REQUIRED ON)
