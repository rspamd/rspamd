CONFIGURE_FILE("cmake/TorchConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/cmake-exports/TorchConfig.cmake" @ONLY)
CONFIGURE_FILE("cmake/TorchWrap.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/cmake-exports/TorchWrap.cmake" @ONLY)
