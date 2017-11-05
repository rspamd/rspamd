# -*- cmake -*-

MACRO(ADD_TORCH_LIBRARY package type src)
  IF ("${type}" STREQUAL "STATIC")
    if ("${src}" MATCHES "cu$" OR "${src}" MATCHES "cu;")
      CUDA_ADD_LIBRARY(${package} STATIC ${src})
    else()
      ADD_LIBRARY(${package} STATIC ${src})
    endif()
  ELSE()
    if ("${src}" MATCHES "cu$" OR "${src}" MATCHES "cu;")
      CUDA_ADD_LIBRARY(${package} ${type} ${src})
    else()
      ADD_LIBRARY(${package} ${type} ${src})
    endif()
  ENDIF()
    INSTALL(TARGETS ${package} DESTINATION ${RSPAMD_LIBDIR})
ENDMACRO()

MACRO(ADD_TORCH_PACKAGE package src luasrc)
  INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/contrib/torch/torch7/lib/TH)
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/contrib/torch/torch7/lib/luaT)
  INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/contrib/torch/torch7/lib/TH)
  INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/contrib/torch/torch7/lib/luaT)
  INCLUDE_DIRECTORIES(${Torch_LUA_INCLUDE_DIR})

 ### C/C++ sources
 # As per CMake doc, macro arguments are not variables, so simple test syntax not working
  IF(NOT "${src}" STREQUAL "")

    ADD_TORCH_LIBRARY(${package} SHARED "${src}")

    ### Torch packages supposes libraries prefix is "lib"
    SET_TARGET_PROPERTIES(${package} PROPERTIES
      PREFIX "lib"
      IMPORT_PREFIX "lib")

    IF(APPLE)
      SET_TARGET_PROPERTIES(${package} PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup")
    ENDIF()

    SET_TARGET_PROPERTIES(${package} PROPERTIES
            COMPILE_FLAGS "-fPIC")
    SET_TARGET_PROPERTIES(${package} PROPERTIES
            PREFIX "lib" IMPORT_PREFIX "lib" OUTPUT_NAME "${package}")
    INSTALL(TARGETS ${package} DESTINATION ${RSPAMD_LIBDIR})

  ENDIF(NOT "${src}" STREQUAL "")

  ### lua sources
  IF(NOT "${luasrc}" STREQUAL "")
    INSTALL(FILES ${luasrc}
      DESTINATION ${LUALIBDIR}/${package})
  ENDIF(NOT "${luasrc}" STREQUAL "")

ENDMACRO(ADD_TORCH_PACKAGE)
