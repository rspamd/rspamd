option (ENABLE_BLAS    "Enable openblas for fast neural network processing [default: OFF]" OFF)

IF(ENABLE_BLAS MATCHES "ON")
    ProcessPackage(BLAS OPTIONAL_INCLUDE LIBRARY openblas blas
            INCLUDE cblas.h INCLUDE_SUFFIXES include/openblas
            include/blas
            ROOT ${BLAS_ROOT_DIR}
            LIB_OUTPUT BLAS_REQUIRED_LIBRARIES)
ENDIF()

IF(WITH_BLAS)
    MESSAGE(STATUS "Use openblas to accelerate kann")
    IF(NOT BLAS_INCLUDE)
        FIND_FILE(HAVE_CBLAS_H HINTS "${RSPAMD_SEARCH_PATH}"
                NAMES cblas.h
                DOC "Path to cblas.h header")
        IF(NOT HAVE_CBLAS_H)
            MESSAGE(STATUS "Blas header cblas.h has not been found, use internal workaround")
        ELSE()
            ADD_DEFINITIONS(-DHAVE_CBLAS_H)
        ENDIF()
    ELSE()
        ADD_DEFINITIONS(-DHAVE_CBLAS_H)
    ENDIF()
    ADD_DEFINITIONS(-DHAVE_CBLAS)
ENDIF(WITH_BLAS)