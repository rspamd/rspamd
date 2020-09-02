option (ENABLE_BLAS    "Enable openblas for fast neural network processing [default: OFF]" OFF)

IF(ENABLE_BLAS MATCHES "ON")
    ProcessPackage(BLAS OPTIONAL_INCLUDE LIBRARY openblas blas blis
            INCLUDE cblas.h INCLUDE_SUFFIXES include/openblas
            include/blas
            include/blis
            ROOT ${BLAS_ROOT_DIR}
            LIB_OUTPUT BLAS_REQUIRED_LIBRARIES)
    ProcessPackage(BLAS_LAPACK OPTIONAL_INCLUDE LIBRARY lapack
            INCLUDE cblas.h INCLUDE_SUFFIXES include/openblas
            include/blas
            include/blis
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
            SET(HAVE_CBLAS_H 1)
        ENDIF()
    ELSE()
        SET(HAVE_CBLAS_H 1)
    ENDIF()
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/sgemm.c" "
#include <stddef.h>
enum CBLAS_ORDER {CblasRowMajor=101, CblasColMajor=102 };
enum CBLAS_TRANSPOSE {CblasNoTrans=111, CblasTrans=112 };
extern void cblas_sgemm(const enum CBLAS_ORDER Order,
                const enum CBLAS_TRANSPOSE TA,
                const enum CBLAS_TRANSPOSE TB,
                const int M, const int N, const int K,
                const float  alpha, const float *A, const int lda,
                const float *B, const int ldb, const float  beta,
                float *C, const int ldc);
int main(int argc, char **argv)
{
    cblas_sgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans, 0, 0, 0, 0, NULL, 0,
        NULL, 0, 0, NULL, 0);
    return 0;
}
")
    try_compile(HAVE_CBLAS_SGEMM
            ${CMAKE_CURRENT_BINARY_DIR}
            "${CMAKE_CURRENT_BINARY_DIR}/sgemm.c"
            COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
            LINK_LIBRARIES ${BLAS_REQUIRED_LIBRARIES}
            OUTPUT_VARIABLE SGEMM_ERR)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/saxpy.c" "
#include <stddef.h>
extern void cblas_saxpy(const int __N,
    const float __alpha, const float *__X, const int __incX, float *__Y, const int __incY);
int main(int argc, char **argv)
{
    cblas_saxpy(0, 0, NULL, 0, NULL, 0);
    return 0;
}
")
    try_compile(HAVE_CBLAS_SAXPY
            ${CMAKE_CURRENT_BINARY_DIR}
            "${CMAKE_CURRENT_BINARY_DIR}/saxpy.c"
            COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
            LINK_LIBRARIES ${BLAS_REQUIRED_LIBRARIES}
            OUTPUT_VARIABLE SAXPY_ERR)

    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/openblas_set_num_threads.c" "
#include <stddef.h>
extern void openblas_set_num_threads(int num_threads);
int main(int argc, char **argv)
{
    openblas_set_num_threads(1);
    return 0;
}
")
    try_compile(HAVE_OPENBLAS_SET_NUM_THREADS
            ${CMAKE_CURRENT_BINARY_DIR}
            "${CMAKE_CURRENT_BINARY_DIR}/openblas_set_num_threads.c"
            COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
            LINK_LIBRARIES ${BLAS_REQUIRED_LIBRARIES}
            OUTPUT_VARIABLE OPENBLAS_SET_NUM_THREADS_ERR)

    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/bli_thread_set_num_threads.c" "
#include <stddef.h>
extern void bli_thread_set_num_threads(int num_threads);
int main(int argc, char **argv)
{
    bli_thread_set_num_threads(1);
    return 0;
}
")
    try_compile(HAVE_BLI_THREAD_SET_NUM_THREADS
            ${CMAKE_CURRENT_BINARY_DIR}
            "${CMAKE_CURRENT_BINARY_DIR}/bli_thread_set_num_threads.c"
            COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
            LINK_LIBRARIES ${BLAS_REQUIRED_LIBRARIES}
            OUTPUT_VARIABLE BLI_SET_NUM_THREADS_ERR)
    # Cmake is just brain damaged
    #CHECK_LIBRARY_EXISTS(${BLAS_REQUIRED_LIBRARIES} cblas_sgemm "" HAVE_CBLAS_SGEMM)
    if(HAVE_CBLAS_SGEMM)
        MESSAGE(STATUS "Blas has CBLAS sgemm")
    else()
        MESSAGE(STATUS "Blas has -NOT- CBLAS sgemm, use internal workaround: ${SGEMM_ERR}")
    endif()
    if(HAVE_CBLAS_SAXPY)
        MESSAGE(STATUS "Blas has CBLAS saxpy")
    else()
        MESSAGE(STATUS "Blas has -NOT- CBLAS saxpy, use internal workaround: ${SAXPY_ERR}")
    endif()
    SET(HAVE_CBLAS 1)
ENDIF(WITH_BLAS)

CONFIGURE_FILE("${CMAKE_SOURCE_DIR}/blas-config.h.in" "${CMAKE_BINARY_DIR}/src/blas-config.h")