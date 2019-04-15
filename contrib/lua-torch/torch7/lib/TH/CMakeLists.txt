cmake_minimum_required(VERSION 2.6)

# avoid some cmake warnings

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
SET(CMAKE_LIBRARY_PATH /usr/lib/x86_64-linux-gnu/ ${CMAKE_LIBRARY_PATH})

#######################################################################
##### flags section
######################################################################

IF(MSVC)
  # MSVC now supports C99 since VS2013/VS2015, however the standard version switch is not provided yet
  # SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /std:c99")
ELSE(MSVC)
  # enable gnu99 and not c99 because we use
  # gnu extensions like posix_memalign
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
ENDIF(MSVC)

IF(MSVC)
  ADD_DEFINITIONS(-D_CRT_SECURE_NO_DEPRECATE=1)  # respect the standard
ENDIF(MSVC)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
IF(UNIX)
  # prevent Unknown CMake command "check_function_exists".
  INCLUDE(CheckFunctionExists)
ENDIF(UNIX)

# OpenMP support?

IF (WITH_OPENMP)
  FIND_PACKAGE(OpenMP)
  IF(OPENMP_FOUND)
    MESSAGE(STATUS "Compiling with OpenMP support")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
  ENDIF(OPENMP_FOUND)
ENDIF (WITH_OPENMP)

# ARM specific flags
FIND_PACKAGE(ARM)
IF (ASIMD_FOUND)
  MESSAGE(STATUS "asimd/Neon found with compiler flag : -D__NEON__")
  SET(CMAKE_C_FLAGS "-D__NEON__ ${CMAKE_C_FLAGS}")
ELSEIF (NEON_FOUND)
  MESSAGE(STATUS "Neon found with compiler flag : -mfpu=neon -D__NEON__")
  SET(CMAKE_C_FLAGS "-mfpu=neon -D__NEON__ ${CMAKE_C_FLAGS}")
ENDIF (ASIMD_FOUND)
IF (CORTEXA8_FOUND)
  MESSAGE(STATUS "Cortex-A8 Found with compiler flag : -mcpu=cortex-a8")
  SET(CMAKE_C_FLAGS "-mcpu=cortex-a8 -fprefetch-loop-arrays ${CMAKE_C_FLAGS}")
ENDIF (CORTEXA8_FOUND)
IF (CORTEXA9_FOUND)
  MESSAGE(STATUS "Cortex-A9 Found with compiler flag : -mcpu=cortex-a9")
  SET(CMAKE_C_FLAGS "-mcpu=cortex-a9 ${CMAKE_C_FLAGS}")
ENDIF (CORTEXA9_FOUND)

INCLUDE (CheckIncludeFile)
INCLUDE (CheckCSourceCompiles)
CHECK_INCLUDE_FILE(cpuid.h HAVE_CPUID_H)
# Check for a cpuid intrinsic
IF(HAVE_CPUID_H)
    CHECK_C_SOURCE_COMPILES("#include <cpuid.h>
        int main()
        {
            unsigned int eax, ebx, ecx, edx;
            return __get_cpuid(0, &eax, &ebx, &ecx, &edx);
        }" HAVE_GCC_GET_CPUID)
ENDIF()
IF(HAVE_GCC_GET_CPUID)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_GCC_GET_CPUID")
ENDIF(HAVE_GCC_GET_CPUID)

CHECK_C_SOURCE_COMPILES("#include <stdint.h>
    static inline void cpuid(uint32_t *eax, uint32_t *ebx,
    			 uint32_t *ecx, uint32_t *edx)
    {
      uint32_t a = *eax, b, c = *ecx, d;
      asm volatile ( \"cpuid\" : \"+a\"(a), \"=b\"(b), \"+c\"(c), \"=d\"(d) );
      *eax = a; *ebx = b; *ecx = c; *edx = d;
    }
    int main() {
      uint32_t a,b,c,d;
      cpuid(&a, &b, &c, &d);
      return 0;
    }" NO_GCC_EBX_FPIC_BUG)

IF(NOT NO_GCC_EBX_FPIC_BUG)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_GCC_GET_CPUID")
ENDIF(NOT NO_GCC_EBX_FPIC_BUG)


FIND_PACKAGE(SSE) # checks SSE, AVX and AVX2
IF(C_SSE2_FOUND)
  MESSAGE(STATUS "SSE2 Found")
  SET(CMAKE_C_FLAGS "${C_SSE2_FLAGS} -DUSE_SSE2 ${CMAKE_C_FLAGS}")
ENDIF(C_SSE2_FOUND)
IF(C_SSE3_FOUND)
  MESSAGE(STATUS "SSE3 Found")
  SET(CMAKE_C_FLAGS "${C_SSE3_FLAGS} -DUSE_SSE3 ${CMAKE_C_FLAGS}")
ENDIF(C_SSE3_FOUND)
# we dont set -mavx and -mavx2 flags globally, but only for specific files
# however, we want to enable the AVX codepaths, so we still need to
# add USE_AVX and USE_AVX2 macro defines
IF(FALSE)
IF(C_AVX_FOUND)
  MESSAGE(STATUS "AVX Found")
  SET(CMAKE_C_FLAGS "-DUSE_AVX ${CMAKE_C_FLAGS}")
ENDIF(C_AVX_FOUND)
IF(C_AVX2_FOUND)
  MESSAGE(STATUS "AVX2 Found")
  SET(CMAKE_C_FLAGS "-DUSE_AVX2 ${CMAKE_C_FLAGS}")
ENDIF(C_AVX2_FOUND)
ENDIF()

CHECK_C_SOURCE_RUNS("
#include <stdatomic.h>
int main()
{
  int a;
  int oa;
  atomic_store(&a, 1);
  atomic_fetch_add(&a, 1);
  oa = atomic_load(&a);
  if(!atomic_compare_exchange_strong(&a, &oa, 3))
    return -1;
  return 0;
}
" HAS_C11_ATOMICS)

IF(NOT HAS_C11_ATOMICS)
  CHECK_C_SOURCE_RUNS("
#include <intrin.h>
int main()
{
  long a;
  _InterlockedExchange(&a, 1);
  _InterlockedExchangeAdd(&a, 1);
  if(_InterlockedCompareExchange(&a, 3, 2) != 2)
    return -1;
  return 0;
}
" HAS_MSC_ATOMICS)

  CHECK_C_SOURCE_RUNS("
int main()
{
  int a;
  __sync_lock_test_and_set(&a, 1);
  __sync_fetch_and_add(&a, 1);
  if(!__sync_bool_compare_and_swap(&a, 2, 3))
    return -1;
  return 0;
}
" HAS_GCC_ATOMICS)
ENDIF()

#######################################################################
##### sources section
######################################################################

# IF ANY SIMD FOUND
IF ("${ARCH}" STREQUAL "x86_64")
  SET(simd generic/simd/convolve.c generic/simd/convolve5x5_sse.c)
  SET(CMAKE_C_FLAGS "-DUSE_SSE2 ${CMAKE_C_FLAGS}")
  SET_SOURCE_FILES_PROPERTIES(generic/simd/convolve5x5_sse.c PROPERTIES COMPILE_FLAGS "-O3 -ffast-math")
ENDIF()


# IF AVX FOUND
IF(FALSE)
IF(C_AVX_FOUND)
  IF(MSVC)
    SET_SOURCE_FILES_PROPERTIES(generic/simd/convolve5x5_avx.c PROPERTIES COMPILE_FLAGS "/Ox /fp:fast ${C_AVX_FLAGS}")
    SET_SOURCE_FILES_PROPERTIES(vector/AVX.c PROPERTIES COMPILE_FLAGS "/Ox /arch:AVX ${C_AVX_FLAGS}")
  ELSE(MSVC)
    SET_SOURCE_FILES_PROPERTIES(generic/simd/convolve5x5_avx.c PROPERTIES COMPILE_FLAGS "-O3 -ffast-math ${C_AVX_FLAGS}")
    SET_SOURCE_FILES_PROPERTIES(vector/AVX.c PROPERTIES COMPILE_FLAGS "-O3 ${C_AVX_FLAGS}")
  ENDIF(MSVC)
  SET(simd ${simd} vector/AVX.c generic/simd/convolve5x5_avx.c)
ENDIF(C_AVX_FOUND)

IF(C_AVX2_FOUND)
  IF(MSVC)
    SET_SOURCE_FILES_PROPERTIES(vector/AVX2.c PROPERTIES COMPILE_FLAGS "/Ox /arch:AVX2 ${C_AVX2_FLAGS}")
  ELSE(MSVC)
    SET_SOURCE_FILES_PROPERTIES(vector/AVX2.c PROPERTIES COMPILE_FLAGS "-O3 ${C_AVX2_FLAGS}")
  ENDIF(MSVC)
  SET(simd ${simd} vector/AVX2.c)
ENDIF(C_AVX2_FOUND)
ENDIF()

SET(hdr
  THGeneral.h THHalf.h THAllocator.h THSize.h THStorage.h THTensor.h THTensorApply.h THBlas.h THMath.h
  THLapack.h THLogAdd.h THRandom.h THVector.h THAtomic.h )

SET(src
  THGeneral.c THHalf.c THAllocator.c THSize.c THStorage.c THTensor.c THBlas.c THLapack.c
  THLogAdd.c THRandom.c THFile.c THDiskFile.c THMemoryFile.c THAtomic.c THVector.c)

SET(src ${src} ${hdr} ${simd})

#######################################################################
##### build section
######################################################################

ADD_TORCH_LIBRARY(TH SHARED "${src}")

IF(HAS_C11_ATOMICS)
  ADD_DEFINITIONS(-DUSE_C11_ATOMICS=1)
  MESSAGE(STATUS "Atomics: using C11 intrinsics")
ELSEIF(HAS_MSC_ATOMICS)
  ADD_DEFINITIONS(-DUSE_MSC_ATOMICS=1)
  MESSAGE(STATUS "Atomics: using MSVC intrinsics")
ELSEIF(HAS_GCC_ATOMICS)
  ADD_DEFINITIONS(-DUSE_GCC_ATOMICS=1)
    MESSAGE(STATUS "Atomics: using GCC intrinsics")
ELSE()
  SET(CMAKE_THREAD_PREFER_PTHREAD TRUE)
  FIND_PACKAGE(Threads)
  IF(THREADS_FOUND)
    ADD_DEFINITIONS(-DUSE_PTHREAD_ATOMICS=1)
    TARGET_LINK_LIBRARIES(TH ${CMAKE_THREAD_LIBS_INIT})
    MESSAGE(STATUS "Atomics: using pthread")
  ENDIF()
ENDIF()

FIND_PACKAGE(BLAS)
IF(BLAS_FOUND)
  SET(USE_BLAS 1)
  TARGET_LINK_LIBRARIES(TH ${BLAS_LIBRARIES})
  IF(BLAS_INFO STREQUAL "mkl")
    ADD_DEFINITIONS(-DTH_BLAS_MKL)
  ELSEIF(BLAS_INFO STREQUAL "open")
    ADD_DEFINITIONS(-DTH_BLAS_OPEN)
  ENDIF()
ENDIF(BLAS_FOUND)

FIND_PACKAGE(LAPACK)
IF(LAPACK_FOUND)
  SET(USE_LAPACK 1)
  TARGET_LINK_LIBRARIES(TH ${LAPACK_LIBRARIES})
ENDIF(LAPACK_FOUND)

IF (UNIX AND NOT APPLE)
   INCLUDE(CheckLibraryExists)
   # https://github.com/libgit2/libgit2/issues/2128#issuecomment-35649830
   CHECK_LIBRARY_EXISTS(rt clock_gettime "time.h" NEED_LIBRT)
   IF(NEED_LIBRT)
     TARGET_LINK_LIBRARIES(TH rt)
     SET(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} rt)
   ENDIF(NEED_LIBRT)
ENDIF(UNIX AND NOT APPLE)

IF(UNIX)
  SET(CMAKE_EXTRA_INCLUDE_FILES "sys/mman.h")
  CHECK_FUNCTION_EXISTS(mmap HAVE_MMAP)
  IF(HAVE_MMAP)
    ADD_DEFINITIONS(-DHAVE_MMAP=1)
  ENDIF(HAVE_MMAP)
  # done for lseek: https://www.gnu.org/software/libc/manual/html_node/File-Position-Primitive.html
  ADD_DEFINITIONS(-D_FILE_OFFSET_BITS=64)
  CHECK_FUNCTION_EXISTS(shm_open HAVE_SHM_OPEN)
  IF(HAVE_SHM_OPEN)
    ADD_DEFINITIONS(-DHAVE_SHM_OPEN=1)
  ENDIF(HAVE_SHM_OPEN)
  CHECK_FUNCTION_EXISTS(shm_unlink HAVE_SHM_UNLINK)
  IF(HAVE_SHM_UNLINK)
    ADD_DEFINITIONS(-DHAVE_SHM_UNLINK=1)
  ENDIF(HAVE_SHM_UNLINK)
  CHECK_FUNCTION_EXISTS(malloc_usable_size HAVE_MALLOC_USABLE_SIZE)
  IF(HAVE_MALLOC_USABLE_SIZE)
    ADD_DEFINITIONS(-DHAVE_MALLOC_USABLE_SIZE=1)
  ENDIF(HAVE_MALLOC_USABLE_SIZE)
ENDIF(UNIX)

IF(NOT MSVC)
  TARGET_LINK_LIBRARIES(TH m)
ENDIF(NOT MSVC)

# Is __thread supported?
IF(NOT MSVC)
  CHECK_C_SOURCE_COMPILES("static __thread int x = 1; int main() { return x; }" C_HAS_THREAD)
ELSE(NOT MSVC)
  CHECK_C_SOURCE_COMPILES("static __declspec( thread ) int x = 1; int main() { return x; }" C_HAS_THREAD)
ENDIF(NOT MSVC)
IF(NOT C_HAS_THREAD)
  MESSAGE(STATUS "Warning: __thread is not supported, generating thread-unsafe code")
ELSE(NOT C_HAS_THREAD)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTH_HAVE_THREAD")
ENDIF(NOT C_HAS_THREAD)

INCLUDE_DIRECTORIES("${CMAKE_CURRENT_BINARY_DIR}")
CONFIGURE_FILE(THGeneral.h.in "${CMAKE_CURRENT_BINARY_DIR}/THGeneral.h")
