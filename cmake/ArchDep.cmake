TARGET_ARCHITECTURE(ARCH)

SET(ASM_CODE "
	.macro TEST1 op
	\\op %eax, %eax
	.endm
	TEST1 xorl
	")
ASM_OP(HAVE_SLASHMACRO "slash macro convention")

SET(ASM_CODE "
	.macro TEST1 op
	$0 %eax, %eax
	.endm
	TEST1 xorl
	")
ASM_OP(HAVE_DOLLARMACRO "dollar macro convention")

# For now we support only x86_64/i386 architecture with optimizations
IF("${ARCH}" STREQUAL "x86_64" OR "${ARCH}" STREQUAL "i386")
    IF(NOT HAVE_SLASHMACRO AND NOT HAVE_DOLLARMACRO)
        MESSAGE(FATAL_ERROR "Your assembler cannot compile macros, please check your CMakeFiles/CMakeError.log")
    ENDIF()

    SET(ASM_CODE "vpaddq %ymm0, %ymm0, %ymm0")
    ASM_OP(HAVE_AVX2 "avx2")
    # Handle broken compilers, sigh...
    IF(HAVE_AVX2)
        CHECK_C_SOURCE_COMPILES(
                "
#include <stddef.h>
#pragma GCC push_options
#pragma GCC target(\"avx2\")
#ifndef __SSE2__
#define __SSE2__
#endif
#ifndef __SSE__
#define __SSE__
#endif
#ifndef __SSE4_2__
#define __SSE4_2__
#endif
#ifndef __SSE4_1__
#define __SSE4_1__
#endif
#ifndef __SSEE3__
#define __SSEE3__
#endif
#ifndef __AVX__
#define __AVX__
#endif
#ifndef __AVX2__
#define __AVX2__
#endif

#ifndef __clang__
#if __GNUC__ < 6
#error Broken due to compiler bug
#endif
#endif

#include <immintrin.h>
static void foo(const char* a) __attribute__((__target__(\"avx2\")));
static void foo(const char* a)
{
	__m256i str = _mm256_loadu_si256((__m256i *)a);
	__m256i t = _mm256_loadu_si256((__m256i *)a + 1);
	_mm256_add_epi8(str, t);
}
int main(int argc, char** argv) {
	foo(argv[0]);
}" HAVE_AVX2_C_COMPILER)
        IF(NOT HAVE_AVX2_C_COMPILER)
            MESSAGE(STATUS "Your compiler has broken AVX2 support")
            UNSET(HAVE_AVX2 CACHE)
        ENDIF()
    ENDIF()
    SET(ASM_CODE "vpaddq %xmm0, %xmm0, %xmm0")
    ASM_OP(HAVE_AVX "avx")
    SET(ASM_CODE "pmuludq %xmm0, %xmm0")
    ASM_OP(HAVE_SSE2 "sse2")
    SET(ASM_CODE "lddqu 0(%esi), %xmm0")
    ASM_OP(HAVE_SSE3 "sse3")
    SET(ASM_CODE "pshufb %xmm0, %xmm0")
    ASM_OP(HAVE_SSSE3 "ssse3")
    SET(ASM_CODE "pblendw \$0, %xmm0, %xmm0")
    ASM_OP(HAVE_SSE41 "sse41")
    SET(ASM_CODE "crc32 %eax, %eax")
    ASM_OP(HAVE_SSE42 "sse42")
ENDIF()

IF ("${ARCH}" STREQUAL "x86_64")
    MESSAGE(STATUS "Enable sse2 on x86_64 architecture")
    IF((CMAKE_C_COMPILER_ID MATCHES "GNU") OR (CMAKE_C_COMPILER_ID MATCHES "Clang"))
        ADD_COMPILE_OPTIONS(-msse2)
        ADD_COMPILE_OPTIONS(-m64)
    ELSEIF(CMAKE_C_COMPILER_ID MATCHES "Intel")
        ADD_COMPILE_OPTIONS(/QxSSE2)
    ELSEIF((CMAKE_C_COMPILER_ID MATCHES "MSVC"))
        ADD_COMPILE_OPTIONS(/arch:SSE2)
    ENDIF()
ENDIF()
