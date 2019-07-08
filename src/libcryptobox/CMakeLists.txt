INCLUDE(AsmOp.cmake)

TARGET_ARCHITECTURE(ARCH)

SET(CHACHASRC ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/chacha.c
	${CMAKE_CURRENT_SOURCE_DIR}/chacha20/ref.c)

SET(BASE64SRC ${CMAKE_CURRENT_SOURCE_DIR}/base64/ref.c
		${CMAKE_CURRENT_SOURCE_DIR}/base64/base64.c)

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

# For now we support only x86_64 architecture with optimizations
IF("${ARCH}" STREQUAL "x86_64")
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

IF(HAVE_AVX2)
	SET(CHACHASRC ${CHACHASRC} ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/avx2.S)
	SET(BASE64SRC ${BASE64SRC} ${CMAKE_CURRENT_SOURCE_DIR}/base64/avx2.c)
	MESSAGE(STATUS "AVX2 support is added")
ENDIF(HAVE_AVX2)
IF(HAVE_AVX)
	SET(CHACHASRC ${CHACHASRC} ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/avx.S)
	MESSAGE(STATUS "AVX support is added")
ENDIF(HAVE_AVX)
IF(HAVE_SSE2)
	SET(CHACHASRC ${CHACHASRC} ${CMAKE_CURRENT_SOURCE_DIR}/chacha20/sse2.S)
	MESSAGE(STATUS "SSE2 support is added")
ENDIF(HAVE_SSE2)
IF(HAVE_SSE42)
	SET(BASE64SRC ${BASE64SRC} ${CMAKE_CURRENT_SOURCE_DIR}/base64/sse42.c)
	MESSAGE(STATUS "SSE42 support is added")
ENDIF(HAVE_SSE42)

CONFIGURE_FILE(platform_config.h.in platform_config.h)
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_BINARY_DIR}")
SET(LIBCRYPTOBOXSRC	${CMAKE_CURRENT_SOURCE_DIR}/cryptobox.c
					${CMAKE_CURRENT_SOURCE_DIR}/keypair.c
					${CMAKE_CURRENT_SOURCE_DIR}/keypairs_cache.c
					${CMAKE_CURRENT_SOURCE_DIR}/catena/catena.c)

SET(RSPAMD_CRYPTOBOX ${LIBCRYPTOBOXSRC} ${CHACHASRC} ${BASE64SRC} PARENT_SCOPE)
