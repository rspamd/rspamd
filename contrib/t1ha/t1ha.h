/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#pragma once

#ifndef __has_attribute
#define __has_attribute(x) (0)
#endif

#ifndef __has_include
#define __has_include(x) (0)
#endif

#ifndef __GNUC_PREREQ
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define __GNUC_PREREQ(maj, min)                                                \
  ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define __GNUC_PREREQ(maj, min) 0
#endif
#endif /* __GNUC_PREREQ */

#ifndef __CLANG_PREREQ
#ifdef __clang__
#define __CLANG_PREREQ(maj, min)                                               \
  ((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
#else
#define __CLANG_PREREQ(maj, min) (0)
#endif
#endif /* __CLANG_PREREQ */

/*****************************************************************************/

#ifdef _MSC_VER
/* Avoid '16' bytes padding added after data member 't1ha_context::total'
 * and other warnings from std-headers if warning-level > 3. */
#pragma warning(push, 3)
#endif

#if defined(__cplusplus) && __cplusplus >= 201103L
#include <climits>
#include <cstddef>
#include <cstdint>
#else
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#endif

/*****************************************************************************/

#if defined(i386) || defined(__386) || defined(__i386) || defined(__i386__) || \
    defined(i486) || defined(__i486) || defined(__i486__) ||                   \
    defined(i586) | defined(__i586) || defined(__i586__) || defined(i686) ||   \
    defined(__i686) || defined(__i686__) || defined(_M_IX86) ||                \
    defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) ||            \
    defined(__INTEL__) || defined(__x86_64) || defined(__x86_64__) ||          \
    defined(__amd64__) || defined(__amd64) || defined(_M_X64) ||               \
    defined(_M_AMD64) || defined(__IA32__) || defined(__INTEL__)
#ifndef __ia32__
/* LY: define neutral __ia32__ for x86 and x86-64 archs */
#define __ia32__ 1
#endif /* __ia32__ */
#if !defined(__amd64__) && (defined(__x86_64) || defined(__x86_64__) ||        \
                            defined(__amd64) || defined(_M_X64))
/* LY: define trusty __amd64__ for all AMD64/x86-64 arch */
#define __amd64__ 1
#endif /* __amd64__ */
#endif /* all x86 */

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) ||           \
    !defined(__ORDER_BIG_ENDIAN__)

/* *INDENT-OFF* */
/* clang-format off */

#if defined(__GLIBC__) || defined(__GNU_LIBRARY__) || defined(__ANDROID__) ||  \
    defined(HAVE_ENDIAN_H) || __has_include(<endian.h>)
#include <endian.h>
#elif defined(__APPLE__) || defined(__MACH__) || defined(__OpenBSD__) ||       \
    defined(HAVE_MACHINE_ENDIAN_H) || __has_include(<machine/endian.h>)
#include <machine/endian.h>
#elif defined(HAVE_SYS_ISA_DEFS_H) || __has_include(<sys/isa_defs.h>)
#include <sys/isa_defs.h>
#elif (defined(HAVE_SYS_TYPES_H) && defined(HAVE_SYS_ENDIAN_H)) ||             \
    (__has_include(<sys/types.h>) && __has_include(<sys/endian.h>))
#include <sys/endian.h>
#include <sys/types.h>
#elif defined(__bsdi__) || defined(__DragonFly__) || defined(__FreeBSD__) ||   \
    defined(__NETBSD__) || defined(__NetBSD__) ||                              \
    defined(HAVE_SYS_PARAM_H) || __has_include(<sys/param.h>)
#include <sys/param.h>
#endif /* OS */

/* *INDENT-ON* */
/* clang-format on */

#if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
#define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
#define __BYTE_ORDER__ __BYTE_ORDER
#elif defined(_BYTE_ORDER) && defined(_LITTLE_ENDIAN) && defined(_BIG_ENDIAN)
#define __ORDER_LITTLE_ENDIAN__ _LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ _BIG_ENDIAN
#define __BYTE_ORDER__ _BYTE_ORDER
#else
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321

#if defined(__LITTLE_ENDIAN__) ||                                              \
    (defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)) ||                      \
    defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) ||    \
    defined(__MIPSEL__) || defined(_MIPSEL) || defined(__MIPSEL) ||            \
    defined(_M_ARM) || defined(_M_ARM64) || defined(__e2k__) ||                \
    defined(__elbrus_4c__) || defined(__elbrus_8c__) || defined(__bfin__) ||   \
    defined(__BFIN__) || defined(__ia64__) || defined(_IA64) ||                \
    defined(__IA64__) || defined(__ia64) || defined(_M_IA64) ||                \
    defined(__itanium__) || defined(__ia32__) || defined(__CYGWIN__) ||        \
    defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__

#elif defined(__BIG_ENDIAN__) ||                                               \
    (defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)) ||                      \
    defined(__ARMEB__) || defined(__THUMBEB__) || defined(__AARCH64EB__) ||    \
    defined(__MIPSEB__) || defined(_MIPSEB) || defined(__MIPSEB) ||            \
    defined(__m68k__) || defined(M68000) || defined(__hppa__) ||               \
    defined(__hppa) || defined(__HPPA__) || defined(__sparc__) ||              \
    defined(__sparc) || defined(__370__) || defined(__THW_370__) ||            \
    defined(__s390__) || defined(__s390x__) || defined(__SYSC_ZARCH__)
#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__

#else
#error __BYTE_ORDER__ should be defined.
#endif /* Arch */

#endif
#endif /* __BYTE_ORDER__ || __ORDER_LITTLE_ENDIAN__ || __ORDER_BIG_ENDIAN__ */

/*****************************************************************************/

#ifndef __dll_export
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#if defined(__GNUC__) || __has_attribute(dllexport)
#define __dll_export __attribute__((dllexport))
#elif defined(_MSC_VER)
#define __dll_export __declspec(dllexport)
#else
#define __dll_export
#endif
#elif defined(__GNUC__) || __has_attribute(visibility)
#define __dll_export __attribute__((visibility("default")))
#else
#define __dll_export
#endif
#endif /* __dll_export */

#ifndef __dll_import
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#if defined(__GNUC__) || __has_attribute(dllimport)
#define __dll_import __attribute__((dllimport))
#elif defined(_MSC_VER)
#define __dll_import __declspec(dllimport)
#else
#define __dll_import
#endif
#else
#define __dll_import
#endif
#endif /* __dll_import */

#if defined(t1ha_EXPORTS)
#define T1HA_API __dll_export
#elif defined(t1ha_IMPORTS)
#define T1HA_API __dll_import
#else
#define T1HA_API
#endif /* T1HA_API */

#define T1HA_ALIGN_PREFIX
#define T1HA_ALIGN_SUFFIX

#ifdef __cplusplus
extern "C" {
#endif

typedef union T1HA_ALIGN_PREFIX t1ha_state256 {
  uint8_t bytes[32];
  uint32_t u32[8];
  uint64_t u64[4];
  struct {
    uint64_t a, b, c, d;
  } n;
} t1ha_state256_t T1HA_ALIGN_SUFFIX;

typedef struct t1ha_context {
  t1ha_state256_t state;
  t1ha_state256_t buffer;
  size_t partial;
  uint64_t total;
} t1ha_context_t;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

/******************************************************************************
 *
 *  t1ha2 = 64 and 128-bit, SLIGHTLY MORE ATTENTION FOR QUALITY AND STRENGTH.
 *
 *    - The recommended version of "Fast Positive Hash" with good quality
 *      for checksum, hash tables and fingerprinting.
 *    - Portable and extremely efficiency on modern 64-bit CPUs.
 *      Designed for 64-bit little-endian platforms,
 *      in other cases will runs slowly.
 *    - Great quality of hashing and still faster than other non-t1ha hashes.
 *      Provides streaming mode and 128-bit result.
 *
 * Note: Due performance reason 64- and 128-bit results are completely
 *       different each other, i.e. 64-bit result is NOT any part of 128-bit.
 */

/* The at-once variant with 64-bit result */
T1HA_API uint64_t t1ha2_atonce(const void *data, size_t length, uint64_t seed);

/* The at-once variant with 128-bit result.
 * Argument `extra_result` is NOT optional and MUST be valid.
 * The high 64-bit part of 128-bit hash will be always unconditionally
 * stored to the address given by `extra_result` argument. */
T1HA_API uint64_t t1ha2_atonce128(uint64_t *__restrict extra_result,
                                  const void *__restrict data, size_t length,
                                  uint64_t seed);

/* The init/update/final trinity for streaming.
 * Return 64 or 128-bit result depentently from `extra_result` argument. */
T1HA_API void t1ha2_init(t1ha_context_t *ctx, uint64_t seed_x, uint64_t seed_y);
T1HA_API void t1ha2_update(t1ha_context_t *__restrict ctx,
                           const void *__restrict data, size_t length);

/* Argument `extra_result` is optional and MAY be NULL.
 *  - If `extra_result` is NOT NULL then the 128-bit hash will be calculated,
 *    and high 64-bit part of it will be stored to the address given
 *    by `extra_result` argument.
 *  - Otherwise the 64-bit hash will be calculated
 *    and returned from function directly.
 *
 * Note: Due performance reason 64- and 128-bit results are completely
 *       different each other, i.e. 64-bit result is NOT any part of 128-bit. */
T1HA_API uint64_t t1ha2_final(t1ha_context_t *__restrict ctx,
                              uint64_t *__restrict extra_result /* optional */);

/******************************************************************************
 *
 *  t1ha1 = 64-bit, BASELINE FAST PORTABLE HASH:
 *
 *    - Runs faster on 64-bit platforms in other cases may runs slowly.
 *    - Portable and stable, returns same 64-bit result
 *      on all architectures and CPUs.
 *    - Unfortunately it fails the "strict avalanche criteria",
 *      see test results at https://github.com/demerphq/smhasher.
 *
 *      This flaw is insignificant for the t1ha1() purposes and imperceptible
 *      from a practical point of view.
 *      However, nowadays this issue has resolved in the next t1ha2(),
 *      that was initially planned to providing a bit more quality.
 */

/* The little-endian variant. */
T1HA_API uint64_t t1ha1_le(const void *data, size_t length, uint64_t seed);

/* The big-endian variant. */
T1HA_API uint64_t t1ha1_be(const void *data, size_t length, uint64_t seed);

/* The historical nicname for generic little-endian variant. */
static __inline uint64_t t1ha(const void *data, size_t length, uint64_t seed) {
  return t1ha1_le(data, length, seed);
}

#ifdef __cplusplus
}
#endif
