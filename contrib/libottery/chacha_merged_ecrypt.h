/* Definitions for types and macros used in chacha_merged.c.  Taken from
 * supercop.
 */

#include <limits.h>

typedef struct
{
  u32 input[16]; /* could be compressed */
  /*
   * [edit]
   *
   * Put here all state variable needed during the encryption process.
   */
} ECRYPT_ctx;
#if (UCHAR_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T char
#define U32C(v) (v##U)
#endif
#endif

#if (USHRT_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T short
#define U32C(v) (v##U)
#endif
#endif

#if (UINT_MAX / 0xFFFFU > 0xFFFFU)
#ifndef I32T
#define I32T int
#define U32C(v) (v##U)
#endif
#endif

#if (ULONG_MAX / 0xFFFFUL > 0xFFFFUL)
#ifndef I32T
#define I32T long
#define U32C(v) (v##UL)
#endif
#endif

#define U8C(v) (v ## U)
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))
#define U8V(v) ((u8)(v) & U8C(0xFF))

#if (defined(WIN32) && defined(_MSC_VER))
#include <stdlib.h>
#pragma intrinsic(_lrotl)     /* compile rotations "inline" */
#define ROTL32(v, n) _lrotl(v, n)
#else
#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))
#endif



#if ECRYPT_LITTLE_ENDIAN
#define U32TO32_LITTLE(v) (v)
#endif
#ifdef ECRYPT_BIG_ENDIAN
#define SWAP32(v) \
  ((ROTL32(v,  8) & U32C(0x00FF00FF)) | \
   (ROTL32(v, 24) & U32C(0xFF00FF00)))

#define U32TO32_LITTLE(v) SWAP32(v)
#endif

#ifdef U32TO32_LITTLE
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((u32*)(p))[0])
#define U32TO8_LITTLE(p, v) (((u32*)(p))[0] = U32TO32_LITTLE(v))
#else
#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))
#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)
#endif

/*
 * The LITTLE endian machines:
 */
#if defined(__ultrix)           /* Older MIPS */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__alpha)          /* Alpha */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(i386)             /* x86 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__i386)           /* x86 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__x86_64)         /* x86_64 (gcc) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(_M_IX86)          /* x86 (MSC, Borland) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(_MSC_VER)         /* x86 (surely MSC) */
#define ECRYPT_LITTLE_ENDIAN
#elif defined(__INTEL_COMPILER) /* x86 (surely Intel compiler icl.exe) */
#define ECRYPT_LITTLE_ENDIAN

/*
 * The BIG endian machines:
 */
#elif defined(__sparc)          /* Newer Sparc's */
#define ECRYPT_BIG_ENDIAN
#elif defined(__powerpc__)      /* PowerPC */
#define ECRYPT_BIG_ENDIAN
#elif defined(__ppc__)          /* PowerPC */
#define ECRYPT_BIG_ENDIAN
#elif defined(__hppa)           /* HP-PA */
#define ECRYPT_BIG_ENDIAN

/*
 * Finally machines with UNKNOWN endianness:
 */
#elif defined (_AIX)            /* RS6000 */
#define ECRYPT_UNKNOWN
#elif defined(__aux)            /* 68K */
#define ECRYPT_UNKNOWN
#elif defined(__dgux)           /* 88K (but P6 in latest boxes) */
#define ECRYPT_UNKNOWN
#elif defined(__sgi)            /* Newer MIPS */
#define ECRYPT_UNKNOWN
#else                           /* Any other processor */
#define ECRYPT_UNKNOWN
#endif
