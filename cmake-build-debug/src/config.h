#ifndef RSPAMD_CONFIG_H_IN
#define RSPAMD_CONFIG_H_IN


/* #undef BUILD_STATIC */
/* #undef CURL_FOUND */
/* #undef DEBUG_MODE */
/* #undef GIT_VERSION */
/* #undef GLIB_HASH_COMPAT */
/* #undef GLIB_RE_COMPAT */
/* #undef GLIB_UNISCRIPT_COMPAT */
#define HAVE_ARPA_INET_H    1
#define HAVE_ATOMIC_BUILTINS 1
#define HAVE_CLOCK_GETCPUCLOCKID 1
#define HAVE_CLOCK_GETTIME  1
#define HAVE_CLOCK_PROCESS_CPUTIME_ID  1
/* #undef HAVE_CLOCK_VIRTUAL */
#define HAVE_CPUID_H        1
#define HAVE_CTYPE_H        1
#define HAVE_DIRENT_H       1
#define HAVE_DIRFD          1
#define HAVE_ENDIAN_H       1
/* #undef HAVE_FALLOCATE */
#define HAVE_FCNTL_H        1
/* #undef HAVE_FETCH_H */
/* #undef HAVE_FIPS_MODE */
#define HAVE_FFSLL          1
#define HAVE_FLOCK          1
#define HAVE_FPATHCONF      1
#define HAVE_GETPAGESIZE    1
#define HAVE_GLOB_H         1
#define HAVE_GRP_H          1
#define HAVE_INTTYPES_H     1
#define HAVE_IPV6_V6ONLY    1
#define HAVE_LIBGEN_H       1
/* #undef HAVE_LIBUTIL_H */
#define HAVE_LOCALE_H       1
/* #undef HAVE_MACHINE_ENDIAN_H */
#define HAVE_MAXPATHLEN     1
#define HAVE_FMEMOPEN       1
/* #undef HAVE_MEMRCHR */
#define HAVE_MKSTEMP        1
#define HAVE_MMAP_ANON      1
#define HAVE_NANOSLEEP      1
#define HAVE_NETDB_H        1
#define HAVE_NETINET_IN_H   1
#define HAVE_NETINET_TCP_H  1
/* #undef HAVE_NFTW */
#define HAVE_OCLOEXEC       1
#define HAVE_ONOFOLLOW      1
#define HAVE_OPENMEMSTREAM  1
#define HAVE_PATH_MAX       1

/* OSX has broken JIT support in PCRE, disable it */
#define HAVE_PCRE_JIT       1
#define HAVE_PCRE_JIT_FAST  1

/* #undef HAVE_PIDFILE */
/* #undef HAVE_PIDFILE_FILENO */
#define HAVE_POLL_H         1
#define HAVE_POSIX_FALLOCATE 1
#define HAVE_PTHREAD_PROCESS_SHARED 1
#define HAVE_PWD_H          1
#define HAVE_RDTSC          1
#define HAVE_READAHEAD      1
/* #undef HAVE_READPASSPHRASE_H */
#define HAVE_RECVMMSG       1
#define HAVE_RUSAGE_SELF    1
#define HAVE_SA_SIGINFO     1
#define HAVE_SANE_SHMEM     1
#define HAVE_SCHED_YIELD    1
#define HAVE_SC_NPROCESSORS_ONLN 1
/* #undef HAVE_SETPROCTITLE */
#define HAVE_SIGALTSTACK    1
/* #undef HAVE_SIGINFO_H */
#define HAVE_SOCK_SEQPACKET 1
#define HAVE_SSL_TLSEXT_HOSTNAME 1
#define HAVE_STDBOOL_H      1
#define HAVE_STDINT_H       1
#define HAVE_STDIO_H        1
#define HAVE_STDLIB_H       1
#define HAVE_STRINGS_H      1
#define HAVE_STRING_H       1
#define HAVE_SYSLOG_H       1
/* #undef HAVE_SYS_CDEFS_H */
/* #undef HAVE_SYS_ENDIAN_H */
#define HAVE_SYS_EVENTFD_H  1
#define HAVE_SYS_FILE_H     1
#define HAVE_SYS_MMAN_H     1
#define HAVE_SYS_PARAM_H    1
#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYS_SOCKET_H   1
#define HAVE_SYS_STAT_H     1
/* #undef HAVE_SYS_TIMEB_H */
#define HAVE_SYS_TYPES_H    1
#define HAVE_SYS_UCONTEXT_H 1
#define HAVE_SYS_UIO_H      1
#define HAVE_SYS_UN_H       1
#define HAVE_SYS_WAIT_H     1
#define HAVE_TANH           1
#define HAVE_TERMIOS_H      1
#define HAVE_TIME_H         1
#define HAVE_UCONTEXT_H     1
#define HAVE_UNISTD_H       1
#define PARAM_H_HAS_BITSET  1
/* #undef WITH_GPERF_TOOLS */
/* #undef WITH_HYPERSCAN */
/* #undef WITH_JEMALLOC */
/* #undef WITH_LUA */
#define WITH_LUAJIT         1
#define WITH_PCRE2          1
#define WITH_SNOWBALL       1
/* #undef WITH_SQLITE */
/* #undef WITH_LUA_TRACE */
#define WITH_LUA_REPL       1
/* #undef WITH_FASTTEXT */
#define BACKWARD_ENABLE     1

/* #undef DISABLE_PTHREAD_MUTEX */

/* Detect endianness */

#ifdef HAVE_ENDIAN_H
 #include <endian.h>
#elif defined(HAVE_SYS_ENDIAN_H)
 #include <sys/endian.h>
#elif defined(HAVE_MACHINE_ENDIAN_H)
 #include <machine/endian.h>
#elif defined(__sun)
 #include <sys/byteorder.h>
 #ifndef LITTLE_ENDIAN
 #define LITTLE_ENDIAN   1234
 #endif
 #ifndef BIG_ENDIAN
 #define BIG_ENDIAN      4321
 #endif
 #ifdef _LITTLE_ENDIAN
  #define BYTE_ORDER LITTLE_ENDIAN
 #else
  #define BYTE_ORDER BIG_ENDIAN
 #endif
#endif

#ifndef BYTE_ORDER

#ifndef LITTLE_ENDIAN
 #define LITTLE_ENDIAN   1234
#endif
#ifndef BIG_ENDIAN
 #define BIG_ENDIAN      4321
#endif

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
    defined(__BIG_ENDIAN__) || \
    defined(__ARMEB__) || \
    defined(__THUMBEB__) || \
    defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
#define BYTE_ORDER BIG_ENDIAN
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
    defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || \
    defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
#define BYTE_ORDER LITTLE_ENDIAN
#else
#error "I don't know what architecture this is!"
#endif

#endif /* BYTE_ORDER */

#define RSPAMD_SHAREDIR "/usr/local/share/rspamd"
#define RSPAMD_CONFDIR "/usr/local/etc/rspamd"
#define RSPAMD_LOCAL_CONFDIR "/usr/local/etc/rspamd"
#define RSPAMD_RUNDIR "/var/run/rspamd"
#define RSPAMD_LOGDIR "/var/log/rspamd"
#define RSPAMD_DBDIR "/var/lib/rspamd"
#define RSPAMD_PLUGINSDIR "/usr/local/share/rspamd/plugins"
#define RSPAMD_LUALIBDIR "/usr/local/share/rspamd/lualib"
#define RSPAMD_RULESDIR "/usr/local/share/rspamd/rules"
#define RSPAMD_WWWDIR "/usr/local/share/rspamd/www"
#define RSPAMD_PREFIX "/usr/local"
#define RSPAMD_LIBDIR "/usr/local/lib/rspamd"

#define RSPAMD_VERSION_MAJOR "3"
#define RSPAMD_VERSION_MINOR "9"
#define RSPAMD_VERSION_PATCH "0"

#define RSPAMD_VERSION_MAJOR_NUM 30
#define RSPAMD_VERSION_MINOR_NUM 90
#define RSPAMD_VERSION_PATCH_NUM 00

#define RSPAMD_VERSION_BRANCH "3"

#if defined(GIT_VERSION) && GIT_VERSION == 1
# define RVERSION         "3.9.0"
# define RSPAMD_VERSION_FULL         "3.9.0_"
# define RID              ""
# define RSPAMD_VERSION_NUM 0x309000ULL
#else
# define RSPAMD_VERSION_FULL         "3.9.0"
# define RVERSION          "3.9.0"
# define RSPAMD_VERSION_NUM 0x3090000000000ULL
# define RID "release"
#endif

#define RSPAMD_MASTER_SITE_URL "https://rspamd.com"

#define MODULES_NUM        

/* sys/types */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/* cdefs */
#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

/* sys/param */
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

/* stdint */
#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif

/* stdbool */
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif

/* stdlib */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

/* stdio */
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

/* time */
#ifdef HAVE_TIME_H
#include <time.h>
#endif

/* string */
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <errno.h>

#include <glib.h>
#include <gmodule.h>

#ifndef PARAM_H_HAS_BITSET
/* Bit map related macros. */
#ifndef NBBY
# define NBBY    8               /* number of bits in a byte */
#endif
#define setbit(a, \
		i)     (((unsigned char *)(a))[(i) / NBBY] |= 1 << ((i) % NBBY))
#define clrbit(a, \
		i)     (((unsigned char *)(a))[(i) / NBBY] &= ~(1 << ((i) % NBBY)))
#define isset(a,i)                                                      \
	(((const unsigned char *)(a))[(i) / NBBY] & (1 << ((i) % NBBY)))
#define isclr(a,i)                                                      \
	((((const unsigned char *)(a))[(i) / NBBY] & (1 << ((i) % NBBY))) == 0)
#endif

#ifdef _MSC_VER
# define RSPAMD_PACKED(name) \
    __pragma(pack(push, 1)) struct name __pragma(pack(pop))
#elif defined(__GNUC__)
# define RSPAMD_PACKED(name) struct __attribute__((packed)) name
#else
# define RSPAMD_PACKED(name) struct name
#endif

#ifndef RSPAMD_ALIGNED
#if defined(_MSC_VER)
# define RSPAMD_ALIGNED(x) __declspec(align(x))
# define RSPAMD_OPTIMIZE(x)
# define RSPAMD_ALWAYS_INLINE
# define RSPAMD_PURE_FUNCTION
#elif defined(__GNUC__)
# define RSPAMD_ALIGNED(x) __attribute__((aligned(x)))
# define RSPAMD_ALWAYS_INLINE __attribute__((always_inline))
# define RSPAMD_PURE_FUNCTION __attribute__((pure))
#ifndef __clang__
# define RSPAMD_OPTIMIZE(x) __attribute__((__optimize__ (x)))
#else
# define RSPAMD_OPTIMIZE(x)
#endif
#else
/* Unknown compiler */
# define RSPAMD_ALIGNED(x)
# define RSPAMD_OPTIMIZE(x)
# define RSPAMD_ALWAYS_INLINE
# define RSPAMD_PURE_FUNCTION
#endif
#endif

#ifndef __cplusplus
# ifdef G_ALIGNOF
#  define RSPAMD_ALIGNOF G_ALIGNOF
# else
#  define RSPAMD_ALIGNOF(t) _Alignof(t)
# endif
#else
/* glib G_ALIGNOF nor C11 _Alignof are not good enough for C++, nuff said... */
# define RSPAMD_ALIGNOF(t) alignof(t)
#endif

/* Address sanitizer */
#ifdef __clang__
#  if __has_feature(address_sanitizer)
/* emulate gcc's __SANITIZE_ADDRESS__ flag */
#    define __SANITIZE_ADDRESS__
#    define RSPAMD_NO_SANITIZE \
      __attribute__((no_sanitize("address", "hwaddress")))
#  else
#    define RSPAMD_NO_SANITIZE
#  endif
#elif defined(__GNUC__)
/* GCC based */
#  if defined(__has_attribute)
#    if __has_attribute(__no_sanitize_address__)
#      define RSPAMD_NO_SANITIZE __attribute__((no_sanitize_address))
#    else
#      define RSPAMD_NO_SANITIZE
#    endif
#  else
#    define RSPAMD_NO_SANITIZE
#  endif
#else
#  define RSPAMD_NO_SANITIZE
#endif


#ifndef BITSPERBYTE
# define BITSPERBYTE (NBBY * sizeof (char))
#endif
#ifndef NBYTES
# define NBYTES(nbits)   (((nbits) + BITSPERBYTE - 1) / BITSPERBYTE)
#endif


#ifdef  __cplusplus
extern "C" {
#endif
extern uint64_t ottery_rand_uint64(void);
#define UCL_RANDOM_FUNCTION ottery_rand_uint64()
#ifdef  __cplusplus
}
#endif


/* Disable slab allocator if jemalloc is already in the system */
#if defined(WITH_JEMALLOC) || defined(__FreeBSD__) || \
	(defined(__NetBSD__) && __NetBSD_Version__ >= 500000000)
#if 0
	#define g_slice_alloc(sz) g_malloc(sz)
	#define g_slice_alloc0(sz) g_malloc0(sz)
	#define g_slice_free1(sz, p) g_free(p)
#endif
#endif

#ifdef __cplusplus
  #define RSPAMD_CONSTRUCTOR(f) \
        static void f(void) noexcept; \
        struct f##_t_ { f##_t_(void) noexcept { f(); } }; static f##_t_ f##_; \
        static void f(void) noexcept
#else
#if  __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
  #define RSPAMD_CONSTRUCTOR(f) \
          static void f(void) __attribute__((constructor)); \
          static void f(void)
  #define RSPAMD_DESTRUCTOR(f) \
          static void f(void) __attribute__((destructor)); \
          static void f(void)
#else
  /* In fact, everything else is not supported ¯\_(ツ)_/¯ */
  #error incompatible compiler found, need gcc > 2.7 or clang
#endif
#endif /* __cplusplus */

#ifdef __GNUC__
#define RSPAMD_CONST_FUNCTION __attribute__ ((const))
#else
#define RSPAMD_CONST_FUNCTION
#endif

#ifdef __GNUC__
#define RSPAMD_UNREACHABLE __builtin_unreachable()
#else
#define RSPAMD_UNREACHABLE abort()
#endif

#define HAVE_OPENSSL             1
#define HAVE_MATH_H              1


#endif
