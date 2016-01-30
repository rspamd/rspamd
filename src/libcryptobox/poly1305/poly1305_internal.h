#if defined(_MSC_VER)
	#include <intrin.h>

	typedef struct uint128_t {
		unsigned long long lo;
		unsigned long long hi;
	} uint128_t;

	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#pragma GCC system_header
	#if defined(__SIZEOF_INT128__)
		typedef unsigned __int128 uint128_t;
	#else
		typedef unsigned uint128_t __attribute__((mode(TI)));
	#endif

	#define POLY1305_NOINLINE __attribute__((noinline))
#endif
