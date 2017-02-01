/*
 *  Copyright (c) 2016 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2016 Leonid Yuriev <leo@yuriev.ru>,
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
 * t1ha = { Fast Positive Hash}
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but without penalties could runs on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others which are not use specific hardware tricks.
 *  3. Not suitable for cryptography.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#ifndef T1HA_INCLUDED
#define T1HA_INCLUDED
#include "config.h"
#include <string.h>
#include <stddef.h>

#ifndef __has_attribute
#define __has_attribute(x) (0)
#endif
#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#ifdef BYTE_ORDER
#ifndef __ORDER_LITTLE_ENDIAN__
#define __ORDER_LITTLE_ENDIAN__ LITTLE_ENDIAN
#endif
#ifndef __ORDER_BIG_ENDIAN__
#define __ORDER_BIG_ENDIAN__ BIG_ENDIAN
#endif
#ifndef __BYTE_ORDER__
#define __BYTE_ORDER__ BYTE_ORDER
#endif
#else
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) ||           \
		!defined(__ORDER_BIG_ENDIAN__)
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321
#if defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) ||                        \
		defined(__THUMBEL__) || defined(__AARCH64EL__) || defined(__MIPSEL__) ||   \
		defined(_MIPSEL) || defined(__MIPSEL) || defined(__i386) ||                \
		defined(__x86_64) || defined(_M_IX86) || defined(_M_X64) ||                \
		defined(i386) || defined(_X86_) || defined(__i386__) || defined(_X86_64_)
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) || \
		defined(__AARCH64EB__) || defined(__MIPSEB__) || defined(_MIPSEB) ||       \
		defined(__MIPSEB)
#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__
#else
#error __BYTE_ORDER__ should be defined.
#endif
#endif
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ &&                               \
		__BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#error Unsupported byte order.
#endif

#if !defined(UNALIGNED_OK)
#if defined(__i386) || defined(__x86_64) || defined(_M_IX86) ||                \
		defined(_M_X64) || defined(i386) || defined(_X86_) || defined(__i386__) || \
		defined(_X86_64_)
#define UNALIGNED_OK 1
#else
#define UNALIGNED_OK 0
#endif
#endif

#ifndef __GNUC_PREREQ
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define __GNUC_PREREQ(maj, min)                                                \
  ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define __GNUC_PREREQ(maj, min) 0
#endif
#endif


#if __GNUC_PREREQ(4, 4) || defined(__clang__)

#if defined(__i386__) || defined(__x86_64__)
#include <x86intrin.h>
#endif
#define likely(cond) __builtin_expect(!!(cond), 1)
#define unlikely(cond) __builtin_expect(!!(cond), 0)
# if __GNUC_PREREQ(4, 6) || defined(__clang__)
#define unreachable() __builtin_unreachable()
# else
#define unreachable()                                                          \
		do {                                                                   \
		for (;;)                                                               \
		;                                                                      \
		} while (0)
# endif
#define bswap64(v) __builtin_bswap64(v)
#define bswap32(v) __builtin_bswap32(v)
#if __GNUC_PREREQ(4, 8) || __has_builtin(__builtin_bswap16)
#define bswap16(v) __builtin_bswap16(v)
#endif
#if __GNUC_PREREQ(4, 3) || __has_attribute(unused)
#define maybe_unused __attribute__((unused))
#endif

#elif defined(_MSC_VER)

#include <intrin.h>
#include <stdlib.h>
#define likely(cond) (cond)
#define unlikely(cond) (cond)
#define unreachable() __assume(0)
#define bswap64(v) _byteswap_uint64(v)
#define bswap32(v) _byteswap_ulong(v)
#define bswap16(v) _byteswap_ushort(v)
#define rot64(v, s) _rotr64(v, s)
#define rot32(v, s) _rotr(v, s)

#if defined(_M_ARM64) || defined(_M_X64)
#pragma intrinsic(_umul128)
#define mul_64x64_128(a, b, ph) _umul128(a, b, ph)
#pragma intrinsic(__umulh)
#define mul_64x64_high(a, b) __umulh(a, b)
#endif

#if defined(_M_IX86)
#pragma intrinsic(__emulu)
#define mul_32x32_64(a, b) __emulu(a, b)
#elif defined(_M_ARM)
#define mul_32x32_64(a, b) _arm_umull(a, b)
#endif

#else /* Compiler */

#define likely(cond) (cond)
#define unlikely(cond) (cond)
#define unreachable()                                                          \
		do                                                                           \
		for (;;)                                                                   \
		;                                                                        \
		while (0)
#endif /* Compiler */

#ifndef bswap64
static __inline uint64_t bswap64(uint64_t v) {
	return v << 56 | v >> 56 | ((v << 40) & 0x00ff000000000000ull) |
			((v << 24) & 0x0000ff0000000000ull) |
			((v << 8) & 0x000000ff00000000ull) |
			((v >> 8) & 0x00000000ff000000ull) |
			((v >> 24) & 0x0000000000ff0000ull) |
			((v >> 40) & 0x000000000000ff00ull);
}
#endif /* bswap64 */

#ifndef bswap32
static __inline uint32_t bswap32(uint32_t v) {
	return v << 24 | v >> 24 | ((v << 8) & 0x00ff0000) | ((v >> 8) & 0x0000ff00);
}
#endif /* bswap32 */

#ifndef bswap16
static __inline uint16_t bswap16(uint16_t v) { return v << 8 | v >> 8; }
#endif /* bswap16 */

#ifndef rot64
static __inline uint64_t rot64(uint64_t v, unsigned s) {
	return (v >> s) | (v << (64 - s));
}
#endif /* rot64 */

#ifndef rot32
static __inline uint32_t rot32(uint32_t v, unsigned s) {
	return (v >> s) | (v << (32 - s));
}
#endif /* rot32 */

#ifndef mul_32x32_64
static __inline uint64_t mul_32x32_64(uint32_t a, uint32_t b) {
	return a * (uint64_t)b;
}
#endif /* mul_32x32_64 */

/***************************************************************************/

static __inline uint64_t fetch64(const void *v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return *(const uint64_t *)v;
#else
	return bswap64(*(const uint64_t *)v);
#endif
}

static __inline uint64_t fetch32(const void *v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return *(const uint32_t *)v;
#else
	return bswap32(*(const uint32_t *)v);
#endif
}

static __inline uint64_t fetch16(const void *v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return *(const uint16_t *)v;
#else
	return bswap16(*(const uint16_t *)v);
#endif
}

static __inline uint64_t fetch_tail(const void *v, size_t tail) {
	const uint8_t *_ = (const uint8_t *)v;
	switch (tail & 7) {
	case 1:
		return _[0];
	case 2:
		return fetch16(_);
	case 3:
		return fetch16(_) | (_[2] << 16);
	case 4:
		return fetch32(_);
	case 5:
		return fetch32(_) | ((uint64_t)_[4] << 32);
	case 6:
		return fetch32(_) | (fetch16(_ + 4) << 32);
	case 7:
		return fetch32(_) | (fetch16(_ + 4) << 32) | ((uint64_t)_[6] << 48);
	case 0:
		return fetch64(_);
	default:
		unreachable();
	}
}

/* xor-mul-xor mixer */
static __inline uint64_t mix(uint64_t v, uint64_t p) {
	static const unsigned s0 = 41;
	v *= p;
	return v ^ rot64(v, s0);
}

static __inline unsigned add_with_carry(uint64_t *sum, uint64_t addend) {
	*sum += addend;
	return *sum < addend;
}

/* xor high and low parts of full 128-bit product */
static __inline uint64_t mux64(uint64_t v, uint64_t p) {
#ifdef __SIZEOF_INT128__
	__uint128_t r = (__uint128_t)v * (__uint128_t)p;
	/* modern GCC could nicely optimize this */
	return r ^ (r >> 64);
#elif defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 128
	__uint128 r = (__uint128)v * (__uint128)p;
	return r ^ (r >> 64);
#elif defined(mul_64x64_128)
	uint64_t l, h;
	l = mul_64x64_128(v, p, &h);
	return l ^ h;
#elif defined(mul_64x64_high)
	uint64_t l, h;
	l = v * p;
	h = mul_64x64_high(v, p);
	return l ^ h;
#else
	/* performs 64x64 to 128 bit multiplication */
	uint64_t ll = mul_32x32_64((uint32_t)v, (uint32_t)p);
	uint64_t lh = mul_32x32_64(v >> 32, (uint32_t)p);
	uint64_t hl = mul_32x32_64(p >> 32, (uint32_t)v);
	uint64_t hh =
			mul_32x32_64(v >> 32, p >> 32) + (lh >> 32) + (hl >> 32) +
			/* Few simplification are possible here for 32-bit architectures,
			 * but thus we would lost compatibility with the original 64-bit
			 * version.  Think is very bad idea, because then 32-bit t1ha will
			 * still (relatively) very slowly and well yet not compatible. */
			add_with_carry(&ll, lh << 32) + add_with_carry(&ll, hl << 32);
	return hh ^ ll;
#endif
}

static uint64_t
t1ha(const void *data, size_t len, uint64_t seed)
{
	/* 'magic' primes */
	static const uint64_t p0 = 17048867929148541611ull;
	static const uint64_t p1 = 9386433910765580089ull;
	static const uint64_t p2 = 15343884574428479051ull;
	static const uint64_t p3 = 13662985319504319857ull;
	static const uint64_t p4 = 11242949449147999147ull;
	static const uint64_t p5 = 13862205317416547141ull;
	static const uint64_t p6 = 14653293970879851569ull;
	/* rotations */
	static const unsigned s0 = 41;
	static const unsigned s1 = 17;
	static const unsigned s2 = 31;

	uint64_t a = seed;
	uint64_t b = len;

	const int need_align = (((uintptr_t)data) & 7) != 0 && !UNALIGNED_OK;
	uint64_t align[4];

	if (unlikely(len > 32)) {
		uint64_t c = rot64(len, s1) + seed;
		uint64_t d = len ^ rot64(seed, s1);
		const void *detent = (const uint8_t *)data + len - 31;
		do {
			const uint64_t *v = (const uint64_t *)data;
			if (unlikely(need_align))
				v = (const uint64_t *)memcpy(&align, v, 32);

			uint64_t w0 = fetch64(v + 0);
			uint64_t w1 = fetch64(v + 1);
			uint64_t w2 = fetch64(v + 2);
			uint64_t w3 = fetch64(v + 3);

			uint64_t d02 = w0 ^ rot64(w2 + d, s1);
			uint64_t c13 = w1 ^ rot64(w3 + c, s1);
			c += a ^ rot64(w0, s0);
			d -= b ^ rot64(w1, s2);
			a ^= p1 * (d02 + w3);
			b ^= p0 * (c13 + w2);
			data = (const uint64_t *)data + 4;
		} while (likely(data < detent));

		a ^= p6 * (rot64(c, s1) + d);
		b ^= p5 * (c + rot64(d, s1));
		len &= 31;
	}

	const uint64_t *v = (const uint64_t *)data;
	if (unlikely(need_align) && len > 1)
		v = (const uint64_t *)memcpy(&align, v, len);

	switch (len) {
	default:
		b += mux64(fetch64(v++), p4);
	case 24:
	case 23:
	case 22:
	case 21:
	case 20:
	case 19:
	case 18:
	case 17:
		a += mux64(fetch64(v++), p3);
	case 16:
	case 15:
	case 14:
	case 13:
	case 12:
	case 11:
	case 10:
	case 9:
		b += mux64(fetch64(v++), p2);
	case 8:
	case 7:
	case 6:
	case 5:
	case 4:
	case 3:
	case 2:
	case 1:
		a += mux64(fetch_tail(v, len), p1);
	case 0:
		return mux64(rot64(a + b, s1), p4) + mix(a ^ b, p0);
	}
}

static __inline uint32_t tail32_le(const void *v, size_t tail) {
	const uint8_t *p = (const uint8_t *)v;
	uint32_t r = 0;
	switch (tail & 3) {
#if UNALIGNED_OK && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	/* For most CPUs this code is better when not needed
	 * copying for alignment or byte reordering. */
	case 0:
		return fetch32(p);
	case 3:
		r = (uint32_t)p[2] << 16;
	case 2:
		return r + fetch16(p);
	case 1:
		return p[0];
#else
	/* For most CPUs this code is better than a
	 * copying for alignment and/or byte reordering. */
	case 0:
		r += p[3];
		r <<= 8;
	case 3:
		r += p[2];
		r <<= 8;
	case 2:
		r += p[1];
		r <<= 8;
	case 1:
		return r + p[0];
#endif
	}
	unreachable();
}

static __inline uint32_t tail32_be(const void *v, size_t tail) {
	const uint8_t *p = (const uint8_t *)v;
	switch (tail & 3) {
#if UNALIGNED_OK && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/* For most CPUs this code is better when not needed
	 * copying for alignment or byte reordering. */
	case 1:
		return p[0];
	case 2:
		return fetch16_be(p);
	case 3:
		return fetch16_be(p) << 8 | p[2];
	case 0:
		return fetch32_be(p);
#else
	/* For most CPUs this code is better than a
	 * copying for alignment and/or byte reordering. */
	case 1:
		return p[0];
	case 2:
		return p[1] | (uint32_t)p[0] << 8;
	case 3:
		return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
	case 0:
		return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
				(uint32_t)p[0] << 24;
#endif
	}
	unreachable();
}

static __inline uint64_t remix32(uint32_t a, uint32_t b) {
	static const uint64_t p0 = 17048867929148541611ull;
	a ^= rot32(b, 13);
	uint64_t l = a | (uint64_t)b << 32;
	l *= p0;
	l ^= l >> 41;
	return l;
}

static __inline void mixup32(uint32_t *a, uint32_t *b, uint32_t v, uint32_t p) {
	uint64_t l = mul_32x32_64(*b + v, p);
	*a ^= (uint32_t)l;
	*b += (uint32_t)(l >> 32);
}

static uint64_t t1ha32(const void *data, size_t len, uint64_t seed) {
	/* 32-bit 'magic' primes */
	static const uint32_t q0 = 0x92D78269;
	static const uint32_t q1 = 0xCA9B4735;
	static const uint32_t q2 = 0xA4ABA1C3;
	static const uint32_t q3 = 0xF6499843;
	static const uint32_t q4 = 0x86F0FD61;
	static const uint32_t q5 = 0xCA2DA6FB;
	static const uint32_t q6 = 0xC4BB3575;
	/* rotations */
	static const unsigned s1 = 17;

	uint32_t a = rot32((uint32_t)len, s1) + (uint32_t)seed;
	uint32_t b = (uint32_t)len ^ (uint32_t)(seed >> 32);

	const int need_align = (((uintptr_t)data) & 3) != 0 && !UNALIGNED_OK;
	uint32_t align[4];

	if (unlikely(len > 16)) {
		uint32_t c = ~a;
		uint32_t d = rot32(b, 5);
		const void *detent = (const uint8_t *)data + len - 15;
		do {
			const uint32_t *v = (const uint32_t *)data;
			if (unlikely(need_align))
				v = (const uint32_t *)memcpy(&align, v, 16);

			uint32_t w0 = fetch32(v + 0);
			uint32_t w1 = fetch32(v + 1);
			uint32_t w2 = fetch32(v + 2);
			uint32_t w3 = fetch32(v + 3);

			uint32_t c02 = w0 ^ rot32(w2 + c, 11);
			uint32_t d13 = w1 + rot32(w3 + d, s1);
			c ^= rot32(b + w1, 7);
			d ^= rot32(a + w0, 3);
			b = q1 * (c02 + w3);
			a = q0 * (d13 ^ w2);

			data = (const uint32_t *)data + 4;
		} while (likely(data < detent));

		c += a;
		d += b;
		a ^= q6 * (rot32(c, 16) + d);
		b ^= q5 * (c + rot32(d, 16));

		len &= 15;
	}

	const uint8_t *v = (const uint8_t *)data;
	if (unlikely(need_align) && len > 4)
		v = (const uint8_t *)memcpy(&align, v, len);

	switch (len) {
	default:
		mixup32(&a, &b, fetch32(v), q4);
		v += 4;
	case 12:
	case 11:
	case 10:
	case 9:
		mixup32(&b, &a, fetch32(v), q3);
		v += 4;
	case 8:
	case 7:
	case 6:
	case 5:
		mixup32(&a, &b, fetch32(v), q2);
		v += 4;
	case 4:
	case 3:
	case 2:
	case 1:
		mixup32(&b, &a, tail32_le(v, len), q1);
	case 0:
		return remix32(a, b);
	}
}

#endif
