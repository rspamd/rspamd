/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ucl.h"
#include "ucl_internal.h"

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#elif defined(HAVE_SYS_ENDIAN_H)
#include <sys/endian.h>
#elif defined(HAVE_MACHINE_ENDIAN_H)
#include <machine/endian.h>
#endif

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
	#if __BYTE_ORDER == __LITTLE_ENDIAN
		#define __LITTLE_ENDIAN__
	#elif __BYTE_ORDER == __BIG_ENDIAN
		#define __BIG_ENDIAN__
	#elif _WIN32
		#define __LITTLE_ENDIAN__
	#endif
#endif

#define SWAP_LE_BE16(val)	((uint16_t) ( 		\
		(uint16_t) ((uint16_t) (val) >> 8) |	\
		(uint16_t) ((uint16_t) (val) << 8)))

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 4 && defined (__GNUC_MINOR__) && __GNUC_MINOR__ >= 3)
#	define SWAP_LE_BE32(val) ((uint32_t)__builtin_bswap32 ((uint32_t)(val)))
#	define SWAP_LE_BE64(val) ((uint64_t)__builtin_bswap64 ((uint64_t)(val)))
#else
	#define SWAP_LE_BE32(val)	((uint32_t)( \
		(((uint32_t)(val) & (uint32_t)0x000000ffU) << 24) | \
		(((uint32_t)(val) & (uint32_t)0x0000ff00U) <<  8) | \
		(((uint32_t)(val) & (uint32_t)0x00ff0000U) >>  8) | \
		(((uint32_t)(val) & (uint32_t)0xff000000U) >> 24)))

	#define SWAP_LE_BE64(val)	((uint64_t)( 			\
		  (((uint64_t)(val) &							\
		(uint64_t)(0x00000000000000ffULL)) << 56) |		\
		  (((uint64_t)(val) &							\
		(uint64_t)(0x000000000000ff00ULL)) << 40) |		\
		  (((uint64_t)(val) &							\
		(uint64_t)(0x0000000000ff0000ULL)) << 24) |		\
		  (((uint64_t)(val) &							\
		(uint64_t) (0x00000000ff000000ULL)) <<  8) |	\
		  (((uint64_t)(val) &							\
		(uint64_t)(0x000000ff00000000ULL)) >>  8) |		\
		  (((uint64_t)(val) &							\
		(uint64_t)(0x0000ff0000000000ULL)) >> 24) |		\
		  (((uint64_t)(val) &							\
		(uint64_t)(0x00ff000000000000ULL)) >> 40) |		\
		  (((uint64_t)(val) &							\
		(uint64_t)(0xff00000000000000ULL)) >> 56)))
#endif

#ifdef __LITTLE_ENDIAN__
#define TO_BE16 SWAP_LE_BE16
#define TO_BE32 SWAP_LE_BE32
#define TO_BE64 SWAP_LE_BE64
#else
#define TO_BE16(val) (uint16_t)(val)
#define TO_BE32(val) (uint32_t)(val)
#define TO_BE64(val) (uint64_t)(val)
#endif

void
ucl_emitter_print_int_msgpack (struct ucl_emitter_context *ctx, int64_t val)
{
	const struct ucl_emitter_functions *func = ctx->func;
	unsigned char buf[sizeof(uint64_t) + 1];
	const unsigned char mask_positive = 0x7f, mask_negative = 0xe0,
		uint8_ch = 0xcc, uint16_ch = 0xcd, uint32_ch = 0xce, uint64_ch = 0xcf,
		int8_ch = 0xd0, int16_ch = 0xd1, int32_ch = 0xd2, int64_ch = 0xd3;
	unsigned len;

	if (val >= 0) {
		if (val <= 0x7f) {
			/* Fixed num 7 bits */
			len = 1;
			buf[0] = mask_positive & val;
		}
		else if (val <= 0xff) {
			len = 2;
			buf[0] = uint8_ch;
			buf[1] = val & 0xff;
		}
		else if (val <= 0xffff) {
			uint16_t v = TO_BE16 (val);

			len = 3;
			buf[0] = uint16_ch;
			memcpy (&buf[1], &v, sizeof (v));
		}
		else if (val <= 0xffffffff) {
			uint32_t v = TO_BE32 (val);

			len = 5;
			buf[0] = uint32_ch;
			memcpy (&buf[1], &v, sizeof (v));
		}
		else {
			uint64_t v = TO_BE64 (val);

			len = 9;
			buf[0] = uint64_ch;
			memcpy (&buf[1], &v, sizeof (v));
		}
	}
	else {
		uint64_t uval;
		/* Bithack abs */
		uval = ((val ^ (val >> 63)) - (val >> 63));

		if (val >= -(1 << 5)) {
			len = 1;
			buf[0] = mask_negative | (uval & 0xff);
		}
		else if (uval <= 0xff) {
			len = 2;
			buf[0] = int8_ch;
			buf[1] = (unsigned char)val;
		}
		else if (uval <= 0xffff) {
			uint16_t v = TO_BE16 (val);

			len = 3;
			buf[0] = int16_ch;
			memcpy (&buf[1], &v, sizeof (v));
		}
		else if (uval <= 0xffffffff) {
			uint32_t v = TO_BE32 (val);

			len = 5;
			buf[0] = int32_ch;
			memcpy (&buf[1], &v, sizeof (v));
		}
		else {
			uint64_t v = TO_BE64 (val);

			len = 9;
			buf[0] = int64_ch;
			memcpy (&buf[1], &v, sizeof (v));
		}
	}

	func->ucl_emitter_append_len (buf, len, func->ud);
}

void
ucl_emitter_print_double_msgpack (struct ucl_emitter_context *ctx, double val)
{
	const struct ucl_emitter_functions *func = ctx->func;
	union {
		double d;
		uint64_t i;
	} u;
	const unsigned char dbl_ch = 0xcb;
	unsigned char buf[sizeof(double) + 1];

	/* Convert to big endian */
	u.d = val;
	u.i = TO_BE64 (u.i);

	buf[0] = dbl_ch;
	memcpy (&buf[1], &u.d, sizeof (double));
	func->ucl_emitter_append_len (buf, sizeof (buf), func->ud);
}

void
ucl_emitter_print_bool_msgpack (struct ucl_emitter_context *ctx, bool val)
{
	const struct ucl_emitter_functions *func = ctx->func;
	const unsigned char true_ch = 0xc3, false_ch = 0xc2;

	func->ucl_emitter_append_character (val ? true_ch : false_ch, 1, func->ud);
}

void
ucl_emitter_print_string_msgpack (struct ucl_emitter_context *ctx,
		const char *s, size_t len)
{
	const struct ucl_emitter_functions *func = ctx->func;
	const unsigned char fix_mask = 0xA0, l8_ch = 0xd9, l16_ch = 0xda, l32_ch = 0xdb;
	unsigned char buf[5];
	unsigned blen;

	if (len <= 0x1F) {
		blen = 1;
		buf[0] = (len | fix_mask) & 0xff;
	}
	else if (len <= 0xff) {
		blen = 2;
		buf[0] = l8_ch;
		buf[1] = len & 0xff;
	}
	else if (len <= 0xffff) {
		uint16_t bl = TO_BE16 (len);

		blen = 3;
		buf[0] = l16_ch;
		memcpy (&buf[1], &bl, sizeof (bl));
	}
	else {
		uint32_t bl = TO_BE32 (len);

		blen = 5;
		buf[0] = l32_ch;
		memcpy (&buf[1], &bl, sizeof (bl));
	}

	func->ucl_emitter_append_len (buf, blen, func->ud);
	func->ucl_emitter_append_len (s, len, func->ud);
}

void
ucl_emitter_print_null_msgpack (struct ucl_emitter_context *ctx)
{
	const struct ucl_emitter_functions *func = ctx->func;
	const unsigned char nil = 0xc0;

	func->ucl_emitter_append_character (nil, 1, func->ud);
}

void
ucl_emitter_print_key_msgpack (bool print_key, struct ucl_emitter_context *ctx,
		const ucl_object_t *obj)
{
	if (print_key) {
		ucl_emitter_print_string_msgpack (ctx, obj->key, obj->keylen);
	}
}

void
ucl_emitter_print_array_msgpack (struct ucl_emitter_context *ctx, size_t len)
{
	const struct ucl_emitter_functions *func = ctx->func;
	const unsigned char fix_mask = 0x90, l16_ch = 0xdc, l32_ch = 0xdd;
	unsigned char buf[5];
	unsigned blen;

	if (len <= 0xF) {
		blen = 1;
		buf[0] = (len | fix_mask) & 0xff;
	}
	else if (len <= 0xffff) {
		uint16_t bl = TO_BE16 (len);

		blen = 3;
		buf[0] = l16_ch;
		memcpy (&buf[1], &bl, sizeof (bl));
	}
	else {
		uint32_t bl = TO_BE32 (len);

		blen = 5;
		buf[0] = l32_ch;
		memcpy (&buf[1], &bl, sizeof (bl));
	}

	func->ucl_emitter_append_len (buf, blen, func->ud);
}

void
ucl_emitter_print_object_msgpack (struct ucl_emitter_context *ctx, size_t len)
{
	const struct ucl_emitter_functions *func = ctx->func;
	const unsigned char fix_mask = 0x80, l16_ch = 0xde, l32_ch = 0xdf;
	unsigned char buf[5];
	unsigned blen;

	if (len <= 0xF) {
		blen = 1;
		buf[0] = (len | fix_mask) & 0xff;
	}
	else if (len <= 0xffff) {
		uint16_t bl = TO_BE16 (len);

		blen = 3;
		buf[0] = l16_ch;
		memcpy (&buf[1], &bl, sizeof (bl));
	}
	else {
		uint32_t bl = TO_BE32 (len);

		blen = 5;
		buf[0] = l32_ch;
		memcpy (&buf[1], &bl, sizeof (bl));
	}

	func->ucl_emitter_append_len (buf, blen, func->ud);
}
