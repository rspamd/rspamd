/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "cryptobox.h"
#include "base64.h"
#include "platform_config.h"
#include "str_util.h"
#include "contrib/libottery/ottery.h"

extern unsigned long cpu_config;
const uint8_t
base64_table_dec[256] =
{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
	 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 254, 255, 255,
	255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
	 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
	255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
	 41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
};

static const char base64_alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

typedef struct base64_impl {
	unsigned long cpu_flags;
	const char *desc;

	int (*decode) (const char *in, size_t inlen,
			unsigned char *out, size_t *outlen);
} base64_impl_t;

#define BASE64_DECLARE(ext) \
    int base64_decode_##ext(const char *in, size_t inlen, unsigned char *out, size_t *outlen);
#define BASE64_IMPL(cpuflags, desc, ext) \
    {(cpuflags), desc, base64_decode_##ext}

BASE64_DECLARE(ref);
#define BASE64_REF BASE64_IMPL(0, "ref", ref)

#ifdef RSPAMD_HAS_TARGET_ATTR
# if defined(HAVE_SSE42)
int base64_decode_sse42 (const char *in, size_t inlen,
		unsigned char *out, size_t *outlen) __attribute__((__target__("sse4.2")));

BASE64_DECLARE(sse42);
#  define BASE64_SSE42 BASE64_IMPL(CPUID_SSE42, "sse42", sse42)
# endif
#endif

#ifdef RSPAMD_HAS_TARGET_ATTR
# if defined(HAVE_AVX2)
int base64_decode_avx2 (const char *in, size_t inlen,
		unsigned char *out, size_t *outlen) __attribute__((__target__("avx2")));

BASE64_DECLARE(avx2);
#  define BASE64_AVX2 BASE64_IMPL(CPUID_AVX2, "avx2", avx2)
# endif
#endif

static const base64_impl_t base64_list[] = {
		BASE64_REF,
#ifdef BASE64_AVX2
		BASE64_AVX2,
#endif
#ifdef BASE64_SSE42
		BASE64_SSE42,
#endif
};

static const base64_impl_t *base64_opt = &base64_list[0];
static const base64_impl_t *base64_ref = &base64_list[0];

const char *
base64_load (void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS (base64_list); i++) {
			if (base64_list[i].cpu_flags & cpu_config) {
				base64_opt = &base64_list[i];
				break;
			}
		}
	}


	return base64_opt->desc;
}

gboolean
rspamd_cryptobox_base64_decode (const gchar *in, gsize inlen,
		guchar *out, gsize *outlen)
{
	if (inlen > 256) {
		/*
		 * For SIMD base64 decoding we need really large inputs with no
		 * garbadge such as newlines
		 * Otherwise, naive version is MUCH faster
		 */

		if (rspamd_memcspn (in, base64_alphabet, 256) == 256) {
			return base64_opt->decode (in, inlen, out, outlen);
		}
		else {
			/* Garbage found */
			return base64_ref->decode (in, inlen, out, outlen);
		}
	}
	else {
		/* Small input, use reference version */
		return base64_ref->decode (in, inlen, out, outlen);
	}

	g_assert_not_reached ();
}

size_t
base64_test (bool generic, size_t niters, size_t len)
{
	size_t cycles;
	guchar *in, *out, *tmp;
	const base64_impl_t *impl;
	gsize outlen;

	g_assert (len > 0);
	in = g_malloc (len);
	tmp = g_malloc (len);
	ottery_rand_bytes (in, len);

	impl = generic ? &base64_list[0] : base64_opt;

	out = rspamd_encode_base64 (in, len, 0, &outlen);
	impl->decode (out, outlen, tmp, &len);

	g_assert (memcmp (in, tmp, len) == 0);

	for (cycles = 0; cycles < niters; cycles ++) {
		impl->decode (out, outlen, in, &len);
	}

	g_free (in);
	g_free (tmp);
	g_free (out);

	return cycles;
}


gboolean
rspamd_cryptobox_base64_is_valid (const gchar *in, gsize inlen)
{
	const guchar *p, *end;

	if (inlen == 0) {
		return FALSE;
	}

	p = in;
	end = in + inlen;

	while (p < end && *p != '=') {
		if (!g_ascii_isspace (*p)) {
			if (base64_table_dec[*p] == 255) {
				return FALSE;
			}
		}
		p ++;
	}

	return TRUE;
}