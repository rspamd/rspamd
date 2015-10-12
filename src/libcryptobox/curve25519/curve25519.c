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

#include "config.h"
#include "cryptobox.h"
#include "curve25519.h"
#include "platform_config.h"

extern unsigned long cpu_config;

typedef struct curve25519_impl_s {
	unsigned long cpu_flags;
	const char *desc;

	void (*scalarmult) (guint8 *mypublic,
			const guint8 *secret,
			const guint8 *basepoint);
} curve25519_impl_t;

#define CURVE25519_DECLARE(ext) \
    void scalarmult_##ext(guint8 *mypublic, const guint8 *secret, const guint8 *basepoint)

#define CURVE25519_IMPL(cpuflags, desc, ext) \
    {(cpuflags), desc, scalarmult_##ext}

#if defined(__LP64__)

#if defined(HAVE_AVX)
CURVE25519_DECLARE(avx);
#define CURVE25519_AVX CURVE25519_IMPL(CPUID_AVX, "avx", avx)
#endif

#endif

#if !defined(__LP64__)
CURVE25519_DECLARE(donna32);
#define CURVE25519_GENERIC CURVE25519_IMPL(0, "donna32", donna32)
#else
CURVE25519_DECLARE(donna64);
#define CURVE25519_GENERIC CURVE25519_IMPL(0, "donna64", donna64)
#endif

static const curve25519_impl_t curve25519_list[] = {
		CURVE25519_GENERIC,
#if defined(CURVE25519_AVX)
		CURVE25519_AVX,
#endif
};

static const curve25519_impl_t *curve25519_opt = &curve25519_list[0];

void
curve25519_load (void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS(curve25519_list); i++) {
			if (curve25519_list[i].cpu_flags & cpu_config) {
				curve25519_opt = &curve25519_list[i];
				break;
			}
		}
	}
}

int
curve25519 (guchar *mypublic,
		const guchar *secret,
		const guchar *basepoint)
{
	curve25519_opt->scalarmult (mypublic, secret, basepoint);

	return 0;
}

