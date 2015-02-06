/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "cryptobox.h"
#include "platform_config.h"
#include "chacha20/chacha.h"
#include "poly1305/poly1305-donna.h"
#include "curve25519/curve25519.h"

unsigned long cpu_config = 0;

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_dummy_symbol_to_prevent_lto(void * const pnt, const size_t len)
{
	(void) pnt;
	(void) len;
}
#endif

void
rspamd_explicit_memzero(void * const pnt, const gsize len)
{
#if defined(HAVE_MEMSET_S)
	if (memset_s (pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
		g_assert (0);
	}
#elif defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero (pnt, len);
#elif defined(HAVE_WEAK_SYMBOLS)
	memset (pnt, 0, len);
	_dummy_symbol_to_prevent_lto (pnt, len);
#else
	volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
	gsize i = (gsize) 0U;
	while (i < len) {
		pnt_[i++] = 0U;
	}
#endif
}

static void
rspamd_cryptobox_cpuid (gint cpu[4], gint info)
{
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
	__asm__ __volatile__ (
			"cpuid":
			"=a" (cpu[0]),
			"=b" (cpu[1]),
			"=c" (cpu[2]),
			"=d" (cpu[3]) :
			"a" (info), "c" (0)
	);
#else
	memset (cpu, 0, sizeof (cpu));
#endif
}


void
rspamd_cryptobox_init (void)
{
	gint cpu[4], nid;

	rspamd_cryptobox_cpuid (cpu, 0);
	nid = cpu[0];

	if (nid > 1) {
		if ((cpu[3] & ((gint)1 << 26))) {
			cpu_config |= CPUID_SSE2;
		}
		if ((cpu[2] & ((gint)1 << 28))) {
			cpu_config |= CPUID_AVX;
		}
	}
	if (nid > 7) {
		rspamd_cryptobox_cpuid (cpu, 7);
		if ((cpu[1] & ((gint)1 <<  5))) {
			cpu_config |= CPUID_AVX2;
		}
	}

	chacha_load ();
}
