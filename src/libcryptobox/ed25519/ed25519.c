/*
 * Copyright (c) 2016, Vsevolod Stakhov
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
#include "ed25519.h"
#include "platform_config.h"

extern unsigned long cpu_config;

typedef struct ed25519_impl_s {
	unsigned long cpu_flags;
	const char *desc;

	void (*keypair) (unsigned char *pk, unsigned char *sk);
	void (*sign) (unsigned char *sig, unsigned long long *siglen_p,
			const unsigned char *m, unsigned long long mlen,
			const unsigned char *sk);
	bool (*verify) (const unsigned char *sig,
			const unsigned char *m,
			unsigned long long mlen,
			const unsigned char *pk);
} ed25519_impl_t;

#define ED25519_DECLARE(ext) \
    void ed_keypair_##ext(unsigned char *pk, unsigned char *sk); \
    void ed_sign_##ext(unsigned char *sig, unsigned long long *siglen_p, \
        const unsigned char *m, unsigned long long mlen, \
        const unsigned char *sk); \
    bool ed_verify_##ext(const unsigned char *sig, \
        const unsigned char *m, \
        unsigned long long mlen, \
        const unsigned char *pk)

#define ED25519_IMPL(cpuflags, desc, ext) \
    {(cpuflags), desc, ed_keypair_##ext, ed_sign_##ext, ed_verify_##ext}

ED25519_DECLARE(ref);
#define ED25519_REF ED25519_IMPL(0, "ref", ref)

static const ed25519_impl_t ed25519_list[] = {
		ED25519_REF,
};

static const ed25519_impl_t *ed25519_opt = &ed25519_list[0];

const char*
ed25519_load (void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS(ed25519_list); i++) {
			if (ed25519_list[i].cpu_flags & cpu_config) {
				ed25519_opt = &ed25519_list[i];
				break;
			}
		}
	}


	return ed25519_opt->desc;
}

void
ed25519_keypair (unsigned char *pk, unsigned char *sk)
{
	ed25519_opt->keypair (pk, sk);
}

void
ed25519_sign (unsigned char *sig, unsigned long long *siglen_p,
		const unsigned char *m, unsigned long long mlen,
		const unsigned char *sk)
{
	ed25519_opt->sign (sig, siglen_p, m, mlen, sk);
}

bool
ed25519_verify (const unsigned char *sig,
		const unsigned char *m,
		unsigned long long mlen,
		const unsigned char *pk)
{
	return ed25519_opt->verify (sig, m, mlen, pk);
}
