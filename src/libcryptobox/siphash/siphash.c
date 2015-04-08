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

#include "config.h"
#include "cryptobox.h"
#include "siphash.h"
#include "platform_config.h"

extern unsigned long cpu_config;

typedef struct siphash_impl_t
{
	unsigned long cpu_flags;
	const char *desc;

	void (*siphash)(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k);
} siphash_impl_t;

#define SIPHASH_DECLARE(ext) \
	void siphash_##ext(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k);

#define SIPHASH_IMPL(cpuflags, desc, ext) \
	{(cpuflags), desc, siphash_##ext}


SIPHASH_DECLARE(ref)
#define SIPHASH_GENERIC SIPHASH_IMPL(0, "generic", ref)

/* list implemenations from most optimized to least, with generic as the last entry */
static const siphash_impl_t siphash_list[] = {
		SIPHASH_GENERIC,
};

static const siphash_impl_t *siphash_opt = &siphash_list[0];

void
siphash_load(void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS(siphash_list); i++) {
			if (siphash_list[i].cpu_flags & cpu_config) {
				siphash_opt = &siphash_list[i];
				break;
			}
		}
	}
}

void siphash24 (unsigned char *out, const unsigned char *in,
		unsigned long long inlen, const unsigned char *k)
{
	siphash_opt->siphash (out, in, inlen, k);
}
