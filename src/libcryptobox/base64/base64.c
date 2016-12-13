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

extern unsigned long cpu_config;

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

static const base64_impl_t base64_list[] = {
		BASE64_REF,
#if defined(BASE64_AVX2)
		BASE64_AVX2,
#endif
#if defined(BASE64_AVX)
		BASE64_AVX,
#endif
#if defined(BASE64_SSSE3)
		BASE64_SSSE3,
#endif
};

static const base64_impl_t *base64_opt = &base64_list[0];

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
	return base64_opt->decode (in, inlen, out, outlen);
}
