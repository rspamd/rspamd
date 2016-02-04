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
#include "curve25519.h"
#include "platform_config.h"

extern unsigned long cpu_config;

typedef struct curve25519_impl_s {
	unsigned long cpu_flags;
	const char *desc;

	void (*scalarmult) (guint8 *mypublic,
			const guint8 *secret,
			const guint8 *basepoint);
	void (*scalarmult_base) (guint8 *mypublic,
				const guint8 *secret);
} curve25519_impl_t;

#define CURVE25519_DECLARE(ext) \
    void scalarmult_##ext(guint8 *mypublic, const guint8 *secret, const guint8 *basepoint); \
    void scalarmult_base_##ext(guint8 *mypublic, const guint8 *secret)

#define CURVE25519_IMPL(cpuflags, desc, ext) \
    {(cpuflags), desc, scalarmult_##ext, scalarmult_base_##ext}

#if defined(__LP64__)
#if defined(HAVE_AVX)
CURVE25519_DECLARE(avx);
#define CURVE25519_AVX CURVE25519_IMPL(CPUID_AVX, "avx", avx)
#endif

#endif

CURVE25519_DECLARE(ref);
#define CURVE25519_REF CURVE25519_IMPL(0, "ref", ref)

#if defined(CMAKE_ARCH_x86_64) || defined(CMAKE_ARCH_i386)
CURVE25519_DECLARE(donna);
#define CURVE25519_GENERIC CURVE25519_IMPL(0, "donna", donna)
#else
#define CURVE25519_GENERIC CURVE25519_REF
#endif


static const curve25519_impl_t curve25519_list[] = {
		CURVE25519_GENERIC,
#if defined(CURVE25519_AVX)
		CURVE25519_AVX,
#endif
};

const guchar secA[] = {0x5A, 0xC9, 0x9F, 0x33, 0x63, 0x2E, 0x5A, 0x76, 0x8D,
					   0xE7, 0xE8, 0x1B, 0xF8, 0x54, 0xC2, 0x7C, 0x46, 0xE3,
					   0xFB, 0xF2, 0xAB, 0xBA, 0xCD, 0x29, 0xEC, 0x4A, 0xFF,
					   0x51, 0x73, 0x69, 0xC6, 0x60};
const guchar secB[] = {0x47, 0xDC, 0x3D, 0x21, 0x41, 0x74, 0x82, 0x0E, 0x11,
					   0x54, 0xB4, 0x9B, 0xC6, 0xCD, 0xB2, 0xAB, 0xD4, 0x5E,
					   0xE9, 0x58, 0x17, 0x05, 0x5D, 0x25, 0x5A, 0xA3, 0x58,
					   0x31, 0xB7, 0x0D, 0x32, 0x60};

static const curve25519_impl_t *curve25519_opt = &curve25519_list[0];

static gboolean
curve25519_test_impl (const curve25519_impl_t *impl)
{
	guchar sec_local[32], sec_ref[32],
		pubA[32], pubB[32];

	curve25519_impl_t ref_impl = CURVE25519_REF;

	ref_impl.scalarmult (pubA, secA, curve25519_basepoint);
	ref_impl.scalarmult (pubB, secB, curve25519_basepoint);

	impl->scalarmult (sec_local, secA, pubB);
	ref_impl.scalarmult (sec_ref, secA, pubB);

	if (memcmp (sec_local, sec_ref, sizeof (sec_ref)) != 0) {
		return FALSE;
	}

	impl->scalarmult (sec_local, secB, pubA);
	ref_impl.scalarmult (sec_ref, secB, pubA);

	if (memcmp (sec_local, sec_ref, sizeof (sec_ref)) != 0) {
		return FALSE;
	}

	impl->scalarmult (sec_local, secB, pubA);
	impl->scalarmult (sec_ref, secA, pubB);

	if (memcmp (sec_local, sec_ref, sizeof (sec_ref)) != 0) {
		return FALSE;
	}

	return TRUE;
}

const char*
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

	g_assert (curve25519_test_impl (curve25519_opt));

	return curve25519_opt->desc;
}

int
curve25519 (guchar *mypublic,
		const guchar *secret,
		const guchar *basepoint)
{
	curve25519_opt->scalarmult (mypublic, secret, basepoint);

	return 0;
}

int
curve25519_base (guchar *mypublic, const guchar *secret)
{
	curve25519_opt->scalarmult_base (mypublic, secret);

	return 0;
}
