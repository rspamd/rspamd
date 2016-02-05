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
#include "keypair.h"
#include "keypair_private.h"

/**
 * Returns specific private key for different keypair types
 */
static void *
rspamd_cryptobox_keypair_sk (struct rspamd_cryptobox_keypair *kp,
		guint *len)
{
	g_assert (kp != NULL);

	if (kp->alg == RSPAMD_CRYPTOBOX_MODE_25519) {
		if (kp->type == RSPAMD_KEYPAIR_KEX) {
			*len = 32;
			return RSPAMD_CRYPTOBOX_KEYPAIR_25519(kp)->sk;
		}
		else {
			*len = 64;
			return RSPAMD_CRYPTOBOX_KEYPAIR_SIG_25519(kp)->sk;
		}
	}
	else {
		if (kp->type == RSPAMD_KEYPAIR_KEX) {
			*len = 32;
			return RSPAMD_CRYPTOBOX_KEYPAIR_NIST(kp)->sk;
		}
		else {
			*len = 32;
			return RSPAMD_CRYPTOBOX_KEYPAIR_SIG_NIST(kp)->sk;
		}
	}

	/* Not reached */
	return NULL;
}

static void *
rspamd_cryptobox_keypair_pk (struct rspamd_cryptobox_keypair *kp,
		guint *len)
{
	g_assert (kp != NULL);

	if (kp->alg == RSPAMD_CRYPTOBOX_MODE_25519) {
		if (kp->type == RSPAMD_KEYPAIR_KEX) {
			*len = 32;
			return RSPAMD_CRYPTOBOX_KEYPAIR_25519(kp)->pk;
		}
		else {
			*len = 32;
			return RSPAMD_CRYPTOBOX_KEYPAIR_SIG_25519(kp)->pk;
		}
	}
	else {
		if (kp->type == RSPAMD_KEYPAIR_KEX) {
			*len = 65;
			return RSPAMD_CRYPTOBOX_KEYPAIR_NIST(kp)->pk;
		}
		else {
			*len = 65;
			return RSPAMD_CRYPTOBOX_KEYPAIR_SIG_NIST(kp)->pk;
		}
	}

	/* Not reached */
	return NULL;
}

static struct rspamd_cryptobox_keypair *
rspamd_cryptobox_keypair_alloc (enum rspamd_cryptobox_keypair_type type,
		enum rspamd_cryptobox_mode alg)
{
	struct rspamd_cryptobox_keypair *kp;
	guint size = 0;

	if (alg == RSPAMD_CRYPTOBOX_MODE_25519) {
		if (type == RSPAMD_KEYPAIR_KEX) {
			size = sizeof (struct rspamd_cryptobox_keypair_25519);
		}
		else {
			size = sizeof (struct rspamd_cryptobox_keypair_sig_25519);
		}
	}
	else {
		if (type == RSPAMD_KEYPAIR_KEX) {
			size = sizeof (struct rspamd_cryptobox_keypair_nist);
		}
		else {
			size = sizeof (struct rspamd_cryptobox_keypair_sig_nist);
		}
	}

	g_assert (size >= sizeof (*kp));

	if (posix_memalign ((void **)&kp, 32, size) != 0) {
		abort ();
	}

	return kp;
}

void
rspamd_cryptobox_nm_dtor (struct rspamd_cryptobox_nm *nm)
{
	rspamd_explicit_memzero (nm->nm, sizeof (nm->nm));
	free (nm);
}

void
rspamd_cryptobox_keypair_dtor (struct rspamd_cryptobox_keypair *kp)
{
	void *sk;
	guint len = 0;

	sk = rspamd_cryptobox_keypair_sk (kp, &len);
	g_assert (sk != NULL && len > 0);
	rspamd_explicit_memzero (sk, len);
	/* Not g_free as kp is aligned using posix_memalign */
	free (kp);
}

void
rspamd_cryptobox_pubkey_dtor (struct rspamd_cryptobox_pubkey *p)
{
	if (p->nm) {
		REF_RELEASE (p->nm);
	}

	/* Not g_free as p is aligned using posix_memalign */
	free (p);
}

struct rspamd_cryptobox_keypair*
rspamd_keypair_new (enum rspamd_cryptobox_keypair_type type,
		enum rspamd_cryptobox_mode alg)
{
	struct rspamd_cryptobox_keypair *kp;
	void *pk, *sk;
	guint size;

	kp = rspamd_cryptobox_keypair_alloc (type, alg);

	sk = rspamd_cryptobox_keypair_sk (kp, &size);
	pk = rspamd_cryptobox_keypair_pk (kp, &size);

	if (type == RSPAMD_KEYPAIR_KEX) {
		rspamd_cryptobox_keypair (pk, sk, alg);
	}
	else {
		rspamd_cryptobox_keypair_sig (pk, sk, alg);
	}

	rspamd_cryptobox_hash (kp->id, pk, size, NULL, 0);
	kp->alg = alg;
	kp->type = type;

	REF_INIT_RETAIN (kp, rspamd_cryptobox_keypair_dtor);

	return pk;
}


struct rspamd_cryptobox_keypair*
rspamd_keypair_ref (struct rspamd_cryptobox_keypair *kp)
{
	REF_RETAIN (kp);
	return kp;
}


void
rspamd_keypair_unref (struct rspamd_cryptobox_keypair *kp)
{
	REF_RELEASE (kp);
}


struct rspamd_cryptobox_pubkey*
rspamd_pubkey_ref (struct rspamd_cryptobox_pubkey *kp)
{
	REF_RETAIN (kp);
	return kp;
}

void
rspamd_pubkey_unref (struct rspamd_cryptobox_pubkey *kp)
{
	REF_RELEASE (kp);
}
