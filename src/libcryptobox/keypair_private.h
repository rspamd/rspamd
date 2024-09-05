/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef KEYPAIR_PRIVATE_H_
#define KEYPAIR_PRIVATE_H_

#include "config.h"
#include "ref.h"
#include "cryptobox.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
 * KEX cached data
 */
struct rspamd_cryptobox_nm {
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];
	uint64_t sk_id; /* Used to store secret key id */
	ref_entry_t ref;
};

/*
 * Generic keypair
 */
struct rspamd_cryptobox_keypair {
	unsigned char id[rspamd_cryptobox_HASHBYTES];
	enum rspamd_cryptobox_keypair_type type;
	ucl_object_t *extensions;
	ref_entry_t ref;
};

/*
 * Curve25519 ecdh keypair
 */
#define RSPAMD_CRYPTOBOX_KEYPAIR_25519(x) ((struct rspamd_cryptobox_keypair_25519 *) (x))
struct rspamd_cryptobox_keypair_25519 {
	struct rspamd_cryptobox_keypair parent;
	unsigned char sk[32];
	unsigned char pk[32];
};

/*
 * Ed25519 keypair
 */
#define RSPAMD_CRYPTOBOX_KEYPAIR_SIG_25519(x) ((struct rspamd_cryptobox_keypair_sig_25519 *) (x))
struct rspamd_cryptobox_keypair_sig_25519 {
	struct rspamd_cryptobox_keypair parent;
	unsigned char sk[64];
	unsigned char pk[32];
};

/*
 * Public component of the keypair
 */
struct rspamd_cryptobox_pubkey {
	unsigned char id[rspamd_cryptobox_HASHBYTES];
	struct rspamd_cryptobox_nm *nm;
	enum rspamd_cryptobox_keypair_type type;
	ref_entry_t ref;
};

/*
 * Public curve25519 ecdh
 */
#define RSPAMD_CRYPTOBOX_PUBKEY_25519(x) ((struct rspamd_cryptobox_pubkey_25519 *) (x))
struct rspamd_cryptobox_pubkey_25519 {
	struct rspamd_cryptobox_pubkey parent;
	unsigned char pk[32];
};

/*
 * Public ed25519
 */
#define RSPAMD_CRYPTOBOX_PUBKEY_SIG_25519(x) ((struct rspamd_cryptobox_pubkey_sig_25519 *) (x))
struct rspamd_cryptobox_pubkey_sig_25519 {
	struct rspamd_cryptobox_pubkey parent;
	unsigned char pk[32];
};

void rspamd_cryptobox_nm_dtor(struct rspamd_cryptobox_nm *nm);

void rspamd_cryptobox_keypair_dtor(struct rspamd_cryptobox_keypair *kp);

void rspamd_cryptobox_pubkey_dtor(struct rspamd_cryptobox_pubkey *p);

#ifdef __cplusplus
}
#endif

#endif /* KEYPAIR_PRIVATE_H_ */
