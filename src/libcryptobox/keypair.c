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

#include "config.h"
#include "libcryptobox/keypair.h"
#include "libcryptobox/keypair_private.h"
#include "libutil/str_util.h"
#include "libutil/printf.h"
#include "contrib/libottery/ottery.h"

const unsigned char encrypted_magic[7] = {'r', 'u', 'c', 'l', 'e', 'v', '1'};

static GQuark
rspamd_keypair_quark(void)
{
	return g_quark_from_static_string("rspamd-cryptobox-keypair");
}

/**
 * Returns specific private key for different keypair types
 */
static void *
rspamd_cryptobox_keypair_sk(struct rspamd_cryptobox_keypair *kp,
							unsigned int *len)
{
	g_assert(kp != NULL);

	if (kp->type == RSPAMD_KEYPAIR_KEX) {
		*len = 32;
		return RSPAMD_CRYPTOBOX_KEYPAIR_25519(kp)->sk;
	}
	else {
		*len = 64;
		return RSPAMD_CRYPTOBOX_KEYPAIR_SIG_25519(kp)->sk;
	}
}

static void *
rspamd_cryptobox_keypair_pk(struct rspamd_cryptobox_keypair *kp,
							unsigned int *len)
{
	g_assert(kp != NULL);

	if (kp->type == RSPAMD_KEYPAIR_KEX) {
		*len = 32;
		return RSPAMD_CRYPTOBOX_KEYPAIR_25519(kp)->pk;
	}
	else {
		*len = 32;
		return RSPAMD_CRYPTOBOX_KEYPAIR_SIG_25519(kp)->pk;
	}
}

static void *
rspamd_cryptobox_pubkey_pk(const struct rspamd_cryptobox_pubkey *kp,
						   unsigned int *len)
{
	g_assert(kp != NULL);

	if (kp->type == RSPAMD_KEYPAIR_KEX) {
		*len = 32;
		return RSPAMD_CRYPTOBOX_PUBKEY_25519(kp)->pk;
	}
	else {
		*len = 32;
		return RSPAMD_CRYPTOBOX_PUBKEY_SIG_25519(kp)->pk;
	}
}

static struct rspamd_cryptobox_keypair *
rspamd_cryptobox_keypair_alloc(enum rspamd_cryptobox_keypair_type type)
{
	struct rspamd_cryptobox_keypair *kp;
	unsigned int size = 0;

	if (type == RSPAMD_KEYPAIR_KEX) {
		size = sizeof(struct rspamd_cryptobox_keypair_25519);
	}
	else {
		size = sizeof(struct rspamd_cryptobox_keypair_sig_25519);
	}

	g_assert(size >= sizeof(*kp));

	if (posix_memalign((void **) &kp, 32, size) != 0) {
		abort();
	}

	memset(kp, 0, size);

	return kp;
}

static struct rspamd_cryptobox_pubkey *
rspamd_cryptobox_pubkey_alloc(enum rspamd_cryptobox_keypair_type type)
{
	struct rspamd_cryptobox_pubkey *pk;
	unsigned int size = 0;


	if (type == RSPAMD_KEYPAIR_KEX) {
		size = sizeof(struct rspamd_cryptobox_pubkey_25519);
	}
	else {
		size = sizeof(struct rspamd_cryptobox_pubkey_sig_25519);
	}

	g_assert(size >= sizeof(*pk));

	if (posix_memalign((void **) &pk, 32, size) != 0) {
		abort();
	}

	memset(pk, 0, size);

	return pk;
}


void rspamd_cryptobox_nm_dtor(struct rspamd_cryptobox_nm *nm)
{
	rspamd_explicit_memzero(nm->nm, sizeof(nm->nm));
	free(nm);
}

void rspamd_cryptobox_keypair_dtor(struct rspamd_cryptobox_keypair *kp)
{
	void *sk;
	unsigned int len = 0;

	sk = rspamd_cryptobox_keypair_sk(kp, &len);
	g_assert(sk != NULL && len > 0);
	rspamd_explicit_memzero(sk, len);

	if (kp->extensions) {
		ucl_object_unref(kp->extensions);
	}

	/* Not g_free as kp is aligned using posix_memalign */
	free(kp);
}

void rspamd_cryptobox_pubkey_dtor(struct rspamd_cryptobox_pubkey *p)
{
	if (p->nm) {
		REF_RELEASE(p->nm);
	}

	/* Not g_free as p is aligned using posix_memalign */
	free(p);
}

struct rspamd_cryptobox_keypair *
rspamd_keypair_new(enum rspamd_cryptobox_keypair_type type)
{
	struct rspamd_cryptobox_keypair *kp;
	void *pk, *sk;
	unsigned int size;

	kp = rspamd_cryptobox_keypair_alloc(type);
	kp->type = type;

	sk = rspamd_cryptobox_keypair_sk(kp, &size);
	pk = rspamd_cryptobox_keypair_pk(kp, &size);

	if (type == RSPAMD_KEYPAIR_KEX) {
		rspamd_cryptobox_keypair(pk, sk);
	}
	else {
		rspamd_cryptobox_keypair_sig(pk, sk);
	}

	rspamd_cryptobox_hash(kp->id, pk, size, NULL, 0);

	REF_INIT_RETAIN(kp, rspamd_cryptobox_keypair_dtor);

	return kp;
}


struct rspamd_cryptobox_keypair *
rspamd_keypair_ref(struct rspamd_cryptobox_keypair *kp)
{
	REF_RETAIN(kp);
	return kp;
}


void rspamd_keypair_unref(struct rspamd_cryptobox_keypair *kp)
{
	REF_RELEASE(kp);
}


struct rspamd_cryptobox_pubkey *
rspamd_pubkey_ref(struct rspamd_cryptobox_pubkey *kp)
{
	REF_RETAIN(kp);
	return kp;
}

void rspamd_pubkey_unref(struct rspamd_cryptobox_pubkey *kp)
{
	REF_RELEASE(kp);
}

enum rspamd_cryptobox_keypair_type
rspamd_keypair_type(struct rspamd_cryptobox_keypair *kp)
{
	g_assert(kp != NULL);

	return kp->type;
}

enum rspamd_cryptobox_keypair_type
rspamd_pubkey_type(struct rspamd_cryptobox_pubkey *p)
{
	g_assert(p != NULL);

	return p->type;
}


struct rspamd_cryptobox_pubkey *
rspamd_pubkey_from_base32(const char *b32,
						  gsize len,
						  enum rspamd_cryptobox_keypair_type type)
{
	unsigned char *decoded;
	gsize dlen, expected_len;
	unsigned int pklen;
	struct rspamd_cryptobox_pubkey *pk;
	unsigned char *pk_data;

	g_assert(b32 != NULL);

	if (len == 0) {
		len = strlen(b32);
	}

	decoded = rspamd_decode_base32(b32, len, &dlen, RSPAMD_BASE32_DEFAULT);

	if (decoded == NULL) {
		return NULL;
	}

	expected_len = (type == RSPAMD_KEYPAIR_KEX) ? crypto_box_PUBLICKEYBYTES : crypto_sign_PUBLICKEYBYTES;

	if (dlen != expected_len) {
		g_free(decoded);
		return NULL;
	}

	pk = rspamd_cryptobox_pubkey_alloc(type);
	REF_INIT_RETAIN(pk, rspamd_cryptobox_pubkey_dtor);
	pk->type = type;
	pk_data = rspamd_cryptobox_pubkey_pk(pk, &pklen);

	memcpy(pk_data, decoded, pklen);
	g_free(decoded);
	rspamd_cryptobox_hash(pk->id, pk_data, pklen, NULL, 0);

	return pk;
}

struct rspamd_cryptobox_pubkey *
rspamd_pubkey_from_hex(const char *hex,
					   gsize len,
					   enum rspamd_cryptobox_keypair_type type)
{
	unsigned char *decoded;
	gsize dlen, expected_len;
	unsigned int pklen;
	struct rspamd_cryptobox_pubkey *pk;
	unsigned char *pk_data;

	g_assert(hex != NULL);

	if (len == 0) {
		len = strlen(hex);
	}

	dlen = len / 2;

	decoded = rspamd_decode_hex(hex, len);

	if (decoded == NULL) {
		return NULL;
	}

	expected_len = (type == RSPAMD_KEYPAIR_KEX) ? crypto_box_PUBLICKEYBYTES : crypto_sign_PUBLICKEYBYTES;

	if (dlen != expected_len) {
		g_free(decoded);
		return NULL;
	}

	pk = rspamd_cryptobox_pubkey_alloc(type);
	REF_INIT_RETAIN(pk, rspamd_cryptobox_pubkey_dtor);
	pk->type = type;
	pk_data = rspamd_cryptobox_pubkey_pk(pk, &pklen);

	memcpy(pk_data, decoded, pklen);
	g_free(decoded);
	rspamd_cryptobox_hash(pk->id, pk_data, pklen, NULL, 0);

	return pk;
}

struct rspamd_cryptobox_pubkey *
rspamd_pubkey_from_bin(const unsigned char *raw,
					   gsize len,
					   enum rspamd_cryptobox_keypair_type type)
{
	gsize expected_len;
	unsigned int pklen;
	struct rspamd_cryptobox_pubkey *pk;
	unsigned char *pk_data;

	g_assert(raw != NULL && len > 0);

	(type == RSPAMD_KEYPAIR_KEX) ? crypto_box_PUBLICKEYBYTES : crypto_sign_PUBLICKEYBYTES;

	if (len != expected_len) {
		return NULL;
	}

	pk = rspamd_cryptobox_pubkey_alloc(type);
	REF_INIT_RETAIN(pk, rspamd_cryptobox_pubkey_dtor);
	pk->type = type;
	pk_data = rspamd_cryptobox_pubkey_pk(pk, &pklen);

	memcpy(pk_data, raw, pklen);
	rspamd_cryptobox_hash(pk->id, pk_data, pklen, NULL, 0);

	return pk;
}


const unsigned char *
rspamd_pubkey_get_nm(struct rspamd_cryptobox_pubkey *p,
					 struct rspamd_cryptobox_keypair *kp)
{
	g_assert(p != NULL);

	if (p->nm) {
		if (memcmp(kp->id, (const unsigned char *) &p->nm->sk_id, sizeof(uint64_t)) == 0) {
			return p->nm->nm;
		}

		/* Wrong ID, need to recalculate */
		REF_RELEASE(p->nm);
		p->nm = NULL;
	}

	return NULL;
}

const unsigned char *
rspamd_pubkey_calculate_nm(struct rspamd_cryptobox_pubkey *p,
						   struct rspamd_cryptobox_keypair *kp)
{
	g_assert(kp->type == p->type);
	g_assert(p->type == RSPAMD_KEYPAIR_KEX);

	if (p->nm == NULL) {
		if (posix_memalign((void **) &p->nm, 32, sizeof(*p->nm)) != 0) {
			abort();
		}

		memcpy(&p->nm->sk_id, kp->id, sizeof(uint64_t));
		REF_INIT_RETAIN(p->nm, rspamd_cryptobox_nm_dtor);
	}

	struct rspamd_cryptobox_pubkey_25519 *rk_25519 =
		RSPAMD_CRYPTOBOX_PUBKEY_25519(p);
	struct rspamd_cryptobox_keypair_25519 *sk_25519 =
		RSPAMD_CRYPTOBOX_KEYPAIR_25519(kp);

	rspamd_cryptobox_nm(p->nm->nm, rk_25519->pk, sk_25519->sk);

	return p->nm->nm;
}

const unsigned char *
rspamd_keypair_get_id(struct rspamd_cryptobox_keypair *kp)
{
	g_assert(kp != NULL);

	return kp->id;
}

const ucl_object_t *
rspamd_keypair_get_extensions(struct rspamd_cryptobox_keypair *kp)
{
	g_assert(kp != NULL);

	return kp->extensions;
}

const unsigned char *
rspamd_pubkey_get_id(struct rspamd_cryptobox_pubkey *pk)
{
	g_assert(pk != NULL);

	return pk->id;
}

const unsigned char *
rspamd_pubkey_get_pk(struct rspamd_cryptobox_pubkey *pk,
					 unsigned int *len)
{
	unsigned char *ret = NULL;
	unsigned int rlen;

	ret = rspamd_cryptobox_pubkey_pk(pk, &rlen);

	if (len) {
		*len = rlen;
	}

	return ret;
}

static void
rspamd_keypair_print_component(unsigned char *data, gsize datalen,
							   GString *res, unsigned int how, const char *description)
{
	int olen, b32_len;

	if (how & RSPAMD_KEYPAIR_HUMAN) {
		rspamd_printf_gstring(res, "%s: ", description);
	}

	if (how & RSPAMD_KEYPAIR_BASE32) {
		b32_len = (datalen * 8 / 5) + 2;
		g_string_set_size(res, res->len + b32_len);
		res->len -= b32_len;
		olen = rspamd_encode_base32_buf(data, datalen, res->str + res->len,
										res->len + b32_len - 1, RSPAMD_BASE32_DEFAULT);

		if (olen > 0) {
			res->len += olen;
			res->str[res->len] = '\0';
		}
	}
	else if (how & RSPAMD_KEYPAIR_HEX) {
		rspamd_printf_gstring(res, "%*xs", (int) datalen, data);
	}
	else {
		g_string_append_len(res, data, datalen);
	}

	if (how & RSPAMD_KEYPAIR_HUMAN) {
		g_string_append_c(res, '\n');
	}
}

GString *
rspamd_keypair_print(struct rspamd_cryptobox_keypair *kp, unsigned int how)
{
	GString *res;
	unsigned int len;
	gpointer p;

	g_assert(kp != NULL);

	res = g_string_sized_new(63);

	if ((how & RSPAMD_KEYPAIR_PUBKEY)) {
		p = rspamd_cryptobox_keypair_pk(kp, &len);
		rspamd_keypair_print_component(p, len, res, how, "Public key");
	}
	if ((how & RSPAMD_KEYPAIR_PRIVKEY)) {
		p = rspamd_cryptobox_keypair_sk(kp, &len);
		rspamd_keypair_print_component(p, len, res, how, "Private key");
	}
	if ((how & RSPAMD_KEYPAIR_ID_SHORT)) {
		rspamd_keypair_print_component(kp->id, RSPAMD_KEYPAIR_SHORT_ID_LEN,
									   res, how, "Short key ID");
	}
	if ((how & RSPAMD_KEYPAIR_ID)) {
		rspamd_keypair_print_component(kp->id, sizeof(kp->id), res, how, "Key ID");
	}

	return res;
}

GString *
rspamd_pubkey_print(struct rspamd_cryptobox_pubkey *pk, unsigned int how)
{
	GString *res;
	unsigned int len;
	gpointer p;

	g_assert(pk != NULL);

	res = g_string_sized_new(63);

	if ((how & RSPAMD_KEYPAIR_PUBKEY)) {
		p = rspamd_cryptobox_pubkey_pk(pk, &len);
		rspamd_keypair_print_component(p, len, res, how, "Public key");
	}
	if ((how & RSPAMD_KEYPAIR_ID_SHORT)) {
		rspamd_keypair_print_component(pk->id, RSPAMD_KEYPAIR_SHORT_ID_LEN,
									   res, how, "Short key ID");
	}
	if ((how & RSPAMD_KEYPAIR_ID)) {
		rspamd_keypair_print_component(pk->id, sizeof(pk->id), res, how,
									   "Key ID");
	}

	return res;
}

const unsigned char *
rspamd_keypair_component(struct rspamd_cryptobox_keypair *kp,
						 unsigned int ncomp, unsigned int *len)
{
	unsigned int rlen = 0;
	const unsigned char *ret = NULL;

	g_assert(kp != NULL);

	switch (ncomp) {
	case RSPAMD_KEYPAIR_COMPONENT_ID:
		rlen = sizeof(kp->id);
		ret = kp->id;
		break;
	case RSPAMD_KEYPAIR_COMPONENT_PK:
		ret = rspamd_cryptobox_keypair_pk(kp, &rlen);
		break;
	case RSPAMD_KEYPAIR_COMPONENT_SK:
		ret = rspamd_cryptobox_keypair_sk(kp, &rlen);
		break;
	}

	if (len) {
		*len = rlen;
	}

	return ret;
}

struct rspamd_cryptobox_keypair *
rspamd_keypair_from_ucl(const ucl_object_t *obj)
{
	const ucl_object_t *privkey, *pubkey, *elt;
	const char *str;
	enum rspamd_cryptobox_keypair_type type = RSPAMD_KEYPAIR_KEX;
	gboolean is_hex = FALSE;
	struct rspamd_cryptobox_keypair *kp;
	unsigned int len;
	gsize ucl_len;
	int dec_len;
	gpointer target;

	if (ucl_object_type(obj) != UCL_OBJECT) {
		return NULL;
	}

	elt = ucl_object_lookup(obj, "keypair");
	if (elt != NULL) {
		obj = elt;
	}

	pubkey = ucl_object_lookup_any(obj, "pubkey", "public", "public_key",
								   NULL);
	if (pubkey == NULL || ucl_object_type(pubkey) != UCL_STRING) {
		return NULL;
	}

	privkey = ucl_object_lookup_any(obj, "privkey", "private", "private_key",
									"secret", "secret_key", NULL);
	if (privkey == NULL || ucl_object_type(privkey) != UCL_STRING) {
		return NULL;
	}

	/* Optional fields */
	elt = ucl_object_lookup(obj, "type");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		str = ucl_object_tostring(elt);

		if (g_ascii_strcasecmp(str, "kex") == 0) {
			type = RSPAMD_KEYPAIR_KEX;
		}
		else if (g_ascii_strcasecmp(str, "sign") == 0) {
			type = RSPAMD_KEYPAIR_SIGN;
		}
		/* TODO: handle errors */
	}

	elt = ucl_object_lookup(obj, "encoding");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		str = ucl_object_tostring(elt);

		if (g_ascii_strcasecmp(str, "hex") == 0) {
			is_hex = TRUE;
		}
		/* TODO: handle errors */
	}

	kp = rspamd_cryptobox_keypair_alloc(type);
	kp->type = type;
	REF_INIT_RETAIN(kp, rspamd_cryptobox_keypair_dtor);
	g_assert(kp != NULL);

	target = rspamd_cryptobox_keypair_sk(kp, &len);
	str = ucl_object_tolstring(privkey, &ucl_len);

	if (is_hex) {
		dec_len = rspamd_decode_hex_buf(str, ucl_len, target, len);
	}
	else {
		dec_len = rspamd_decode_base32_buf(str, ucl_len, target, len, RSPAMD_BASE32_DEFAULT);
	}

	if (dec_len != (int) len) {
		rspamd_keypair_unref(kp);

		return NULL;
	}

	target = rspamd_cryptobox_keypair_pk(kp, &len);
	str = ucl_object_tolstring(pubkey, &ucl_len);

	if (is_hex) {
		dec_len = rspamd_decode_hex_buf(str, ucl_len, target, len);
	}
	else {
		dec_len = rspamd_decode_base32_buf(str, ucl_len, target, len, RSPAMD_BASE32_DEFAULT);
	}

	if (dec_len != (int) len) {
		rspamd_keypair_unref(kp);

		return NULL;
	}

	rspamd_cryptobox_hash(kp->id, target, len, NULL, 0);

	elt = ucl_object_lookup(obj, "extensions");
	if (elt && ucl_object_type(elt) == UCL_OBJECT) {
		/* Use copy to avoid issues with the refcounts */
		kp->extensions = ucl_object_copy(elt);
	}

	return kp;
}

ucl_object_t *
rspamd_keypair_to_ucl(struct rspamd_cryptobox_keypair *kp,
					  enum rspamd_keypair_dump_flags flags)
{
	ucl_object_t *ucl_out, *elt;
	int how = 0;
	GString *keypair_out;
	const char *encoding;

	g_assert(kp != NULL);

	if (flags & RSPAMD_KEYPAIR_DUMP_HEX) {
		how |= RSPAMD_KEYPAIR_HEX;
		encoding = "hex";
	}
	else {
		how |= RSPAMD_KEYPAIR_BASE32;
		encoding = "base32";
	}

	if (flags & RSPAMD_KEYPAIR_DUMP_FLATTENED) {
		ucl_out = ucl_object_typed_new(UCL_OBJECT);
		elt = ucl_out;
	}
	else {
		ucl_out = ucl_object_typed_new(UCL_OBJECT);
		elt = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(ucl_out, elt, "keypair", 0, false);
	}


	/* pubkey part */
	keypair_out = rspamd_keypair_print(kp,
									   RSPAMD_KEYPAIR_PUBKEY | how);
	ucl_object_insert_key(elt,
						  ucl_object_fromlstring(keypair_out->str, keypair_out->len),
						  "pubkey", 0, false);
	g_string_free(keypair_out, TRUE);

	if (!(flags & RSPAMD_KEYPAIR_DUMP_NO_SECRET)) {
		/* privkey part */
		keypair_out = rspamd_keypair_print(kp,
										   RSPAMD_KEYPAIR_PRIVKEY | how);
		ucl_object_insert_key(elt,
							  ucl_object_fromlstring(keypair_out->str, keypair_out->len),
							  "privkey", 0, false);
		g_string_free(keypair_out, TRUE);
	}

	keypair_out = rspamd_keypair_print(kp,
									   RSPAMD_KEYPAIR_ID | how);
	ucl_object_insert_key(elt,
						  ucl_object_fromlstring(keypair_out->str, keypair_out->len),
						  "id", 0, false);
	g_string_free(keypair_out, TRUE);

	ucl_object_insert_key(elt,
						  ucl_object_fromstring(encoding),
						  "encoding", 0, false);

	ucl_object_insert_key(elt,
						  ucl_object_fromstring("curve25519"),
						  "algorithm", 0, false);

	ucl_object_insert_key(elt,
						  ucl_object_fromstring(
							  kp->type == RSPAMD_KEYPAIR_KEX ? "kex" : "sign"),
						  "type", 0, false);

	if (kp->extensions) {
		ucl_object_insert_key(elt, ucl_object_copy(kp->extensions),
							  "extensions", 0, false);
	}

	return ucl_out;
}

gboolean
rspamd_keypair_decrypt(struct rspamd_cryptobox_keypair *kp,
					   const unsigned char *in, gsize inlen,
					   unsigned char **out, gsize *outlen,
					   GError **err)
{
	const unsigned char *nonce, *mac, *data, *pubkey;

	g_assert(kp != NULL);
	g_assert(in != NULL);

	if (kp->type != RSPAMD_KEYPAIR_KEX) {
		g_set_error(err, rspamd_keypair_quark(), EINVAL,
					"invalid keypair type");

		return FALSE;
	}

	if (inlen < sizeof(encrypted_magic) + crypto_box_publickeybytes() +
					crypto_box_macbytes() +
					crypto_box_noncebytes()) {
		g_set_error(err, rspamd_keypair_quark(), E2BIG, "invalid size: too small");

		return FALSE;
	}

	if (memcmp(in, encrypted_magic, sizeof(encrypted_magic)) != 0) {
		g_set_error(err, rspamd_keypair_quark(), EINVAL,
					"invalid magic");

		return FALSE;
	}

	/* Set pointers */
	pubkey = in + sizeof(encrypted_magic);
	mac = pubkey + crypto_box_publickeybytes();
	nonce = mac + crypto_box_macbytes();
	data = nonce + crypto_box_noncebytes();

	if (data - in >= inlen) {
		g_set_error(err, rspamd_keypair_quark(), E2BIG, "invalid size: too small");

		return FALSE;
	}

	inlen -= data - in;

	/* Allocate memory for output */
	*out = g_malloc(inlen);
	memcpy(*out, data, inlen);

	if (!rspamd_cryptobox_decrypt_inplace(*out, inlen, nonce, pubkey,
										  rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_SK, NULL),
										  mac)) {
		g_set_error(err, rspamd_keypair_quark(), EPERM, "verification failed");
		g_free(*out);

		return FALSE;
	}

	if (outlen) {
		*outlen = inlen;
	}

	return TRUE;
}

gboolean
rspamd_keypair_encrypt(struct rspamd_cryptobox_keypair *kp,
					   const unsigned char *in, gsize inlen,
					   unsigned char **out, gsize *outlen,
					   GError **err)
{
	unsigned char *nonce, *mac, *data, *pubkey;
	struct rspamd_cryptobox_keypair *local;
	gsize olen;

	g_assert(kp != NULL);
	g_assert(in != NULL);

	if (kp->type != RSPAMD_KEYPAIR_KEX) {
		g_set_error(err, rspamd_keypair_quark(), EINVAL,
					"invalid keypair type");

		return FALSE;
	}

	local = rspamd_keypair_new(kp->type);

	olen = inlen + sizeof(encrypted_magic) +
		   crypto_box_publickeybytes() +
		   crypto_box_macbytes() +
		   crypto_box_noncebytes();
	*out = g_malloc(olen);
	memcpy(*out, encrypted_magic, sizeof(encrypted_magic));
	pubkey = *out + sizeof(encrypted_magic);
	mac = pubkey + crypto_box_publickeybytes();
	nonce = mac + crypto_box_macbytes();
	data = nonce + crypto_box_noncebytes();

	ottery_rand_bytes(nonce, crypto_box_noncebytes());
	memcpy(data, in, inlen);
	memcpy(pubkey, rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_PK, NULL),
		   crypto_box_publickeybytes());
	rspamd_cryptobox_encrypt_inplace(data, inlen, nonce, pubkey,
									 rspamd_keypair_component(local, RSPAMD_KEYPAIR_COMPONENT_SK, NULL),
									 mac);
	rspamd_keypair_unref(local);

	if (outlen) {
		*outlen = olen;
	}

	return TRUE;
}

gboolean
rspamd_pubkey_encrypt(struct rspamd_cryptobox_pubkey *pk,
					  const unsigned char *in, gsize inlen,
					  unsigned char **out, gsize *outlen,
					  GError **err)
{
	unsigned char *nonce, *mac, *data, *pubkey;
	struct rspamd_cryptobox_keypair *local;
	gsize olen;

	g_assert(pk != NULL);
	g_assert(in != NULL);

	if (pk->type != RSPAMD_KEYPAIR_KEX) {
		g_set_error(err, rspamd_keypair_quark(), EINVAL,
					"invalid pubkey type");

		return FALSE;
	}

	local = rspamd_keypair_new(pk->type);

	olen = inlen + sizeof(encrypted_magic) +
		   crypto_box_publickeybytes() +
		   crypto_box_macbytes() +
		   crypto_box_noncebytes();
	*out = g_malloc(olen);
	memcpy(*out, encrypted_magic, sizeof(encrypted_magic));
	pubkey = *out + sizeof(encrypted_magic);
	mac = pubkey + crypto_box_publickeybytes();
	nonce = mac + crypto_box_macbytes();
	data = nonce + crypto_box_noncebytes();

	ottery_rand_bytes(nonce, crypto_box_noncebytes());
	memcpy(data, in, inlen);
	memcpy(pubkey, rspamd_pubkey_get_pk(pk, NULL),
		   crypto_box_publickeybytes());
	rspamd_cryptobox_encrypt_inplace(data, inlen, nonce, pubkey,
									 rspamd_keypair_component(local, RSPAMD_KEYPAIR_COMPONENT_SK, NULL),
									 mac);
	rspamd_keypair_unref(local);

	if (outlen) {
		*outlen = olen;
	}

	return TRUE;
}