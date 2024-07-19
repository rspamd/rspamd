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

/* Detached unit tests for the cryptobox */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_CRYPTOBOX_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_CRYPTOBOX_HXX
#include "libcryptobox/cryptobox.h"

TEST_SUITE("rspamd_cryptobox")
{

	TEST_CASE("rspamd_cryptobox_keypair")
	{
		enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_NIST;
		rspamd_sk_t sk;
		rspamd_pk_t pk;

		rspamd_cryptobox_keypair(pk, sk, mode);
	}
/*
	TEST_CASE("rspamd_cryptobox_keypair_sig")
	{
		enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_NIST;
		rspamd_sig_sk_t sk;
		rspamd_sig_pk_t pk;

		rspamd_cryptobox_keypair_sig(pk, sk, mode);
	}
*/
	TEST_CASE("rspamd_cryptobox_hash")
	{
		rspamd_cryptobox_hash_state_t p;
		const unsigned char *key = reinterpret_cast<const unsigned char *>("key");
		gsize keylen = sizeof(key);

		memset(&p, 0, rspamd_cryptobox_HASHBYTES);

		rspamd_cryptobox_hash_init(&p, key, keylen);

		const unsigned char* data = reinterpret_cast<const unsigned char *>("data");
		gsize len = sizeof(data);

		rspamd_cryptobox_hash_update(&p, data, len);

		unsigned char out1[rspamd_cryptobox_HASHSTATEBYTES];

		rspamd_cryptobox_hash_final(&p, out1);

		unsigned char out2[rspamd_cryptobox_HASHSTATEBYTES];

		rspamd_cryptobox_hash(out2, data, len, key, keylen);
		CHECK(strcmp((char *)out1, (char *)out2) == 0);
	}

	TEST_CASE("rspamd_cryptobox_fast_hash")
	{
		rspamd_cryptobox_fast_hash_state_s *st = rspamd_cryptobox_fast_hash_new();

		uint64_t seed = 10;

		rspamd_cryptobox_fast_hash_init(st, seed);

		const unsigned char* data = reinterpret_cast<const unsigned char *>("data");
		gsize len = sizeof(data);

		rspamd_cryptobox_fast_hash_update(st, data, len);

		uint64_t out1 = rspamd_cryptobox_fast_hash_final(st);
		CHECK(out1 == 7343692543952389622);

		uint64_t out2 = rspamd_cryptobox_fast_hash(data, len, seed);
		CHECK(out1 == out2);

		rspamd_cryptobox_fast_hash_free(st);
	}

	TEST_CASE("rspamd_cryptobox_pbkdf")
	{
		const char *pass = "passpa";
		gsize pass_len = sizeof(pass);

		const uint8_t *salt = reinterpret_cast<const uint8_t *>("salt");
		gsize salt_len = sizeof(salt);

		uint8_t key1[256];
		gsize key_len1 = sizeof(key1);

		uint8_t key2[256];
		gsize key_len2 = sizeof(key2);

		unsigned int complexity = 10;
		enum rspamd_cryptobox_pbkdf_type type = RSPAMD_CRYPTOBOX_PBKDF2;


		CHECK(rspamd_cryptobox_pbkdf(pass, pass_len, salt, salt_len, key1, key_len1, complexity, type));
		CHECK(rspamd_cryptobox_pbkdf(pass, pass_len, salt, salt_len, key2, key_len2, complexity, type));
		CHECK(strcmp((char *)key1, (char *)key2) == 0);

		type = RSPAMD_CRYPTOBOX_CATENA;
		CHECK(rspamd_cryptobox_pbkdf(pass, pass_len, salt, salt_len, key1, key_len1, complexity, type));
		CHECK(rspamd_cryptobox_pbkdf(pass, pass_len, salt, salt_len, key2, key_len2, complexity, type));
		CHECK(strcmp((char *)key1, (char *)key2) == 0);
	}

/*
	TEST_CASE("rspamd_cryptobox_encrypt_inplace")
	{
		unsigned char* data = (unsigned char *) "data";
		gsize len = 5;
		rspamd_nonce_t nonce;
		rspamd_pk_t pk;
		rspamd_sk_t sk;
		rspamd_mac_t sig;
		enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_NIST;

		ottery_rand_bytes(nonce, sizeof(nonce));
		ottery_rand_bytes(pk, sizeof(pk));
		ottery_rand_bytes(sk, sizeof(sk));
		memset(sig, 0, sizeof(sig));

		rspamd_cryptobox_encrypt_inplace(data, len, nonce, pk, sk, sig, mode);
		MESSAGE(sig);
	}

	TEST_CASE("rspamd_cryptobox_decrypt_inplace")
	{
		unsigned char* data = (unsigned char *) "data";
		gsize len = 5;
		rspamd_nonce_t nonce;
		rspamd_pk_t pk;
		rspamd_sk_t sk;
		rspamd_mac_t sig;
		enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_NIST;

		ottery_rand_bytes(nonce, sizeof(nonce));
		ottery_rand_bytes(pk, sizeof(pk));
		ottery_rand_bytes(sk, sizeof(sk));
		memset(sig, 0, sizeof(sig));

		CHECK(rspamd_cryptobox_decrypt_inplace(data, len, nonce, pk, sk, sig, mode) == true)
	}

*/

	TEST_CASE("rspamd_cryptobox_sign")
	{
		enum rspamd_cryptobox_mode mode = RSPAMD_CRYPTOBOX_MODE_NIST;
		rspamd_sk_t sk;
		rspamd_pk_t pk;
		unsigned char sig[256];
		unsigned long long siglen;
		const unsigned char m[] = "data to be signed";
		size_t mlen = strlen((const char*)m);

		rspamd_cryptobox_keypair(pk, sk, mode);

		rspamd_cryptobox_sign(sig, &siglen, m, mlen, sk, mode);
		bool check_result = rspamd_cryptobox_verify(sig, siglen, m, mlen, pk, mode);
		CHECK(check_result == true);
	}

}

#endif