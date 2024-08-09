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
#include <string>
#include <string_view>

TEST_SUITE("rspamd_cryptobox")
{

	TEST_CASE("rspamd_cryptobox_keypair")
	{
		rspamd_sk_t sk;
		rspamd_pk_t pk;

		rspamd_cryptobox_keypair(pk, sk);
	}

	TEST_CASE("rspamd_cryptobox_keypair_sig")
	{
		rspamd_sig_sk_t sk;
		rspamd_sig_pk_t pk;

		rspamd_cryptobox_keypair_sig(pk, sk);
	}

	TEST_CASE("rspamd_cryptobox_hash")
	{
		rspamd_cryptobox_hash_state_t p = {0};
		std::string key{"key"};

		rspamd_cryptobox_hash_init(&p, reinterpret_cast<const unsigned char *>(key.data()), key.size());
		std::string data{"key"};
		rspamd_cryptobox_hash_update(&p, reinterpret_cast<const unsigned char *>(data.data()), data.size());

		unsigned char out1[rspamd_cryptobox_HASHBYTES];
		rspamd_cryptobox_hash_final(&p, out1);

		unsigned char out2[rspamd_cryptobox_HASHBYTES];
		rspamd_cryptobox_hash(out2,
							  reinterpret_cast<const unsigned char *>(data.data()), data.size(),
							  reinterpret_cast<const unsigned char *>(key.data()), key.size());
		CHECK(memcmp(out1, out2, sizeof(out1)) == 0);
	}

	TEST_CASE("rspamd_cryptobox_fast_hash")
	{
		rspamd_cryptobox_fast_hash_state_s *st = rspamd_cryptobox_fast_hash_new();
		uint64_t seed = 10;
		rspamd_cryptobox_fast_hash_init(st, seed);
		std::string data{"key"};

		rspamd_cryptobox_fast_hash_update(st,
										  reinterpret_cast<const unsigned char *>(data.data()),
										  data.size());

		uint64_t out1 = rspamd_cryptobox_fast_hash_final(st);
		CHECK(out1 == 358126267837521635);

		uint64_t out2 = rspamd_cryptobox_fast_hash(reinterpret_cast<const unsigned char *>(data.data()),
												   data.size(), seed);
		CHECK(out1 == out2);

		rspamd_cryptobox_fast_hash_free(st);
	}

	TEST_CASE("rspamd_cryptobox_pbkdf")
	{
		std::string pass{"passpa"};
		std::string salt{"salt"};

		uint8_t key1[256] = {0};
		gsize key_len1 = sizeof(key1);

		uint8_t key2[256] = {0};
		gsize key_len2 = sizeof(key2);

		unsigned int complexity = 10;
		enum rspamd_cryptobox_pbkdf_type type = RSPAMD_CRYPTOBOX_PBKDF2;


		CHECK(rspamd_cryptobox_pbkdf(pass.data(), pass.size(),
									 reinterpret_cast<const unsigned char *>(salt.data()), salt.size(),
									 key1, key_len1, complexity, type));
		CHECK(rspamd_cryptobox_pbkdf(pass.data(), pass.size(),
									 reinterpret_cast<const unsigned char *>(salt.data()), salt.size(),
									 key2, key_len2, complexity, type));
		CHECK(memcmp(key1, key2, key_len1) == 0);

		type = RSPAMD_CRYPTOBOX_CATENA;
		CHECK(rspamd_cryptobox_pbkdf(pass.data(), pass.size(),
									 reinterpret_cast<const unsigned char *>(salt.data()), salt.size(),
									 key1, key_len1, complexity, type));
		CHECK(rspamd_cryptobox_pbkdf(pass.data(), pass.size(),
									 reinterpret_cast<const unsigned char *>(salt.data()), salt.size(),
									 key2, key_len2, complexity, type));
		CHECK(memcmp(key1, key2, key_len1) == 0);
	}


	TEST_CASE("rspamd_cryptobox_encrypt_inplace_25519")
	{
		unsigned char data[256];
		gsize len = sizeof(data);
		rspamd_nonce_t nonce;
		rspamd_pk_t pk;
		rspamd_sk_t sk;
		rspamd_mac_t sig;

		ottery_rand_bytes(nonce, sizeof(nonce));

		rspamd_cryptobox_keypair(pk, sk);

		memset(sig, 0, sizeof(sig));

		rspamd_cryptobox_encrypt_inplace(data, len, nonce, pk, sk, sig);

		CHECK(rspamd_cryptobox_decrypt_inplace(data, len, nonce, pk, sk, sig));
	}

	TEST_CASE("rspamd_cryptobox_sign_25519")
	{
		rspamd_sig_sk_t sk;
		rspamd_sig_pk_t pk;
		unsigned char sig[256];
		unsigned long long siglen;
		std::string m{"data to be signed"};

		rspamd_cryptobox_keypair_sig(pk, sk);

		rspamd_cryptobox_sign(sig, &siglen,
							  reinterpret_cast<const unsigned char *>(m.data()), m.size(), sk);
		bool check_result = rspamd_cryptobox_verify(sig, siglen,
													reinterpret_cast<const unsigned char *>(m.data()), m.size(),
													pk);
		CHECK(check_result == true);
	}

	TEST_CASE("rspamd_keypair_encryption")
	{
		auto *kp = rspamd_keypair_new(RSPAMD_KEYPAIR_KEX);
		std::string data{"data to be encrypted"};
		unsigned char *out;
		gsize outlen;
		GError *err = nullptr;

		auto ret = rspamd_keypair_encrypt(kp, reinterpret_cast<const unsigned char *>(data.data()), data.size(),
										  &out, &outlen, &err);
		CHECK(ret);
		CHECK(err == nullptr);

		unsigned char *decrypted;
		gsize decrypted_len;
		ret = rspamd_keypair_decrypt(kp, out, outlen, &decrypted, &decrypted_len, &err);
		CHECK(ret);
		CHECK(err == nullptr);
		CHECK(decrypted_len == data.size());
		CHECK(data == std::string_view{reinterpret_cast<const char *>(decrypted), decrypted_len});

		g_free(out);
		g_free(decrypted);
	}
}

#endif
