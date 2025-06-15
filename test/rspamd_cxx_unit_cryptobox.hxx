/*
 * Copyright 2025 Vsevolod Stakhov
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
#include <vector>
#include <iosfwd>

namespace std// NOLINT(cert-dcl58-cpp)
{
template<typename T>
ostream &operator<<(ostream &stream, const vector<T> &in)
{
	stream << "[";
	for (size_t i = 0; i < in.size(); ++i) {
		if (i != 0) { stream << ", "; }
		stream << in[i];
	}
	stream << "]";
	return stream;
}
}// namespace std

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

	TEST_CASE("rspamd x25519 scalarmult")
	{
		rspamd_sk_t sk;

		// Use a fixed zero secret key
		memset(sk, 0, sizeof(sk));

		// Use a well known public key
		const char *pk = "k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay";
		gsize outlen;
		auto *pk_decoded = rspamd_decode_base32(pk, strlen(pk), &outlen, RSPAMD_BASE32_DEFAULT);
		unsigned char expected[32] = {95, 76, 225, 188, 0, 26, 146, 94, 70, 249,
									  90, 189, 35, 51, 1, 42, 9, 37, 94, 254, 204, 55, 198, 91, 180, 90,
									  46, 217, 140, 226, 211, 90};
		const auto expected_arr = std::vector(std::begin(expected), std::end(expected));

		CHECK(outlen == 32);
		unsigned char out[32];
		/* Clamp integer */
		sk[0] &= 248;
		sk[31] &= 127;
		sk[31] |= 64;
		CHECK(crypto_scalarmult(out, sk, pk_decoded) != -1);
		auto out_arr = std::vector(std::begin(out), std::end(out));
		CHECK(out_arr == expected_arr);
	}

	TEST_CASE("rspamd x25519 ecdh")
	{
		rspamd_sk_t sk;

		// Use a fixed zero secret key
		memset(sk, 0, sizeof(sk));

		// Use a well known public key
		const char *pk = "k4nz984k36xmcynm1hr9kdbn6jhcxf4ggbrb1quay7f88rpm9kay";
		gsize outlen;
		auto *pk_decoded = rspamd_decode_base32(pk, strlen(pk), &outlen, RSPAMD_BASE32_DEFAULT);
		unsigned char expected[32] = {61, 109, 220, 195, 100, 174, 127, 237, 148,
									  122, 154, 61, 165, 83, 93, 105, 127, 166, 153, 112, 103, 224, 2, 200,
									  136, 243, 73, 51, 8, 163, 150, 7};
		const auto expected_arr = std::vector(std::begin(expected), std::end(expected));

		CHECK(outlen == 32);
		unsigned char out[32];

		rspamd_cryptobox_nm(out, pk_decoded, sk);
		auto out_arr = std::vector(std::begin(out), std::end(out));
		CHECK(out_arr == expected_arr);
	}

	// Test vectors for XChaCha20-Poly1305 compatibility with Go implementation
	// These test cases use the same inputs as the Go version to verify compatibility

	TEST_CASE("rspamd xchacha20poly1305 compatibility all_zeros_64_bytes")
	{
		// Test case: all_zeros_64_bytes
		// Key: 32 zero bytes
		// Nonce: 24 zero bytes
		// Plaintext: 64 zero bytes

		rspamd_nm_t key;
		memset(key, 0, sizeof(key));

		rspamd_nonce_t nonce;
		memset(nonce, 0, sizeof(nonce));

		unsigned char plaintext[64];
		memset(plaintext, 0, sizeof(plaintext));

		// Expected values from C implementation
		unsigned char expected_cipher[64] = {
			0x78, 0x9e, 0x96, 0x89, 0xe5, 0x20, 0x8d, 0x7f, 0xd9, 0xe1, 0xf3, 0xc5, 0xb5, 0x34, 0x1f, 0x48,
			0xef, 0x18, 0xa1, 0x3e, 0x41, 0x89, 0x98, 0xad, 0xda, 0xdd, 0x97, 0xa3, 0x69, 0x3a, 0x98, 0x7f,
			0x8e, 0x82, 0xec, 0xd5, 0xc1, 0x43, 0x3b, 0xfe, 0xd1, 0xaf, 0x49, 0x75, 0x0c, 0x0f, 0x1f, 0xf2,
			0x9c, 0x41, 0x74, 0xa0, 0x5b, 0x11, 0x9a, 0xa3, 0xa9, 0xe8, 0x33, 0x38, 0x12, 0xe0, 0xc0, 0xfe};

		rspamd_mac_t expected_mac = {
			0x9c, 0x22, 0xbd, 0x8b, 0x7d, 0x68, 0x00, 0xca, 0x3f, 0x9d, 0xf1, 0xc0, 0x3e, 0x31, 0x3e, 0x68};

		// Test encryption using Rspamd's nm (shared key) encryption
		unsigned char ciphertext[64];
		memcpy(ciphertext, plaintext, sizeof(plaintext));

		rspamd_mac_t mac;

		rspamd_cryptobox_encrypt_nm_inplace(ciphertext, sizeof(ciphertext), nonce, key, mac);

		CHECK(memcmp(ciphertext, expected_cipher, sizeof(expected_cipher)) == 0);
		CHECK(memcmp(mac, expected_mac, sizeof(expected_mac)) == 0);

		// Test decryption
		gboolean decrypt_ok = rspamd_cryptobox_decrypt_nm_inplace(ciphertext, sizeof(ciphertext), nonce, key, mac);
		CHECK(decrypt_ok == TRUE);
		CHECK(memcmp(ciphertext, plaintext, sizeof(plaintext)) == 0);
	}

	TEST_CASE("rspamd xchacha20poly1305 compatibility all_zeros_128_bytes")
	{
		// Test case: all_zeros_128_bytes
		// Key: 32 zero bytes
		// Nonce: 24 zero bytes
		// Plaintext: 128 zero bytes

		rspamd_nm_t key;
		memset(key, 0, sizeof(key));

		rspamd_nonce_t nonce;
		memset(nonce, 0, sizeof(nonce));

		unsigned char plaintext[128];
		memset(plaintext, 0, sizeof(plaintext));

		unsigned char expected_cipher[128] = {
			0x78, 0x9e, 0x96, 0x89, 0xe5, 0x20, 0x8d, 0x7f, 0xd9, 0xe1, 0xf3, 0xc5, 0xb5, 0x34, 0x1f, 0x48,
			0xef, 0x18, 0xa1, 0x3e, 0x41, 0x89, 0x98, 0xad, 0xda, 0xdd, 0x97, 0xa3, 0x69, 0x3a, 0x98, 0x7f,
			0x8e, 0x82, 0xec, 0xd5, 0xc1, 0x43, 0x3b, 0xfe, 0xd1, 0xaf, 0x49, 0x75, 0x0c, 0x0f, 0x1f, 0xf2,
			0x9c, 0x41, 0x74, 0xa0, 0x5b, 0x11, 0x9a, 0xa3, 0xa9, 0xe8, 0x33, 0x38, 0x12, 0xe0, 0xc0, 0xfe,
			0xa4, 0x9e, 0x1e, 0xe0, 0x13, 0x4a, 0x70, 0xa9, 0xd4, 0x9c, 0x24, 0xe0, 0xcb, 0xd8, 0xfc, 0x3b,
			0xa2, 0x7e, 0x97, 0xc3, 0x32, 0x2a, 0xd4, 0x87, 0xf7, 0x78, 0xf8, 0xdc, 0x6a, 0x12, 0x2f, 0xa5,
			0x9c, 0xbe, 0x33, 0xe7, 0x78, 0xea, 0x2e, 0x50, 0xbb, 0x59, 0x09, 0xc9, 0x97, 0x1c, 0x4f, 0xec,
			0x2f, 0x93, 0x52, 0x3f, 0x77, 0x89, 0x2d, 0x17, 0xca, 0xa5, 0x81, 0x67, 0xde, 0xc4, 0xd6, 0xc7};

		rspamd_mac_t expected_mac = {
			0xcf, 0xe1, 0x4a, 0xc3, 0x39, 0x35, 0xd3, 0x63, 0x1a, 0x06, 0xbf, 0x55, 0x88, 0xf4, 0x12, 0xfa};

		unsigned char ciphertext[128];
		memcpy(ciphertext, plaintext, sizeof(plaintext));

		rspamd_mac_t mac;
		rspamd_cryptobox_encrypt_nm_inplace(ciphertext, sizeof(ciphertext), nonce, key, mac);

		CHECK(memcmp(ciphertext, expected_cipher, sizeof(expected_cipher)) == 0);
		CHECK(memcmp(mac, expected_mac, sizeof(expected_mac)) == 0);

		// Test decryption
		gboolean decrypt_ok = rspamd_cryptobox_decrypt_nm_inplace(ciphertext, sizeof(ciphertext), nonce, key, mac);
		CHECK(decrypt_ok == TRUE);
		CHECK(memcmp(ciphertext, plaintext, sizeof(plaintext)) == 0);
	}

	TEST_CASE("rspamd xchacha20poly1305 compatibility test_pattern_64_bytes")
	{
		// Test case: test_pattern_64_bytes
		// Key: 0x01 repeated 32 times
		// Nonce: 0x01, 0x02, 0x03, ... 0x18 (24 bytes)
		// Plaintext: 0x00, 0x01, 0x02, ... 0x41 (66 bytes)

		rspamd_nm_t key;
		memset(key, 0x01, sizeof(key));

		rspamd_nonce_t nonce = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
			0x21, 0x22, 0x23, 0x24};

		unsigned char plaintext[66];
		for (int i = 0; i < 66; i++) {
			plaintext[i] = i;
		}

		// Expected values from C implementation
		unsigned char expected_cipher[66] = {
			0xe6, 0x0e, 0xf7, 0x6d, 0x7f, 0x04, 0x37, 0x81, 0x9f, 0x60, 0x03, 0x28, 0x60, 0xb1, 0x2b, 0xaa,
			0xae, 0x2b, 0x13, 0xef, 0x6d, 0xd3, 0x18, 0xf1, 0x3b, 0xc6, 0x06, 0xfb, 0x65, 0x9a, 0x53, 0x3b,
			0x23, 0xe6, 0x99, 0x0c, 0x65, 0x2f, 0xbf, 0x56, 0xcb, 0x7c, 0x18, 0x53, 0xa8, 0xbc, 0x11, 0xc4,
			0x0b, 0x35, 0xc9, 0x40, 0x9a, 0xc2, 0xe1, 0x7f, 0x1a, 0x72, 0xaa, 0xb3, 0x8b, 0x4e, 0x21, 0x32,
			0x87, 0xf7};

		rspamd_mac_t expected_mac = {
			0xf2, 0xa7, 0xbd, 0xae, 0x53, 0x68, 0xfe, 0xd8, 0x4c, 0x92, 0xe8, 0x52, 0x35, 0x4d, 0x78, 0x7c};

		unsigned char ciphertext[66];
		memcpy(ciphertext, plaintext, sizeof(plaintext));

		rspamd_mac_t mac;

		rspamd_cryptobox_encrypt_nm_inplace(ciphertext, sizeof(ciphertext), nonce, key, mac);

		CHECK(memcmp(ciphertext, expected_cipher, sizeof(expected_cipher)) == 0);
		CHECK(memcmp(mac, expected_mac, sizeof(expected_mac)) == 0);

		// Test decryption
		gboolean decrypt_ok = rspamd_cryptobox_decrypt_nm_inplace(ciphertext, sizeof(ciphertext), nonce, key, mac);
		CHECK(decrypt_ok == TRUE);
		CHECK(memcmp(ciphertext, plaintext, sizeof(plaintext)) == 0);
	}

	TEST_CASE("rspamd mac key derivation compatibility all_zeros")
	{
		// Test MAC key derivation process
		// Key: 32 zero bytes
		// Nonce: 24 zero bytes

		rspamd_nm_t key;
		memset(key, 0, sizeof(key));

		rspamd_nonce_t nonce;
		memset(nonce, 0, sizeof(nonce));

		// Expected values from C implementation
		unsigned char expected_subkey[64] = {
			0xbc, 0xd0, 0x2a, 0x18, 0xbf, 0x3f, 0x01, 0xd1, 0x92, 0x92, 0xde, 0x30, 0xa7, 0xa8, 0xfd, 0xac,
			0xa4, 0xb6, 0x5e, 0x50, 0xa6, 0x00, 0x2c, 0xc7, 0x2c, 0xd6, 0xd2, 0xf7, 0xc9, 0x1a, 0xc3, 0xd5,
			0x72, 0x8f, 0x83, 0xe0, 0xaa, 0xd2, 0xbf, 0xcf, 0x9a, 0xbd, 0x2d, 0x2d, 0xb5, 0x8f, 0xae, 0xdd,
			0x65, 0x01, 0x5d, 0xd8, 0x3f, 0xc0, 0x9b, 0x13, 0x1e, 0x27, 0x10, 0x43, 0x01, 0x9e, 0x8e, 0x0f};

		unsigned char expected_mac_key[32] = {
			0xbc, 0xd0, 0x2a, 0x18, 0xbf, 0x3f, 0x01, 0xd1, 0x92, 0x92, 0xde, 0x30, 0xa7, 0xa8, 0xfd, 0xac,
			0xa4, 0xb6, 0x5e, 0x50, 0xa6, 0x00, 0x2c, 0xc7, 0x2c, 0xd6, 0xd2, 0xf7, 0xc9, 0x1a, 0xc3, 0xd5};

		// Generate subkey using XChaCha20 (first 64 bytes of keystream)
		// This simulates the MAC key derivation process used in secretbox
		unsigned char subkey[64];
		memset(subkey, 0, sizeof(subkey));

		// Use libsodium's ChaCha20 directly to generate the subkey
		// This matches what happens inside the secretbox implementation
		crypto_stream_xchacha20(subkey, sizeof(subkey), nonce, key);

		// MAC key is first 32 bytes of subkey
		unsigned char mac_key[32];
		memcpy(mac_key, subkey, 32);

		CHECK(memcmp(subkey, expected_subkey, sizeof(expected_subkey)) == 0);
		CHECK(memcmp(mac_key, expected_mac_key, sizeof(expected_mac_key)) == 0);
	}

	TEST_CASE("rspamd mac key derivation compatibility test_pattern")
	{
		// Test MAC key derivation process
		// Key: 0x01 repeated 32 times
		// Nonce: 0x01, 0x02, 0x03, ... 0x18 (24 bytes)

		rspamd_nm_t key;
		memset(key, 0x01, sizeof(key));

		rspamd_nonce_t nonce = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20,
			0x21, 0x22, 0x23, 0x24};

		// Expected values from C implementation
		unsigned char expected_subkey[64] = {
			0x47, 0xa6, 0xe3, 0xb5, 0x0f, 0xd4, 0x7f, 0x08, 0xb5, 0x35, 0x80, 0xfc, 0x93, 0x66, 0x1a, 0x7f,
			0x9c, 0xf5, 0x8c, 0x93, 0xae, 0x4e, 0x3f, 0xcf, 0x86, 0xb7, 0xdf, 0x34, 0x48, 0x73, 0x33, 0xdb,
			0x71, 0x31, 0x0f, 0xe1, 0xcc, 0xd9, 0x0c, 0x0a, 0x1a, 0x19, 0x54, 0x30, 0xdf, 0xe3, 0xda, 0xee,
			0x70, 0x29, 0xd9, 0xae, 0xf6, 0x4d, 0x78, 0xe3, 0xe8, 0x43, 0x98, 0xea, 0xaa, 0xd8, 0x85, 0x79};

		unsigned char expected_mac_key[32] = {
			0x47, 0xa6, 0xe3, 0xb5, 0x0f, 0xd4, 0x7f, 0x08, 0xb5, 0x35, 0x80, 0xfc, 0x93, 0x66, 0x1a, 0x7f,
			0x9c, 0xf5, 0x8c, 0x93, 0xae, 0x4e, 0x3f, 0xcf, 0x86, 0xb7, 0xdf, 0x34, 0x48, 0x73, 0x33, 0xdb};

		// Generate subkey using XChaCha20 (first 64 bytes of keystream)
		// This simulates the MAC key derivation process used in secretbox
		unsigned char subkey[64];
		memset(subkey, 0, sizeof(subkey));

		// Use libsodium's ChaCha20 directly to generate the subkey
		// This matches what happens inside the secretbox implementation
		crypto_stream_xchacha20(subkey, sizeof(subkey), nonce, key);

		// MAC key is first 32 bytes of subkey
		unsigned char mac_key[32];
		memcpy(mac_key, subkey, 32);

		CHECK(memcmp(subkey, expected_subkey, sizeof(expected_subkey)) == 0);
		CHECK(memcmp(mac_key, expected_mac_key, sizeof(expected_mac_key)) == 0);
	}
}

#endif
