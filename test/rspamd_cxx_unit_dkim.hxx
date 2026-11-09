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

/* Detached unit tests for the dkim utils */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_DKIM_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_DKIM_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"
#include "contrib/fmt/include/fmt/base.h"
#include "libserver/dkim.h"

#include <vector>
#include <utility>
#include <string>
#include <tuple>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define RSPAMD_DKIM_TEST_ASAN 1
#endif
#endif
#if !defined(RSPAMD_DKIM_TEST_ASAN) && defined(__SANITIZE_ADDRESS__)
#define RSPAMD_DKIM_TEST_ASAN 1
#endif
#ifdef RSPAMD_DKIM_TEST_ASAN
#include <sanitizer/allocator_interface.h>
#endif

namespace rspamd_dkim_test {

/* Base64 of the SubjectPublicKeyInfo of a key, or empty if the key is null */
static inline std::string spki_b64(EVP_PKEY *pkey)
{
	if (pkey == nullptr) {
		return {};
	}

	unsigned char *der = nullptr;
	int len = i2d_PUBKEY(pkey, &der);

	if (len <= 0) {
		return {};
	}

	auto *b64 = g_base64_encode(der, len);
	std::string ret{b64};
	g_free(b64);
	OPENSSL_free(der);

	return ret;
}

static inline std::string gen_rsa_b64(int bits)
{
	auto *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	EVP_PKEY *pkey = nullptr;
	std::string ret;

	if (ctx && EVP_PKEY_keygen_init(ctx) > 0 &&
		EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0 &&
		EVP_PKEY_keygen(ctx, &pkey) > 0) {
		ret = spki_b64(pkey);
	}

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ERR_clear_error();

	return ret;
}

static inline std::string gen_ec_b64(int nid)
{
	auto *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
	EVP_PKEY *pkey = nullptr;
	std::string ret;

	if (ctx && EVP_PKEY_keygen_init(ctx) > 0 &&
		EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) > 0 &&
		EVP_PKEY_keygen(ctx, &pkey) > 0) {
		ret = spki_b64(pkey);
	}

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ERR_clear_error();

	return ret;
}

#ifdef EVP_PKEY_ED25519
static inline std::string gen_ed25519_b64()
{
	auto *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
	EVP_PKEY *pkey = nullptr;
	std::string ret;

	if (ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0) {
		ret = spki_b64(pkey);
	}

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	ERR_clear_error();

	return ret;
}
#endif

/* Parses a record; returns true if a key came out and frees it */
static inline bool parse_record(const std::string &rec, std::string &errmsg)
{
	GError *err = nullptr;
	gsize klen = rec.size();
	auto *key = rspamd_dkim_parse_key(rec.c_str(), &klen, &err);

	if (key == nullptr) {
		errmsg = err ? err->message : "";
		CHECK(err != nullptr);
	}

	if (err) {
		g_error_free(err);
	}

	if (key) {
		rspamd_dkim_key_free(key);
		return true;
	}

	return false;
}

}// namespace rspamd_dkim_test

TEST_SUITE("rspamd_dkim")
{

	TEST_CASE("rspamd_dkim_parse_key")
	{
		struct test_case {
			std::string input;
			bool is_valid;
			std::string expected_id;
		};
		std::vector<test_case> cases{
			{"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// Spaces before p
			{"   p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// Spaces and bogus semicolon before p
			{";  p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// Spaces after p
			{"k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB      ",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces
			{"k=rsa; t=s; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB  ;    ",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces around '=' sign
			{"k=rsa; t=s; p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB;",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces around '=' sign + bad stuff
			{"ololo k=rsa; t=s; p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB;",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// ; and spaces around '=' sign + bad stuff
			{"ololo=trololo; k=rsa; t=s; "
			 "p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB ",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// Spaces within base64
			{"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 " QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "  5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/ jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "  TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "  VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "  lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 " kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB",
			 true, "e40cc5c40ee29cb4f21d95c7f0dc9989"},
			// Invalid RSA
			{"ololo=trololo; k=rsa; t=s; "
			 "p =   BADMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB ",
			 false, ""},
			// Invalid RSA for eddsa
			{"ololo=trololo; k=ed25519; t=s; "
			 "p =   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			 "QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			 "5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			 "TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			 "VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			 "lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			 "kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB ",
			 false, ""},
		};

		auto cur_test_idx = 0;
		for (auto &&c: cases) {
			SUBCASE(fmt::format("process DKIM record {}: {}", cur_test_idx++, c.input).c_str())
			{
				GError *err = nullptr;
				gsize klen = c.input.size();
				auto *key = rspamd_dkim_parse_key(c.input.c_str(), &klen, &err);
				if (c.is_valid) {
					REQUIRE_MESSAGE(key != nullptr, (err ? err->message : "unknown error"));
					char hexbuf[RSPAMD_DKIM_KEY_ID_LEN * 2 + 1];
					auto *id = rspamd_dkim_key_id(key);
					REQUIRE(id != nullptr);

					auto hexlen = rspamd_encode_hex_buf(id, RSPAMD_DKIM_KEY_ID_LEN, hexbuf,
														sizeof(hexbuf));
					CHECK(hexlen > 0);
					CHECK(std::string{hexbuf, (std::size_t) hexlen} == c.expected_id);
					rspamd_dkim_key_free(key);
				}
				else {
					CHECK(key == nullptr);
				}
			}
		}
	}

	TEST_CASE("rspamd_dkim_domain_lowercase")
	{
		std::vector<std::pair<std::string, std::string>> cases{
			{"example.com", "example.com"},
			{"ExAmple.COM", "example.com"},
			{"Mail.Example.ORG", "mail.example.org"},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "dkim", 0);

		for (auto &&[d, expected]: cases) {
			SUBCASE(fmt::format("d={}", d).c_str())
			{
				GError *err = nullptr;
				auto sig = fmt::format("v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s=sel; "
									   "h=from:to; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; "
									   "b=dGVzdA==",
									   d);
				auto *ctx = rspamd_create_dkim_context(sig.c_str(), pool, nullptr, 0,
													   RSPAMD_DKIM_NORMAL, &err);
				REQUIRE_MESSAGE(ctx != nullptr, (err ? err->message : "unknown error"));
				CHECK(std::string{rspamd_dkim_get_domain(ctx)} == expected);
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("rspamd_dkim_arc_seal_instance")
	{
		/* The ARC-Seal header list is sized from i=, which must be validated first */
		std::vector<std::string> cases{
			"cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
			/* fuzzer input: no i= and none of the other required tags */
			"00",
			"i=0; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
			"i=11; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
			"i=2000000; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
			"i=2147483648; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
			"i=4294967295; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
			/* must not be truncated to i=1 */
			"i=4294967297; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==",
		};

		for (auto &&sig: cases) {
			SUBCASE(fmt::format("arc-seal: {}", sig).c_str())
			{
				auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "dkim", 0);
				GError *err = nullptr;
#ifdef RSPAMD_DKIM_TEST_ASAN
				auto before = __sanitizer_get_current_allocated_bytes();
#endif
				auto *ctx = rspamd_create_dkim_context(sig.c_str(), pool, nullptr, 0,
													   RSPAMD_DKIM_ARC_SEAL, &err);
#ifdef RSPAMD_DKIM_TEST_ASAN
				/* Measured while the pool, which owns the header list, is alive */
				CHECK(__sanitizer_get_current_allocated_bytes() - before < 1024 * 1024);
#endif
				CHECK(ctx == nullptr);
				REQUIRE(err != nullptr);
				CHECK(std::string{err->message}.find("ARC") != std::string::npos);
				g_error_free(err);
				rspamd_mempool_delete(pool);
			}
		}
	}

	TEST_CASE("rspamd_dkim_empty_tag_spec")
	{
		/*
		 * arc.lua splits the header on `;` and drops elements without `=`;
		 * the C parser must read the same tags, never a `;i` tag name
		 */
		struct test_case {
			std::string sig;
			bool valid;
			std::string domain;
		};
		std::vector<test_case> cases{
			{"cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==;;i=1", true, "example.com"},
			{"i=1; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==;;i=0", false, ""},
			{"i=1; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==; x;i=0", false, ""},
			{"i=1; cv=none; a=rsa-sha256; d=attacker.example; s=sel; b=dGVzdA==;;d=trusted.example",
			 true, "trusted.example"},
			{";i=1; ; cv=none; a=rsa-sha256; d=example.com; s=sel; b=dGVzdA==;;", true, "example.com"},
		};

		for (auto &&c: cases) {
			SUBCASE(fmt::format("arc-seal: {}", c.sig).c_str())
			{
				auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "dkim", 0);
				GError *err = nullptr;
				auto *ctx = rspamd_create_dkim_context(c.sig.c_str(), pool, nullptr, 0,
													   RSPAMD_DKIM_ARC_SEAL, &err);
				if (c.valid) {
					REQUIRE_MESSAGE(ctx != nullptr, (err ? err->message : "unknown error"));
					CHECK(std::string{rspamd_dkim_get_domain(ctx)} == c.domain);
				}
				else {
					CHECK(ctx == nullptr);
				}
				if (err) {
					g_error_free(err);
				}
				rspamd_mempool_delete(pool);
			}
		}
	}

	TEST_CASE("rspamd_dkim_key_type_matches_record")
	{
		using namespace rspamd_dkim_test;

		const std::string rsa_2048 =
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA"
			"QEA5CeQZpoPbsS8lG41UI1rxTtOSqPrfgZzhrZsk0t9dIbFTvaoql/FLuYcbdUARc"
			"5zuyXsDj1eSprOgcPT9PY9RoSUsY8i/jnD49DHXtMfXoBk0J6epNzbZqqWU+"
			"TG02HwWNy/kf1h+OlAGQKJLgakivZ3nMMnUIPHkUjwvhbkaMXCI046XoqsEQ7KW"
			"VKRoF3cK1cFXLo+bgO3sEJgGtvwzPodG0CqVu+gjehrjwdLnPhqyEspfI1IbL"
			"lnNaq5pWei/B8pG6teV+y3t4yay5ZGktALJjlylKHVo2USkVYQTFQ9Ji25m2jupdCd"
			"kn1FTuYNqh0Nzg3KPQHNVp7mlE7lfwIDAQAB";
		const auto ec_p256 = gen_ec_b64(NID_X9_62_prime256v1);
		const auto ec_p384 = gen_ec_b64(NID_secp384r1);
		const auto ec_k1 = gen_ec_b64(NID_secp256k1);
		std::string msg;

		REQUIRE(!ec_p256.empty());
		REQUIRE(!ec_p384.empty());

		SUBCASE("rsa key with the default type")
		{
			CHECK(parse_record("v=DKIM1; p=" + rsa_2048, msg));
			CHECK(parse_record("v=DKIM1; k=rsa; p=" + rsa_2048, msg));
		}
		SUBCASE("ec key with k=rsa or the default type")
		{
			CHECK(!parse_record("v=DKIM1; k=rsa; p=" + ec_p256, msg));
			CHECK(msg.find("not an RSA key") != std::string::npos);
			CHECK(!parse_record("v=DKIM1; p=" + ec_p256, msg));
			CHECK(ERR_peek_error() == 0);
		}
		SUBCASE("rsa key with k=ecdsa256")
		{
			CHECK(!parse_record("v=DKIM1; k=ecdsa256; p=" + rsa_2048, msg));
			CHECK(msg.find("not an ECDSA key") != std::string::npos);
			CHECK(ERR_peek_error() == 0);
		}
		SUBCASE("named NIST curves with k=ecdsa256")
		{
			CHECK(parse_record("v=DKIM1; k=ecdsa256; p=" + ec_p256, msg));
			CHECK(parse_record("v=DKIM1; k=ecdsa256; p=" + ec_p384, msg));
			CHECK(ERR_peek_error() == 0);
		}
		SUBCASE("other curve with k=ecdsa256")
		{
			if (ec_k1.empty()) {
				MESSAGE("secp256k1 is not available, skipped");
			}
			else {
				CHECK(!parse_record("v=DKIM1; k=ecdsa256; p=" + ec_k1, msg));
				CHECK(ERR_peek_error() == 0);
			}
		}
#ifdef EVP_PKEY_ED25519
		SUBCASE("ed25519 SPKI with k=ecdsa256")
		{
			const auto ed = gen_ed25519_b64();

			if (ed.empty()) {
				MESSAGE("ed25519 key generation is not available, skipped");
			}
			else {
				CHECK(!parse_record("v=DKIM1; k=ecdsa256; p=" + ed, msg));
				CHECK(ERR_peek_error() == 0);
			}
		}
#endif
		SUBCASE("rsa key shorter than 1024 bits")
		{
			const auto small = gen_rsa_b64(512);

			if (small.empty()) {
				MESSAGE("512 bit RSA generation is refused by this OpenSSL, skipped");
			}
			else {
				CHECK(!parse_record("v=DKIM1; k=rsa; p=" + small, msg));
				CHECK(msg.find("too short") != std::string::npos);
				CHECK(ERR_peek_error() == 0);
			}
		}
		SUBCASE("garbage in p= leaves no openssl errors")
		{
			CHECK(!parse_record("v=DKIM1; p=AAAAAAAAAAAAAAAA", msg));
			CHECK(ERR_peek_error() == 0);
		}
		SUBCASE("tags are matched by their whole name")
		{
			CHECK(!parse_record("v=DKIM1; xp=" + rsa_2048, msg));
			CHECK(msg.find("revoked") != std::string::npos);
			CHECK(parse_record("v=DKIM1; xp=garbage; p=" + rsa_2048, msg));
			CHECK(parse_record("v=DKIM1; p=" + rsa_2048 + "; xp=garbage", msg));
			CHECK(parse_record("v=DKIM1; xk=ed25519; p=" + rsa_2048, msg));
			CHECK(parse_record("v=DKIM1; p=" + rsa_2048 + "; xk=ed25519", msg));
			CHECK(parse_record("foo;p=" + rsa_2048, msg));
		}
	}

	TEST_CASE("rspamd_dkim_relaxed_header_whitespace")
	{
		struct test_case {
			std::string name;
			std::string value;
			std::string expected;
		};
		std::vector<test_case> cases{
			{"Subject", "a\fb", "subject:a\fb\r\n"},
			{"Subject", "a\vb", "subject:a\vb\r\n"},
			{"Subject", "a \f b", "subject:a \f b\r\n"},
			{"Subject", "  a   b\t\tc  ", "subject:a b c\r\n"},
			{"Subject", "a \t b", "subject:a b\r\n"},
			{"Subject", "a\r\n b\r\n\tc", "subject:a b c\r\n"},
			{"Subject", "\r\n a", "subject:a\r\n"},
		};

		for (auto &&c: cases) {
			SUBCASE(fmt::format("value {}", c.value.size()).c_str())
			{
				char buf[256];
				auto r = rspamd_dkim_canonize_header_relaxed_str(c.name.c_str(),
																 c.value.c_str(), buf, sizeof(buf));
				REQUIRE(r > 0);
				CHECK(std::string{buf, (std::size_t) r} == c.expected);
			}
		}
	}
}

#endif
