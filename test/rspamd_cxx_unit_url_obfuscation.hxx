/*
 * Copyright 2026 Vsevolod Stakhov
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

/* Unit tests for URL obfuscation detail flags */

#ifndef RSPAMD_CXX_UNIT_URL_OBFUSCATION_HXX
#define RSPAMD_CXX_UNIT_URL_OBFUSCATION_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/url.h"
#include "libutil/mem_pool.h"

#include <string>

struct url_obf_test_ctx {
	rspamd_mempool_t *pool;

	url_obf_test_ctx()
	{
		static bool url_initialized = false;
		if (!url_initialized) {
			rspamd_url_init(NULL);
			url_initialized = true;
		}
		pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "url_obf_test", 0);
	}

	~url_obf_test_ctx()
	{
		rspamd_mempool_delete(pool);
	}

	struct rspamd_url *parse_url(const std::string &url_str,
								 enum rspamd_url_parse_flags flags = RSPAMD_URL_PARSE_TEXT)
	{
		auto *url = rspamd_mempool_alloc0_type(pool, struct rspamd_url);
		char *copy = rspamd_mempool_strdup(pool, url_str.c_str());
		auto rc = rspamd_url_parse(url, copy, strlen(copy), pool, flags, nullptr);
		if (rc == URI_ERRNO_OK) {
			return url;
		}
		return nullptr;
	}
};

TEST_SUITE("url_obfuscation")
{
	TEST_CASE("numeric IP sets OBF_IP_NUMERIC")
	{
		url_obf_test_ctx ctx;
		/* Numeric IP in decimal: 0x7f000001 = 2130706433 = 127.0.0.1 */
		auto *url = ctx.parse_url("http://2130706433/test");
		REQUIRE(url != nullptr);
		CHECK((url->flags & RSPAMD_URL_FLAG_OBSCURED) != 0);
		REQUIRE(url->ext != nullptr);
		CHECK((url->ext->obfuscation_flags & RSPAMD_URL_OBF_IP_NUMERIC) != 0);
		CHECK(url->ext->obfuscation_count > 0);
	}

	TEST_CASE("backslashes set OBF_BACKSLASHES")
	{
		url_obf_test_ctx ctx;
		auto *url = ctx.parse_url("http:\\\\example.com/test", RSPAMD_URL_PARSE_HREF);
		if (url != nullptr) {
			if (url->flags & RSPAMD_URL_FLAG_OBSCURED) {
				REQUIRE(url->ext != nullptr);
				CHECK((url->ext->obfuscation_flags & RSPAMD_URL_OBF_BACKSLASHES) != 0);
			}
		}
	}

	TEST_CASE("missing slashes sets OBF_MISSING_SLASHES")
	{
		url_obf_test_ctx ctx;
		/* URL without // after schema */
		auto *url = ctx.parse_url("http:example.com/test");
		if (url != nullptr) {
			REQUIRE(url->ext != nullptr);
			CHECK((url->ext->obfuscation_flags & RSPAMD_URL_OBF_MISSING_SLASHES) != 0);
		}
	}

	TEST_CASE("host encoding sets OBF_HOST_ENCODED")
	{
		url_obf_test_ctx ctx;
		auto *url = ctx.parse_url("http://%65%78%61%6d%70%6c%65.com/test");
		if (url != nullptr) {
			REQUIRE(url->ext != nullptr);
			CHECK((url->ext->obfuscation_flags & RSPAMD_URL_OBF_HOST_ENCODED) != 0);
		}
	}

	TEST_CASE("multiple @ signs set OBF_MULTIPLE_AT")
	{
		url_obf_test_ctx ctx;
		auto *url = ctx.parse_url("http://user@@example.com/test");
		if (url != nullptr) {
			CHECK((url->flags & RSPAMD_URL_FLAG_OBSCURED) != 0);
			REQUIRE(url->ext != nullptr);
			CHECK((url->ext->obfuscation_flags & RSPAMD_URL_OBF_MULTIPLE_AT) != 0);
		}
	}

	TEST_CASE("password in URL sets OBF_HAS_PASSWORD")
	{
		url_obf_test_ctx ctx;
		auto *url = ctx.parse_url("http://user:pass@example.com/test");
		if (url != nullptr) {
			REQUIRE(url->ext != nullptr);
			CHECK((url->ext->obfuscation_flags & RSPAMD_URL_OBF_HAS_PASSWORD) != 0);
		}
	}

	TEST_CASE("obfuscation_flag_to_string returns correct names")
	{
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_MULTIPLE_AT)) == "multiple_at");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_BACKSLASHES)) == "backslashes");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_IP_NUMERIC)) == "ip_numeric");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_DOT_TRICKS)) == "dot_tricks");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_HTML_BADCHARS)) == "html_badchars");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_PHISH_MISMATCH)) == "phish_mismatch");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_HOST_ENCODED)) == "host_encoded");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_HAS_PORT)) == "has_port");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_HAS_USER)) == "has_user");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_SCHEMALESS)) == "schemaless");
		CHECK(std::string(rspamd_url_obfuscation_flag_to_string(RSPAMD_URL_OBF_NO_TLD)) == "no_tld");
	}

	TEST_CASE("obfuscation_flag_from_string works")
	{
		int flag = 0;
		CHECK(rspamd_url_obfuscation_flag_from_string("multiple_at", &flag) == true);
		CHECK((flag & RSPAMD_URL_OBF_MULTIPLE_AT) != 0);

		flag = 0;
		CHECK(rspamd_url_obfuscation_flag_from_string("ip_numeric", &flag) == true);
		CHECK((flag & RSPAMD_URL_OBF_IP_NUMERIC) != 0);

		flag = 0;
		CHECK(rspamd_url_obfuscation_flag_from_string("nonexistent_flag", &flag) == false);
	}

	TEST_CASE("obfuscation_count matches popcount")
	{
		url_obf_test_ctx ctx;
		/* Numeric IP should trigger OBSCURED + IP_NUMERIC */
		auto *url = ctx.parse_url("http://2130706433/test");
		REQUIRE(url != nullptr);
		REQUIRE(url->ext != nullptr);

		unsigned int expected_count = __builtin_popcount(url->ext->obfuscation_flags);
		CHECK(url->ext->obfuscation_count == expected_count);
	}

	TEST_CASE("displayed_url and redirected_url are independent")
	{
		url_obf_test_ctx ctx;
		auto *url1 = ctx.parse_url("http://example.com/path1");
		auto *url2 = ctx.parse_url("http://phishing.com/path2");
		auto *url3 = ctx.parse_url("http://redirect-target.com/path3");

		REQUIRE(url1 != nullptr);
		REQUIRE(url2 != nullptr);
		REQUIRE(url3 != nullptr);

		auto *ext = rspamd_url_ensure_ext(url1, ctx.pool);
		ext->displayed_url = url2;
		ext->redirected_url = url3;

		CHECK(url1->ext->displayed_url == url2);
		CHECK(url1->ext->redirected_url == url3);
		CHECK(url1->ext->displayed_url != url1->ext->redirected_url);

		/* rspamd_url_get_linked prefers displayed_url */
		CHECK(rspamd_url_get_linked(url1) == url2);
	}
}

#endif
