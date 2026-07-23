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

#ifndef RSPAMD_CXX_UNIT_CONTENT_TYPE_HXX
#define RSPAMD_CXX_UNIT_CONTENT_TYPE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/content_type.h"

#include <string>
#include <string_view>

/*
 * Mirrors the (file-static) max_content_type_params cap in
 * src/libmime/content_type.c. Kept in sync deliberately: if the cap changes,
 * this test should be updated alongside it.
 */
static constexpr unsigned int expected_param_cap = 1024;

TEST_SUITE("content_type")
{
	TEST_CASE("normal parameters are not truncated")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string hdr = "text/plain; charset=utf-8; boundary=xyz";

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);

		std::string_view type{ct->type.begin, ct->type.len};
		std::string_view subtype{ct->subtype.begin, ct->subtype.len};
		CHECK(type == "text");
		CHECK(subtype == "plain");
		CHECK(ct->nparams == 2);
		CHECK((ct->flags & RSPAMD_CONTENT_TYPE_BROKEN) == 0);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("parameter flood is bounded and flagged broken")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		/*
		 * A single Content-Type value packed with far more parameters than any
		 * real message would carry. Without the cap this materialises one pool
		 * object + hash entry per parameter, amplifying a bounded input into a
		 * huge allocation count.
		 */
		std::string hdr = "text/plain";
		for (int i = 0; i < 5000; i++) {
			hdr += "; p" + std::to_string(i) + "=v" + std::to_string(i);
		}

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);

		/* The declared type must still be parsed correctly */
		std::string_view type{ct->type.begin, ct->type.len};
		std::string_view subtype{ct->subtype.begin, ct->subtype.len};
		CHECK(type == "text");
		CHECK(subtype == "plain");

		/* Parameter count saturates at the cap and the truncation is signalled */
		CHECK(ct->nparams == expected_param_cap);
		CHECK((ct->flags & RSPAMD_CONTENT_TYPE_BROKEN) != 0);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("duplicate-name flood is bounded too")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		/*
		 * Repeating the same parameter name keeps the hash table at a single
		 * entry but still allocates one param struct per occurrence, so the cap
		 * must count params, not distinct names.
		 */
		std::string hdr = "text/plain";
		for (int i = 0; i < 5000; i++) {
			hdr += "; a=b";
		}

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK(ct->nparams == expected_param_cap);
		CHECK((ct->flags & RSPAMD_CONTENT_TYPE_BROKEN) != 0);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("content-disposition parameter flood is bounded")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"cd-test", 0);
		std::string hdr = "attachment";
		for (int i = 0; i < 5000; i++) {
			hdr += "; p" + std::to_string(i) + "=v" + std::to_string(i);
		}

		auto *cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(cd != nullptr);
		CHECK(cd->type == RSPAMD_CT_ATTACHMENT);
		CHECK(cd->nparams == expected_param_cap);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("content-disposition normal filename is preserved")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"cd-test", 0);
		std::string hdr = "attachment; filename=report.pdf";

		auto *cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(cd != nullptr);
		CHECK(cd->type == RSPAMD_CT_ATTACHMENT);
		CHECK(cd->nparams == 1);

		std::string_view fname{cd->filename.begin, cd->filename.len};
		CHECK(fname == "report.pdf");

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("rfc2231 piecewise reconstruction orders by id, not by wraparound")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		/*
		 * Two continuation pieces of one parameter whose ids differ by more
		 * than INT32_MAX. The old comparator subtracted the two unsigned ids
		 * and truncated to int32_t, which wraps and reverses the order. The
		 * reconstructed value must be "ab" (id 0 then id 3000000000), not "ba".
		 */
		std::string hdr = "text/plain; x*0=a; x*3000000000=b";

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		REQUIRE(ct->attrs != nullptr);

		rspamd_ftok_t key;
		key.begin = "x";
		key.len = 1;
		auto *param = (struct rspamd_content_type_param *)
			g_hash_table_lookup(ct->attrs, &key);
		REQUIRE(param != nullptr);

		std::string_view value{param->value.begin, param->value.len};
		CHECK(value == "ab");

		rspamd_mempool_delete(pool);
	}
}

#endif// RSPAMD_CXX_UNIT_CONTENT_TYPE_HXX
