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

#include <cstring>
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

	/*
	 * Junk parameters in front used to hide the ones rspamd relies on: an RFC
	 * reader takes the charset or the filename from anywhere in the header
	 */
	TEST_CASE("parameters rspamd uses are kept past the cap")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string junk;
		for (int i = 0; i < 1100; i++) {
			junk += "; p" + std::to_string(i) + "=v";
		}

		std::string hdr = "text/html" + junk + "; charset=\"utf-16le\"; boundary=Zz";
		/* A plain name once: a second one past the cap is not stored */
		for (int i = 0; i < 1000; i++) {
			hdr += "; charset=koi8-r";
		}
		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK((ct->flags & RSPAMD_CONTENT_TYPE_BROKEN) != 0);
		CHECK(ct->nparams == expected_param_cap + 2);
		CHECK(std::string_view{ct->charset.begin, ct->charset.len} == "utf-16le");
		CHECK(std::string_view{ct->orig_boundary.begin, ct->orig_boundary.len} == "Zz");
		CHECK(g_hash_table_size(ct->attrs) == expected_param_cap + 2);

		std::string cd_hdr = "attachment" + junk + "; filename=\"invoice.pdf.js\"";
		for (int i = 0; i < 1000; i++) {
			cd_hdr += "; filename=x";
		}
		auto *cd = rspamd_content_disposition_parse(cd_hdr.data(), cd_hdr.size(), pool);
		REQUIRE(cd != nullptr);
		CHECK(std::string_view{cd->filename.begin, cd->filename.len} == "invoice.pdf.js");
		CHECK(g_hash_table_size(cd->attrs) == expected_param_cap + 1);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("pieces of a split parameter are kept past the cap")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string hdr = "multipart/mixed";
		for (int i = 0; i < 1100; i++) {
			hdr += "; p" + std::to_string(i) + "=v";
		}
		hdr += "; boundary*0=\"foo\"; boundary*1=\"bar\"";

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK(std::string_view{ct->orig_boundary.begin, ct->orig_boundary.len} == "foobar");

		/* 17 pieces, from before the cap or all past it */
		for (int junk: {1023, 1024}) {
			std::string cd_hdr = "attachment";
			for (int i = 0; i < junk; i++) {
				cd_hdr += "; p" + std::to_string(i) + "=v";
			}
			for (int i = 0; i < 16; i++) {
				cd_hdr += "; filename*" + std::to_string(i) + "=" + std::string(1, (char) ('a' + i));
			}
			cd_hdr += "; filename*16=.exe";

			auto *cd = rspamd_content_disposition_parse(cd_hdr.data(), cd_hdr.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK(std::string_view{cd->filename.begin, cd->filename.len} == "abcdefghijklmnop.exe");
		}

		rspamd_mempool_delete(pool);
	}

	/* Names the RFC 2231 handling stores as they are must not get around the bound */
	TEST_CASE("starred names do not lift the cap")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string junk;
		for (int i = 0; i < 1100; i++) {
			junk += "; p" + std::to_string(i) + "=v";
		}

		std::string hdr = "text/plain" + junk;
		std::string cd_hdr = "attachment" + junk;
		for (int i = 0; i < 5000; i++) {
			hdr += "; charset*x=1; name**=1";
			cd_hdr += "; filename*x=1";
		}

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK(ct->nparams <= expected_param_cap + 16);
		CHECK(g_hash_table_size(ct->attrs) <= expected_param_cap + 16);

		unsigned int stored = 0;
		auto *cd = rspamd_content_disposition_parse(cd_hdr.data(), cd_hdr.size(), pool);
		REQUIRE(cd != nullptr);
		CHECK(cd->nparams <= expected_param_cap + 16);
		GHashTableIter it;
		gpointer k, v;
		g_hash_table_iter_init(&it, cd->attrs);
		while (g_hash_table_iter_next(&it, &k, &v)) {
			for (auto *p = static_cast<rspamd_content_type_param *>(v); p != nullptr; p = p->next) {
				stored++;
			}
		}
		CHECK(stored <= expected_param_cap + 16);

		rspamd_mempool_delete(pool);
	}

	/*
	 * Copies of one parameter past the cap used to take the room of the
	 * others, and junk names with a star that of the pieces of a value
	 */
	TEST_CASE("parameters past the cap are not crowded out by others")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string junk;
		for (int i = 0; i < 1100; i++) {
			junk += "; p" + std::to_string(i) + "=v";
		}

		std::string copies;
		for (int i = 0; i < 100; i++) {
			copies += "; name*0=x; charset*x=1; boundary*1x=z; filename*1=w";
		}
		/* Once: copies of a piece end the pieces of that name, as in readers */
		copies += "; boundary*99=y";

		std::string hdr = "multipart/mixed" + junk + copies +
						  "; charset=\"utf-16le\"; boundary*0=\"foo\"; boundary*1=\"bar\"";
		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK(std::string_view{ct->charset.begin, ct->charset.len} == "utf-16le");
		CHECK(std::string_view{ct->orig_boundary.begin, ct->orig_boundary.len} == "foobar");
		/* Once each: name*0, boundary*99, filename*1, the charset and two pieces */
		CHECK(ct->nparams == expected_param_cap + 6);

		std::string cd_hdr = "attachment" + junk + copies + "; filename=\"invoice.pdf.exe\"";
		auto *cd = rspamd_content_disposition_parse(cd_hdr.data(), cd_hdr.size(), pool);
		REQUIRE(cd != nullptr);
		CHECK(std::string_view{cd->filename.begin, cd->filename.len} == "invoice.pdf.exe");

		rspamd_mempool_delete(pool);
	}

	/* Readers take the plain value then: a.exe, not a.exew */
	TEST_CASE("a plain parameter is not merged into pieces without a first one")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		const std::pair<std::string, std::string> cases[] = {
			{"attachment; filename*1=w; filename=\"invoice.pdf.exe\"", "invoice.pdf.exe"},
			{"attachment; filename=\"invoice.pdf.exe\"; filename*1=w", "invoice.pdf.exe"},
			{"attachment; filename*1=b; filename*0=a; filename=\"x.exe\"", "ab"},
			/* No piece 0 for readers: a leading zero, a number that wraps, a quoted extended one */
			{"attachment; filename*00=\"invoice.pdf\"; filename=\"invoice.pdf.exe\"", "invoice.pdf.exe"},
			{"attachment; filename*4294967296=\"invoice.pdf\"; filename=\"invoice.pdf.exe\"", "invoice.pdf.exe"},
			{"attachment; filename*0*=\"invoice.pdf\"; filename=\"invoice.exe\"", "invoice.exe"},
			/* name*= before pieces, whatever the order (Thunderbird) */
			{"attachment; filename*0=invoice.pdf; filename*=utf-8''invoice.exe", "invoice.exe"},
			/* A repeated piece ends them */
			{"attachment; filename*0=a; filename*0=b; filename*1=c", "a"},
		};

		for (const auto &[hdr, expected]: cases) {
			auto *cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK(std::string_view{cd->filename.begin, cd->filename.len} == expected);
		}

		/* Pieces joined into nothing are no value */
		std::string hdr = "application/octet-stream; name*0=; name=\"invoice.pdf.exe\"";
		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		rspamd_ftok_t key;
		key.begin = "name";
		key.len = 4;
		auto *param = (struct rspamd_content_type_param *) g_hash_table_lookup(ct->attrs, &key);
		REQUIRE(param != nullptr);
		CHECK(std::string_view{param->value.begin, param->value.len} == "invoice.pdf.exe");

		rspamd_mempool_delete(pool);
	}

	/* As Thunderbird: values that do not decode are no value, empty pieces are pieces */
	TEST_CASE("RFC 2231 values readers do not take")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		const std::pair<std::string, std::string> cases[] = {
			{"attachment; filename*0=\"invoice\"; filename*1=\"\"; filename*2=\".exe\"", "invoice.exe"},
			{"attachment; filename*0=evil.exe; filename*=utf-8''good%FF.pdf", "evil.exe"},
			{"attachment; filename*0=evil.exe; filename*=utf-8''good%ZZ.pdf", "evil.exe"},
			{"attachment; filename*0*=utf-8''good%FF.pdf; filename=\"evil.exe\"", "evil.exe"},
			/* No value readers take: the pieces as they hold, decoded */
			{"attachment; filename*0*=\"utf-8''invoice%2Eexe\"", "invoice.exe"},
			/* An empty name*= is no value, nor one that does not decode, first or not */
			{"attachment; filename*=\"\"; filename=\"evil.exe\"", "evil.exe"},
			{"attachment; filename*=utf-8''good%FF.pdf; filename=\"evil.exe\"", "evil.exe"},
			{"attachment; filename*0=evil.exe; filename*=utf-8''%FF; filename*=utf-8''good.pdf", "evil.exe"},
			/* A plain value first is taken, as in Python; the first of several */
			{"attachment; filename=\"good.pdf\"; filename*=utf-8''evil.exe", "good.pdf"},
			{"attachment; filename=\"good.pdf\"; filename*0=evil; filename*1=.exe", "good.pdf"},
			{"attachment; filename=\"a.exe\"; filename=\"b.pdf\"", "a.exe"},
			/* An empty value does not end the parameters, and an empty piece is a piece */
			{"attachment; foo=; filename=x.exe", "x.exe"},
			{"attachment; filename*0=\"invoice\"; filename*1=; filename*2=\".exe\"", "invoice.exe"},
			/* ASCII is valid under any label, even one ICU cannot open */
			{"attachment; filename=\"invoice.exe\"; filename*=de''invoice.exe; filename*0=invoice.pdf", "invoice.exe"},
			/* The last name*= names the charset of the first one, a later one is piece 0 */
			{"attachment; filename*=koi8-r''%F3%DE%C5%D4.pdf; filename*=utf-8''invoice.exe; filename=\"x.pdf\"",
			 "invoice.exe"},
			/* x-user-defined: the bytes past ASCII are U+F780 to U+F7FF */
			{"attachment; filename*0=invoice.pdf; filename*=x-user-defined''invoice%FF.exe", "invoice\uF7FF.exe"},
			/* Readers check escapes in the data only, and no charset is not checked */
			{"attachment; filename*0=invoice.pdf; filename*=utf-8'%'invoice.exe", "invoice.exe"},
			{"attachment; filename*0=invoice.pdf; filename*=x-cp1251''%D1%F7%E5%F2.exe", "\u0421\u0447\u0435\u0442.exe"},
			/* Percent decoding as readers do it: '+' stays, and so does a bad escape in a piece */
			{"attachment; filename*=utf-8''a+b.exe", "a+b.exe"},
			{"attachment; filename*0*=utf-8''a+b; filename*1*=%2Bc.exe", "a+b+c.exe"},
			{"attachment; filename*0*=utf-8''a%ZZ; filename*1*=%2.exe", "a%ZZ%2.exe"},
		};

		for (const auto &c: cases) {
			auto *cd = rspamd_content_disposition_parse(c.first.data(), c.first.size(), pool);
			REQUIRE(cd != nullptr);
			std::string_view fname{cd->filename.begin, cd->filename.len};
			CHECK_MESSAGE(fname == c.second, c.first);
		}

		/* A charset that writes its characters in ASCII is decoded all the same */
		{
			std::string hdr = "application/octet-stream; name*=iso-2022-jp''%1B%24B%25F%259%25H%1B%28B.txt; "
							  "name=\"x.txt\"";
			auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(ct != nullptr);
			rspamd_ftok_t key;
			key.begin = "name";
			key.len = 4;
			auto *param = (struct rspamd_content_type_param *) g_hash_table_lookup(ct->attrs, &key);
			REQUIRE(param != nullptr);
			CHECK(std::string_view{param->value.begin, param->value.len} == "\u30C6\u30B9\u30C8.txt");
		}

		/* The boundary as readers take it */
		{
			std::string hdr = "multipart/mixed; boundary*=windows-1251''%D1%F7; boundary*=utf-8''evil; boundary=\"good\"";
			auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(ct != nullptr);
			CHECK(std::string_view{ct->orig_boundary.begin, ct->orig_boundary.len} == "evil");
		}

		/* Pieces without a first one are no value: the name of Content-Type is taken */
		{
			const char *msg_cd = "attachment; filename*1=x.pdf";
			auto *cd = rspamd_content_disposition_parse(msg_cd, strlen(msg_cd), pool);
			REQUIRE(cd != nullptr);
			rspamd_ftok_t key;
			key.begin = "filename";
			key.len = 8;
			auto *param = (struct rspamd_content_type_param *) g_hash_table_lookup(cd->attrs, &key);
			REQUIRE(param != nullptr);
			CHECK((param->flags & RSPAMD_CONTENT_PARAM_NO_VALUE) != 0);
		}

		/* An empty charset is not checked, as in readers */
		{
			std::string hdr = "attachment; filename*0=invoice.pdf; filename*=''invoice%E9.exe";
			auto *cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK(std::string_view{cd->filename.begin, cd->filename.len}.ends_with(".exe"));
		}

		/* A charset that ICU cannot open, with nothing else to take */
		for (const char *charset: {"x-mac-thai", "johab"}) {
			std::string hdr = std::string{"attachment; filename*0*="} + charset + "''abc.exe";
			auto *cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK(std::string_view{cd->filename.begin, cd->filename.len}.ends_with("abc.exe"));

			hdr = std::string{"attachment; filename*="} + charset + "''abc.exe";
			cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK(std::string_view{cd->filename.begin, cd->filename.len} == "abc.exe");

			/* Readers take the first name*=, which does not decode, then the pieces */
			hdr = std::string{"attachment; filename*0=good.pdf; filename*="} + charset +
				  "''abc; filename*=utf-8''evil.exe";
			cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK(std::string_view{cd->filename.begin, cd->filename.len} != "evil.exe");

			std::string ct_hdr = std::string{"text/plain; charset*0*="} + charset + "''koi8-r";
			CHECK(rspamd_content_type_parse(ct_hdr.data(), ct_hdr.size(), pool) != nullptr);
		}

		/* Past the cap too: an empty name*= is no value, a repeated piece ends them */
		std::string junk;
		for (int i = 0; i < 1030; i++) {
			junk += "; p" + std::to_string(i) + "=v";
		}
		const std::pair<std::string, std::string> cap_cases[] = {
			{"; filename*0=good.pdf; filename*=utf-8''; filename*=utf-8''evil.exe", "evil.exe"},
			{"; filename*0=\"a.exe\"; filename*1=\"x\"; filename*1=\"y\"; filename*2=\".pdf\"", "a.exex"},
			{"; filename*0=good.pdf; filename*=utf-8''a%ZZ; filename*=utf-8''evil.exe", "evil.exe"},
			/* Values readers take no data of still name the charset */
			{"; filename*=utf-8''invoice+AC4-exe; filename*=utf-7''", "invoice.exe"},
			{"; filename*=utf-8''invoice+AC4-exe; filename*=utf-8''b; filename*=utf-8''c; filename*=utf-7''",
			 "invoice.exe"},
			{"; filename*0*=utf-8''invoice+AC4-exe; filename*0*=utf-7''x", "invoice.exe"},
			{"; filename*0*=utf-7''; filename*0*=utf-8''a.exe", "a.exe"},
			/* A third name*= ends the pieces, a quoted second one leaves piece 0 to the next */
			{"; filename*=utf-8''%FF; filename*=utf-8''evil; filename*1=.exe; filename*=utf-8''z; filename*2=.txt",
			 "evil.exe"},
			{"; filename*=utf-8''%FF; filename*=\"utf-8''q\"; filename*=utf-8''evil.exe", "evil.exe"},
			/* A first value that is no value still makes a plain one after it no first one */
			{"; filename*=utf-8''; filename=a.txt; filename*=utf-8''evil.exe", "evil.exe"},
			{"; filename*0*=\"utf-8''x\"; filename=a.txt; filename*=utf-8''evil.exe", "evil.exe"},
			{"; filename*0*=utf-8''; filename=a.txt; filename*0*=utf-8''evil.exe", "evil.exe"},
		};

		/* As readers take them, and the same past the cap */
		for (const auto &c: cap_cases) {
			for (const auto *pad: {"", junk.c_str()}) {
				std::string hdr = "attachment" + std::string{pad} + c.first;
				auto *cd = rspamd_content_disposition_parse(hdr.data(), hdr.size(), pool);
				REQUIRE(cd != nullptr);
				std::string_view fname{cd->filename.begin, cd->filename.len};
				CHECK_MESSAGE(fname == c.second, c.first);
			}
		}

		for (const auto *pad: {"", junk.c_str()}) {
			std::string hdr = "multipart/mixed" + std::string{pad} +
							  "; boundary*=us-ascii''; boundary=AAA; boundary*=us-ascii''BBB";
			auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(ct != nullptr);
			CHECK(std::string_view{ct->orig_boundary.begin, ct->orig_boundary.len} == "BBB");
		}

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
		/*
		 * Readers take no piece numbered above 999 (Thunderbird), so that one
		 * is another parameter now; pieces given out of order are joined in
		 * their order
		 */
		const std::pair<std::string, std::string> cases[] = {
			{"text/plain; x*0=a; x*3000000000=b", "a"},
			{"text/plain; x*1=b; x*0=a", "ab"},
		};

		for (const auto &[hdr, expected]: cases) {
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
			CHECK(value == expected);
		}

		rspamd_mempool_delete(pool);
	}

	/* The value of a parameter of a Content-Type, as parsed */
	static std::string ct_param_value(struct rspamd_content_type * ct, const char *name)
	{
		rspamd_ftok_t key;
		key.begin = name;
		key.len = strlen(name);

		if (ct->attrs == nullptr) {
			return "<no attrs>";
		}

		auto *param = (struct rspamd_content_type_param *) g_hash_table_lookup(ct->attrs, &key);

		if (param == nullptr) {
			return "<no param>";
		}

		return std::string{param->value.begin, param->value.len};
	}

	TEST_CASE("many distinct RFC 2231 names resolve correctly")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		/* Each name is its own chain of one value; under the cap of 1024 parameters */
		std::string hdr = "text/plain";
		for (int i = 0; i < 1000; i++) {
			hdr += "; p" + std::to_string(i) + "*=utf-8''v" + std::to_string(i);
		}

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK(ct->nparams == 1000);
		CHECK(ct_param_value(ct, "p0") == "v0");
		CHECK(ct_param_value(ct, "p1") == "v1");
		CHECK(ct_param_value(ct, "p500") == "v500");
		CHECK(ct_param_value(ct, "p999") == "v999");

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("a high piece number alone")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string hdr = "text/plain; name*999=x";

		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		/* No piece 0: kept as it is, flagged */
		CHECK(ct_param_value(ct, "name") == "x");

		rspamd_ftok_t key;
		key.begin = "name";
		key.len = 4;
		auto *param = (struct rspamd_content_type_param *) g_hash_table_lookup(ct->attrs, &key);
		REQUIRE(param != nullptr);
		CHECK((param->flags & RSPAMD_CONTENT_PARAM_NO_VALUE) != 0);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("pieces of short and long chains are joined in order")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";

		/* 5 pieces are a short chain, 26 a long one; in order and reversed */
		for (size_t count: {5, 16, 17, 26}) {
			for (bool reversed: {false, true}) {
				std::string hdr = "text/plain";
				for (size_t i = 0; i < count; i++) {
					size_t n = reversed ? count - 1 - i : i;
					hdr += "; x*" + std::to_string(n) + "=" + std::string(1, alphabet[n]);
				}

				auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
				REQUIRE(ct != nullptr);
				CHECK_MESSAGE(ct_param_value(ct, "x") == alphabet.substr(0, count), hdr);
			}
		}

		/* The run stops at a missing piece, in both */
		{
			std::string hdr = "text/plain; x*0=a; x*1=b; x*3=d";
			auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(ct != nullptr);
			CHECK(ct_param_value(ct, "x") == "ab");

			hdr = "text/plain";
			for (int i = 0; i < 26; i++) {
				if (i != 10) {
					hdr += "; x*" + std::to_string(i) + "=" + std::string(1, alphabet[i]);
				}
			}
			ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
			REQUIRE(ct != nullptr);
			CHECK(ct_param_value(ct, "x") == "abcdefghij");
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("quoted pairs of a quoted value are unescaped")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		std::string hdr = "multipart/mixed; boundary=\"A\\\"B\"; foo=1";
		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);
		CHECK(std::string_view{ct->boundary.begin, ct->boundary.len} == "a\"b");
		CHECK(std::string_view{ct->orig_boundary.begin, ct->orig_boundary.len} == "A\"B");
		CHECK(ct_param_value(ct, "foo") == "1");

		const std::pair<std::string, std::string> cases[] = {
			{"text/plain; name=\"a\\\\b.txt\"", "a\\b.txt"},
			{"text/plain; name=\"a\\b\"", "ab"},
			{"text/plain; name=\"a\\\\\"", "a\\"},
			{"text/plain; name=\"a\\\\\"; foo=bar", "a\\"},
			{"text/plain; name=\"\\\"\\\"\"", "\"\""},
			/* Unquoted tokens keep their backslashes */
			{"text/plain; name=a\\b", "a\\b"},
		};

		for (const auto &[h, expected]: cases) {
			ct = rspamd_content_type_parse(h.data(), h.size(), pool);
			REQUIRE(ct != nullptr);
			CHECK_MESSAGE(ct_param_value(ct, "name") == expected, h);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("quoted pairs of a quoted content-disposition value are unescaped")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"cd-test", 0);
		const std::pair<std::string, std::string> cases[] = {
			{"attachment; filename=\"a\\\"b.txt\"", "a\"b.txt"},
			{"attachment; filename=\"a\\\\b.txt\"", "a\\b.txt"},
			{"attachment; filename=\"a\\b\"", "ab"},
			{"attachment; filename=\"a\\\\\"", "a\\"},
			{"attachment; filename=\"a\\\\\"; foo=bar", "a\\"},
		};

		for (const auto &[h, expected]: cases) {
			auto *cd = rspamd_content_disposition_parse(h.data(), h.size(), pool);
			REQUIRE(cd != nullptr);
			CHECK_MESSAGE((std::string_view{cd->filename.begin, cd->filename.len} == expected), h);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("lowercasing a parameter value keeps its new length")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);
		/* U+212A KELVIN SIGN (3 bytes) lowercases to 'k' (1 byte): "kabc" is 4 bytes, not 6 */
		std::string hdr = "text/plain; foo=\xE2\x84\xAA"
						  "ABC";
		auto *ct = rspamd_content_type_parse(hdr.data(), hdr.size(), pool);
		REQUIRE(ct != nullptr);

		std::string value = ct_param_value(ct, "foo");
		CHECK(value.size() == 4);
		CHECK(value == "kabc");

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("empty type with parameters is rejected without leaking")
	{
		/*
		 * The parameter table is created while parsing, before the parser
		 * finds out that the type is empty and rejects the value. It must
		 * still be released with the pool (LeakSanitizer reports it at exit
		 * otherwise).
		 */
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"ct-test", 0);

		for (const auto *hdr: {";a=\"b\"; c=d", "; name*0*=us-ascii''a; name*1=b", " ;a=b"}) {
			CAPTURE(hdr);
			auto *ct = rspamd_content_type_parse(hdr, strlen(hdr), pool);
			CHECK(ct == nullptr);
		}

		rspamd_mempool_delete(pool);
	}
}

#endif// RSPAMD_CXX_UNIT_CONTENT_TYPE_HXX
