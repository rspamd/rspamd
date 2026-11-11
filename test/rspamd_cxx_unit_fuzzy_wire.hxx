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

/* Detached unit tests for the fuzzy wire extensions */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_FUZZY_WIRE_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_FUZZY_WIRE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"
#include "libserver/fuzzy_wire.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace rspamd::test::fuzzy_wire {

using ext_ptr = std::unique_ptr<struct rspamd_fuzzy_cmd_extension, decltype(&g_free)>;

static auto parse(const std::vector<unsigned char> &buf) -> std::pair<bool, ext_ptr>
{
	struct rspamd_fuzzy_cmd_extension *res = nullptr;
	auto ok = rspamd_fuzzy_extensions_from_wire(buf.data(), buf.size(), &res);

	return {ok != FALSE, ext_ptr{res, g_free}};
}

static auto count(const struct rspamd_fuzzy_cmd_extension *head) -> unsigned int
{
	unsigned int n = 0;

	for (auto *cur = head; cur != nullptr; cur = cur->next) {
		n++;
	}

	return n;
}

static auto find(const struct rspamd_fuzzy_cmd_extension *head, int type)
	-> const struct rspamd_fuzzy_cmd_extension *
{
	for (auto *cur = head; cur != nullptr; cur = cur->next) {
		if ((int) cur->ext == type) {
			return cur;
		}
	}

	return nullptr;
}

static auto append_facts(std::vector<unsigned char> &buf, uint32_t facts) -> void
{
	buf.push_back(RSPAMD_FUZZY_EXT_SENDER_FACTS);
	buf.push_back(RSPAMD_FUZZY_SENDER_FACTS_LEN);
	buf.push_back((facts >> 24) & 0xff);
	buf.push_back((facts >> 16) & 0xff);
	buf.push_back((facts >> 8) & 0xff);
	buf.push_back(facts & 0xff);
}

/* The three extensions every client has been sending since forever */
static auto legacy_extensions() -> std::vector<unsigned char>
{
	std::vector<unsigned char> buf = {RSPAMD_FUZZY_EXT_SOURCE_DOMAIN, 11};

	for (auto c: std::string("example.com")) {
		buf.push_back((unsigned char) c);
	}

	buf.push_back(RSPAMD_FUZZY_EXT_SOURCE_IP4);
	buf.insert(buf.end(), {192, 0, 2, 1});

	return buf;
}

static auto decode_facts(const struct rspamd_fuzzy_cmd_extension *ext) -> uint32_t
{
	uint32_t v;

	memcpy(&v, ext->payload, sizeof(v));

	return GUINT32_FROM_BE(v);
}

}// namespace rspamd::test::fuzzy_wire

TEST_SUITE("rspamd_fuzzy_wire")
{
	using namespace rspamd::test::fuzzy_wire;

	TEST_CASE("legacy extensions still parse")
	{
		auto [ok, exts] = parse(legacy_extensions());

		REQUIRE(ok);
		REQUIRE(exts != nullptr);
		CHECK(count(exts.get()) == 2);

		auto *dom = find(exts.get(), RSPAMD_FUZZY_EXT_SOURCE_DOMAIN);
		REQUIRE(dom != nullptr);
		CHECK(std::string((const char *) dom->payload, dom->length) == "example.com");

		auto *ip = find(exts.get(), RSPAMD_FUZZY_EXT_SOURCE_IP4);
		REQUIRE(ip != nullptr);
		CHECK(ip->length == 4);
		CHECK(ip->payload[0] == 192);
		CHECK(ip->payload[3] == 1);
	}

	TEST_CASE("empty extensions area")
	{
		auto [ok, exts] = parse({});

		CHECK(ok);
		CHECK(exts == nullptr);
	}

	TEST_CASE("ipv6 source")
	{
		std::vector<unsigned char> buf = {RSPAMD_FUZZY_EXT_SOURCE_IP6};
		buf.insert(buf.end(), 16, 0xaa);

		auto [ok, exts] = parse(buf);

		REQUIRE(ok);
		REQUIRE(exts != nullptr);
		CHECK(exts->ext == RSPAMD_FUZZY_EXT_SOURCE_IP6);
		CHECK(exts->length == 16);
	}

	TEST_CASE("sender facts round trip")
	{
		struct test_case {
			unsigned int spf, dkim, dmarc, ptr, rcpts;
			bool ptr_generic, tls;
		};

		std::vector<test_case> cases = {
			{RSPAMD_FUZZY_SF_SPF_ABSENT, RSPAMD_FUZZY_SF_DKIM_ABSENT,
			 RSPAMD_FUZZY_SF_DMARC_ABSENT, RSPAMD_FUZZY_SF_PTR_UNKNOWN,
			 RSPAMD_FUZZY_SF_RCPTS_ONE, false, false},
			{RSPAMD_FUZZY_SF_SPF_PASS, RSPAMD_FUZZY_SF_DKIM_PASS,
			 RSPAMD_FUZZY_SF_DMARC_PASS, RSPAMD_FUZZY_SF_PTR_CONFIRMED,
			 RSPAMD_FUZZY_SF_RCPTS_FEW, false, true},
			{RSPAMD_FUZZY_SF_SPF_TEMPERROR, RSPAMD_FUZZY_SF_DKIM_TEMPERROR,
			 RSPAMD_FUZZY_SF_DMARC_TEMPERROR, RSPAMD_FUZZY_SF_PTR_NONE,
			 RSPAMD_FUZZY_SF_RCPTS_BULK, true, true},
			{RSPAMD_FUZZY_SF_SPF_SOFTFAIL, RSPAMD_FUZZY_SF_DKIM_FAIL,
			 RSPAMD_FUZZY_SF_DMARC_FAIL_REJECT, RSPAMD_FUZZY_SF_PTR_PRESENT,
			 RSPAMD_FUZZY_SF_RCPTS_MANY, true, false},
		};

		/* Every enumerated value of every field must survive the round trip */
		for (unsigned int spf = 0; spf <= RSPAMD_FUZZY_SF_SPF_TEMPERROR; spf++) {
			cases.push_back({spf, RSPAMD_FUZZY_SF_DKIM_NONE,
							 RSPAMD_FUZZY_SF_DMARC_NO_RECORD,
							 RSPAMD_FUZZY_SF_PTR_NONE, RSPAMD_FUZZY_SF_RCPTS_ONE,
							 false, false});
		}

		for (unsigned int dkim = 0; dkim <= RSPAMD_FUZZY_SF_DKIM_TEMPERROR; dkim++) {
			cases.push_back({RSPAMD_FUZZY_SF_SPF_NONE, dkim,
							 RSPAMD_FUZZY_SF_DMARC_NO_RECORD,
							 RSPAMD_FUZZY_SF_PTR_NONE, RSPAMD_FUZZY_SF_RCPTS_ONE,
							 false, false});
		}

		for (unsigned int dmarc = 0; dmarc <= RSPAMD_FUZZY_SF_DMARC_TEMPERROR; dmarc++) {
			cases.push_back({RSPAMD_FUZZY_SF_SPF_NONE, RSPAMD_FUZZY_SF_DKIM_NONE,
							 dmarc, RSPAMD_FUZZY_SF_PTR_NONE,
							 RSPAMD_FUZZY_SF_RCPTS_ONE, false, false});
		}

		for (unsigned int ptr = 0; ptr <= RSPAMD_FUZZY_SF_PTR_CONFIRMED; ptr++) {
			for (unsigned int rcpts = 0; rcpts <= RSPAMD_FUZZY_SF_RCPTS_BULK; rcpts++) {
				cases.push_back({RSPAMD_FUZZY_SF_SPF_NONE,
								 RSPAMD_FUZZY_SF_DKIM_NONE,
								 RSPAMD_FUZZY_SF_DMARC_NO_RECORD, ptr, rcpts,
								 true, true});
			}
		}

		for (const auto &c: cases) {
			auto packed = rspamd_fuzzy_sf_pack(c.spf, c.dkim, c.dmarc, c.ptr,
											   c.ptr_generic, c.rcpts, c.tls);

			/* Reserved bits are never written */
			CHECK((packed & RSPAMD_FUZZY_SF_RESERVED_MASK) == 0);
			CHECK(((packed >> RSPAMD_FUZZY_SENDER_FACTS_CLASS_SHIFT) &
				   RSPAMD_FUZZY_SENDER_FACTS_CLASS_MASK) ==
				  RSPAMD_FUZZY_SENDER_FACTS_CLASS_V0);

			std::vector<unsigned char> buf;
			append_facts(buf, packed);

			auto [ok, exts] = parse(buf);
			REQUIRE(ok);
			REQUIRE(exts != nullptr);
			REQUIRE(exts->ext == RSPAMD_FUZZY_EXT_SENDER_FACTS);
			REQUIRE(exts->length == RSPAMD_FUZZY_SENDER_FACTS_LEN);

			auto val = decode_facts(exts.get());
			CHECK(val == packed);
			CHECK(((val >> RSPAMD_FUZZY_SF_SPF_SHIFT) & RSPAMD_FUZZY_SF_SPF_MASK) == c.spf);
			CHECK(((val >> RSPAMD_FUZZY_SF_DKIM_SHIFT) & RSPAMD_FUZZY_SF_DKIM_MASK) == c.dkim);
			CHECK(((val >> RSPAMD_FUZZY_SF_DMARC_SHIFT) & RSPAMD_FUZZY_SF_DMARC_MASK) == c.dmarc);
			CHECK(((val >> RSPAMD_FUZZY_SF_PTR_SHIFT) & RSPAMD_FUZZY_SF_PTR_MASK) == c.ptr);
			CHECK((bool) ((val >> RSPAMD_FUZZY_SF_PTR_GENERIC_SHIFT) & 1u) == c.ptr_generic);
			CHECK(((val >> RSPAMD_FUZZY_SF_RCPTS_SHIFT) & RSPAMD_FUZZY_SF_RCPTS_MASK) == c.rcpts);
			CHECK((bool) ((val >> RSPAMD_FUZZY_SF_TLS_SHIFT) & 1u) == c.tls);
		}
	}

	TEST_CASE("sender facts reserved bits are ignored on read")
	{
		auto packed = rspamd_fuzzy_sf_pack(RSPAMD_FUZZY_SF_SPF_FAIL,
										   RSPAMD_FUZZY_SF_DKIM_FAIL,
										   RSPAMD_FUZZY_SF_DMARC_FAIL_QUARANTINE,
										   RSPAMD_FUZZY_SF_PTR_CONFIRMED, true,
										   RSPAMD_FUZZY_SF_RCPTS_MANY, true);

		std::vector<unsigned char> buf;
		/* A future version that has started using the reserved area */
		append_facts(buf, packed | RSPAMD_FUZZY_SF_RESERVED_MASK);

		auto [ok, exts] = parse(buf);
		REQUIRE(ok);
		REQUIRE(exts != nullptr);

		auto val = decode_facts(exts.get());
		CHECK((val & ~RSPAMD_FUZZY_SF_RESERVED_MASK) == packed);
		CHECK(((val >> RSPAMD_FUZZY_SF_SPF_SHIFT) & RSPAMD_FUZZY_SF_SPF_MASK) ==
			  RSPAMD_FUZZY_SF_SPF_FAIL);
		CHECK(((val >> RSPAMD_FUZZY_SF_RCPTS_SHIFT) & RSPAMD_FUZZY_SF_RCPTS_MASK) ==
			  RSPAMD_FUZZY_SF_RCPTS_MANY);
	}

	TEST_CASE("string tables agree with the enums")
	{
		CHECK(rspamd_fuzzy_sf_spf_str(RSPAMD_FUZZY_SF_SPF_ABSENT) == nullptr);
		CHECK(std::string(rspamd_fuzzy_sf_spf_str(RSPAMD_FUZZY_SF_SPF_SOFTFAIL)) == "softfail");
		CHECK(std::string(rspamd_fuzzy_sf_spf_str(RSPAMD_FUZZY_SF_SPF_TEMPERROR)) == "temperror");
		CHECK(rspamd_fuzzy_sf_spf_str(RSPAMD_FUZZY_SF_SPF_TEMPERROR + 1) == nullptr);

		CHECK(rspamd_fuzzy_sf_dkim_str(RSPAMD_FUZZY_SF_DKIM_ABSENT) == nullptr);
		CHECK(std::string(rspamd_fuzzy_sf_dkim_str(RSPAMD_FUZZY_SF_DKIM_PERMERROR)) == "permerror");
		CHECK(rspamd_fuzzy_sf_dkim_str(RSPAMD_FUZZY_SF_DKIM_TEMPERROR + 1) == nullptr);

		CHECK(rspamd_fuzzy_sf_dmarc_str(RSPAMD_FUZZY_SF_DMARC_ABSENT) == nullptr);
		CHECK(std::string(rspamd_fuzzy_sf_dmarc_str(RSPAMD_FUZZY_SF_DMARC_FAIL_REJECT)) == "fail_reject");
		CHECK(rspamd_fuzzy_sf_dmarc_str(RSPAMD_FUZZY_SF_DMARC_TEMPERROR + 1) == nullptr);

		CHECK(rspamd_fuzzy_sf_ptr_str(RSPAMD_FUZZY_SF_PTR_UNKNOWN) == nullptr);
		CHECK(std::string(rspamd_fuzzy_sf_ptr_str(RSPAMD_FUZZY_SF_PTR_CONFIRMED)) == "confirmed");

		CHECK(std::string(rspamd_fuzzy_sf_rcpts_str(RSPAMD_FUZZY_SF_RCPTS_ONE)) == "1");
		CHECK(std::string(rspamd_fuzzy_sf_rcpts_str(RSPAMD_FUZZY_SF_RCPTS_BULK)) == "21+");
		CHECK(rspamd_fuzzy_sf_rcpts_str(RSPAMD_FUZZY_SF_RCPTS_BULK + 1) == nullptr);
	}

	TEST_CASE("unknown skippable extension is skipped")
	{
		auto buf = legacy_extensions();

		/* Something a future client sends and we know nothing about */
		buf.push_back(RSPAMD_FUZZY_EXT_SKIPPABLE_MIN + 0x20);
		buf.push_back(3);
		buf.insert(buf.end(), {1, 2, 3});

		append_facts(buf, rspamd_fuzzy_sf_pack(RSPAMD_FUZZY_SF_SPF_PASS,
											   RSPAMD_FUZZY_SF_DKIM_NONE,
											   RSPAMD_FUZZY_SF_DMARC_NO_RECORD,
											   RSPAMD_FUZZY_SF_PTR_CONFIRMED,
											   false, RSPAMD_FUZZY_SF_RCPTS_ONE,
											   true));

		/* And another one, this time at the very end and empty */
		buf.push_back(0xff);
		buf.push_back(0);

		auto [ok, exts] = parse(buf);

		REQUIRE(ok);
		REQUIRE(exts != nullptr);
		/* Domain, ip4 and sender facts: the two unknown ones are dropped */
		CHECK(count(exts.get()) == 3);

		auto *dom = find(exts.get(), RSPAMD_FUZZY_EXT_SOURCE_DOMAIN);
		REQUIRE(dom != nullptr);
		CHECK(std::string((const char *) dom->payload, dom->length) == "example.com");

		auto *ip = find(exts.get(), RSPAMD_FUZZY_EXT_SOURCE_IP4);
		REQUIRE(ip != nullptr);
		CHECK(ip->payload[0] == 192);

		auto *facts = find(exts.get(), RSPAMD_FUZZY_EXT_SENDER_FACTS);
		REQUIRE(facts != nullptr);
		CHECK(((decode_facts(facts) >> RSPAMD_FUZZY_SF_SPF_SHIFT) &
			   RSPAMD_FUZZY_SF_SPF_MASK) == RSPAMD_FUZZY_SF_SPF_PASS);
	}

	TEST_CASE("sender facts of the wrong declared length are rejected")
	{
		/* The type is known and fixed width, so any other length is malformed */
		for (unsigned int len: {0, 1, 2, 3, 5, 6, 8, 16, 255}) {
			CAPTURE(len);

			std::vector<unsigned char> buf = {RSPAMD_FUZZY_EXT_SENDER_FACTS,
											  (unsigned char) len};
			buf.insert(buf.end(), len, 0);

			auto [ok, exts] = parse(buf);
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("a wrong length invalidates the whole command")
		{
			/* Not merely the offending entry: the legacy ones go too */
			auto buf = legacy_extensions();
			buf.push_back(RSPAMD_FUZZY_EXT_SENDER_FACTS);
			buf.push_back(8);
			buf.insert(buf.end(), 8, 0);

			auto [ok, exts] = parse(buf);
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("the exact length is still accepted")
		{
			std::vector<unsigned char> buf;
			append_facts(buf, rspamd_fuzzy_sf_pack(RSPAMD_FUZZY_SF_SPF_PASS,
												   RSPAMD_FUZZY_SF_DKIM_PASS,
												   RSPAMD_FUZZY_SF_DMARC_PASS,
												   RSPAMD_FUZZY_SF_PTR_CONFIRMED,
												   false,
												   RSPAMD_FUZZY_SF_RCPTS_ONE,
												   true));

			auto [ok, exts] = parse(buf);
			REQUIRE(ok);
			REQUIRE(exts != nullptr);
			CHECK(exts->length == RSPAMD_FUZZY_SENDER_FACTS_LEN);
		}

		SUBCASE("other skippable types keep accepting any length")
		{
			/* The strictness must not leak into types we know nothing about */
			for (unsigned int len: {0, 1, 4, 7, 32}) {
				CAPTURE(len);

				std::vector<unsigned char> buf = {RSPAMD_FUZZY_EXT_SKIPPABLE_MIN + 3,
												  (unsigned char) len};
				buf.insert(buf.end(), len, 0);

				auto [ok, exts] = parse(buf);
				CHECK(ok);
				CHECK(exts == nullptr);
			}
		}
	}

	TEST_CASE("a buffer of only unknown skippable extensions is accepted")
	{
		std::vector<unsigned char> buf = {RSPAMD_FUZZY_EXT_SKIPPABLE_MIN + 1, 2, 0, 0};

		auto [ok, exts] = parse(buf);

		CHECK(ok);
		CHECK(exts == nullptr);
	}

	TEST_CASE("unknown non skippable extension is rejected")
	{
		auto buf = legacy_extensions();

		/* Its length is implied by the type, so we cannot skip over it */
		buf.push_back('x');
		buf.insert(buf.end(), {1, 2, 3});

		auto [ok, exts] = parse(buf);

		CHECK(!ok);
		CHECK(exts == nullptr);
	}

	TEST_CASE("truncated extensions are rejected")
	{
		SUBCASE("no length byte for a legacy type")
		{
			auto [ok, exts] = parse({RSPAMD_FUZZY_EXT_SOURCE_DOMAIN});
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("legacy domain shorter than advertised")
		{
			auto [ok, exts] = parse({RSPAMD_FUZZY_EXT_SOURCE_DOMAIN, 10, 'a', 'b'});
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("truncated ipv4")
		{
			auto [ok, exts] = parse({RSPAMD_FUZZY_EXT_SOURCE_IP4, 192, 0});
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("truncated ipv6")
		{
			std::vector<unsigned char> buf = {RSPAMD_FUZZY_EXT_SOURCE_IP6};
			buf.insert(buf.end(), 15, 0xaa);

			auto [ok, exts] = parse(buf);
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("no length byte for a skippable type")
		{
			auto [ok, exts] = parse({RSPAMD_FUZZY_EXT_SENDER_FACTS});
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("truncated sender facts")
		{
			auto [ok, exts] = parse({RSPAMD_FUZZY_EXT_SENDER_FACTS,
									 RSPAMD_FUZZY_SENDER_FACTS_LEN, 0, 0});
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("truncated unknown skippable type")
		{
			auto [ok, exts] = parse({RSPAMD_FUZZY_EXT_SKIPPABLE_MIN + 5, 4, 0});
			CHECK(!ok);
			CHECK(exts == nullptr);
		}

		SUBCASE("valid extensions followed by a truncated one")
		{
			auto buf = legacy_extensions();
			buf.push_back(RSPAMD_FUZZY_EXT_SENDER_FACTS);
			buf.push_back(RSPAMD_FUZZY_SENDER_FACTS_LEN);
			buf.push_back(0);

			auto [ok, exts] = parse(buf);
			CHECK(!ok);
			CHECK(exts == nullptr);
		}
	}

	TEST_CASE("clients built before and after the sender facts")
	{
		/* An old client: no extension in the skippable range at all */
		auto [old_ok, old_exts] = parse(legacy_extensions());

		REQUIRE(old_ok);
		REQUIRE(old_exts != nullptr);
		CHECK(count(old_exts.get()) == 2);
		CHECK(find(old_exts.get(), RSPAMD_FUZZY_EXT_SENDER_FACTS) == nullptr);

		/* A new one, sending the very same legacy extensions plus the facts */
		auto buf = legacy_extensions();
		append_facts(buf, rspamd_fuzzy_sf_pack(RSPAMD_FUZZY_SF_SPF_FAIL,
											   RSPAMD_FUZZY_SF_DKIM_FAIL,
											   RSPAMD_FUZZY_SF_DMARC_FAIL_REJECT,
											   RSPAMD_FUZZY_SF_PTR_NONE, false,
											   RSPAMD_FUZZY_SF_RCPTS_BULK, false));

		auto [new_ok, new_exts] = parse(buf);

		REQUIRE(new_ok);
		REQUIRE(new_exts != nullptr);
		CHECK(count(new_exts.get()) == 3);

		auto *dom = find(new_exts.get(), RSPAMD_FUZZY_EXT_SOURCE_DOMAIN);
		REQUIRE(dom != nullptr);
		CHECK(std::string((const char *) dom->payload, dom->length) == "example.com");

		auto *facts = find(new_exts.get(), RSPAMD_FUZZY_EXT_SENDER_FACTS);
		REQUIRE(facts != nullptr);
		CHECK(((decode_facts(facts) >> RSPAMD_FUZZY_SF_DMARC_SHIFT) &
			   RSPAMD_FUZZY_SF_DMARC_MASK) == RSPAMD_FUZZY_SF_DMARC_FAIL_REJECT);
	}
}

#endif
