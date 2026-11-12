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

/* Detached unit tests for the dkim2 parsing and canonicalization */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_DKIM2_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_DKIM2_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"
#include "libserver/dkim2.hxx"
#include "libserver/dkim2_sign.hxx"

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/* base64("<bounce@example.com>") */
#define DKIM2_TEST_MF "PGJvdW5jZUBleGFtcGxlLmNvbT4="
/* base64("<user@example.net>") */
#define DKIM2_TEST_RT "PHVzZXJAZXhhbXBsZS5uZXQ+"
/* base64 of 32 'A' bytes */
#define DKIM2_TEST_HH "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
/* base64 of 32 'B' bytes */
#define DKIM2_TEST_BH "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
/* base64("0123456789abcdef") */
#define DKIM2_TEST_SIG "MDEyMzQ1Njc4OWFiY2RlZg=="
/* base64("<>") */
#define DKIM2_TEST_NULL "PD4="
/* The mandatory part of a signature that has a real hop */
#define DKIM2_TEST_SIG_BASE "i=1; m=1; t=1700000000; d=example.com; mf=" DKIM2_TEST_MF \
							"; rt=" DKIM2_TEST_RT

TEST_SUITE("rspamd_dkim2")
{
	using namespace rspamd::dkim2;

	static auto body_canon_str(std::string_view in) -> std::string
	{
		std::string out;

		body_canon_foreach(in, [&](const char *p, std::size_t len) {
			out.append(p, len);
		});

		return out;
	}

	/* A signature of a real hop for the Chain of Custody tests */
	static auto make_hop(unsigned int i, std::string domain, std::string mf,
						 std::vector<std::string> rt) -> sig_header_t
	{
		sig_header_t sig;

		sig.i = i;
		sig.m = 1;
		sig.domain = std::move(domain);
		sig.mf = std::move(mf);
		sig.rt = std::move(rt);

		return sig;
	}

	/* A signature of an imaginary hop: nd= and no mf=/rt= */
	static auto make_nd(unsigned int i, std::string domain, std::string nd) -> sig_header_t
	{
		sig_header_t sig;

		sig.i = i;
		sig.m = 1;
		sig.domain = std::move(domain);
		sig.has_nd = true;
		sig.nd = std::move(nd);

		return sig;
	}

	static auto recipe_error_of(std::string_view json, const recipe_limits_t &limits = {})
		-> std::optional<recipe_error_kind>
	{
		auto r = parse_recipe(json, limits);

		if (r.has_value()) {
			return std::nullopt;
		}

		return r.error().kind;
	}

	TEST_CASE("dkim2 parse_tag_list")
	{
		auto tags = parse_tag_list("i=1; m = 2 ;mf=abc;");
		REQUIRE(tags.has_value());
		REQUIRE(tags->size() == 3);
		CHECK((*tags)[0].name == "i");
		CHECK((*tags)[0].value == "1");
		CHECK((*tags)[1].name == "m");
		CHECK((*tags)[1].value == "2");
		CHECK((*tags)[2].name == "mf");
		CHECK((*tags)[2].value == "abc");

		/* tag-name = ALPHA *(ALPHA / DIGIT / "_") */
		CHECK(parse_tag_list("a_b1=1").has_value());
		CHECK(!parse_tag_list("a-b=1").has_value());
		CHECK(!parse_tag_list("1a=1").has_value());
		CHECK(!parse_tag_list("=1").has_value());
		CHECK(!parse_tag_list("foo bar=1").has_value());
		CHECK(!parse_tag_list("novalue").has_value());
		/* An empty value is a value */
		auto empty_value = parse_tag_list("a=");
		REQUIRE(empty_value.has_value());
		CHECK((*empty_value)[0].value == "");

		/* A tag name that occurs twice makes the whole list invalid */
		CHECK(!parse_tag_list("a=1; b=2; a=3").has_value());
		/* Tag names are case-sensitive and MUST be in lower case */
		CHECK(!parse_tag_list("a=1; A=3").has_value());
		CHECK(!parse_tag_list("I=1").has_value());
		CHECK(parse_tag_list("a=1; A=3", false).has_value());

		/* A flood of separators is refused at once */
		CHECK(!parse_tag_list(std::string(1000000, ';')).has_value());

		/* Only one trailing semicolon is optional */
		CHECK(!parse_tag_list("a=1;;b=2").has_value());
		CHECK(!parse_tag_list("a=1;;").has_value());
		CHECK(!parse_tag_list(";a=1").has_value());
		CHECK(!parse_tag_list("").has_value());

		/* Values are printable ASCII */
		CHECK(!parse_tag_list(std::string_view{"a=x\0y", 5}).has_value());
		CHECK(!parse_tag_list("a=x\x7fy").has_value());
		CHECK(!parse_tag_list("a=caf\xc3\xa9").has_value());

		/* The lenient mode is for DNS records */
		auto lenient = parse_tag_list("v=DKIM1;; k=rsa; ; p=abc;", false);
		REQUIRE(lenient.has_value());
		CHECK(lenient->size() == 3);
		CHECK(!parse_tag_list("p=1; p=2", false).has_value());
	}

	TEST_CASE("dkim2 combine results")
	{
		using r = result_t;
		auto all = [](std::vector<result_t> v) {
			return combine_all(v);
		};
		auto any = [](std::vector<result_t> v) {
			return combine_any(v);
		};

		/* Section 14.6 step 6 */
		CHECK(all({r::pass}) == r::pass);
		CHECK(all({r::pass, r::pass}) == r::pass);
		CHECK(all({r::pass, r::temperror}) == r::temperror);
		CHECK(all({r::temperror, r::temperror}) == r::temperror);
		CHECK(all({r::pass, r::fail}) == r::fail);
		CHECK(all({r::temperror, r::fail}) == r::fail);
		CHECK(all({r::permerror, r::fail}) == r::fail);
		CHECK(all({r::pass, r::permerror}) == r::permerror);
		CHECK(all({r::temperror, r::permerror}) == r::permerror);
		CHECK(all({}) == r::permerror);

		/* Section 14.6 step 7 */
		CHECK(any({r::fail, r::pass}) == r::pass);
		CHECK(any({r::permerror, r::temperror, r::pass}) == r::pass);
		CHECK(any({r::fail, r::temperror}) == r::temperror);
		CHECK(any({r::permerror, r::temperror}) == r::temperror);
		CHECK(any({r::permerror, r::fail}) == r::fail);
		CHECK(any({r::permerror, r::permerror}) == r::permerror);
		CHECK(any({}) == r::permerror);
	}

	TEST_CASE("dkim2 parse_mi")
	{
		auto mi = parse_mi("m=1; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH);
		REQUIRE(mi.has_value());
		CHECK(mi->m == 1);
		REQUIRE(mi->hash_groups.size() == 1);
		REQUIRE(mi->hash_groups[0].size() == 1);
		CHECK(mi->hash_groups[0][0].alg == "sha256");
		CHECK(mi->hash_groups[0][0].header_hash == std::string(32, 'A'));
		CHECK(mi->hash_groups[0][0].body_hash == std::string(32, 'B'));
		CHECK(!mi->has_recipe);

		/* `,` binds more tightly than `|` */
		auto mi2 = parse_mi("m=2; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH
							" , sha512:" DKIM2_TEST_HH ":" DKIM2_TEST_BH
							" | sha3:" DKIM2_TEST_HH ":" DKIM2_TEST_BH "; r=e30=");
		REQUIRE(mi2.has_value());
		REQUIRE(mi2->hash_groups.size() == 2);
		CHECK(mi2->hash_groups[0].size() == 2);
		CHECK(mi2->hash_groups[0][1].alg == "sha512");
		REQUIRE(mi2->hash_groups[1].size() == 1);
		CHECK(mi2->hash_groups[1][0].alg == "sha3");
		CHECK(mi2->has_recipe);
		CHECK(mi2->recipe_b64 == "e30=");

		/* An algorithm MUST NOT be present more than once */
		auto dup = parse_mi("m=3; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH
							"|sha256:" DKIM2_TEST_BH ":" DKIM2_TEST_HH);
		REQUIRE(!dup.has_value());
		CHECK(dup.error().num == 3);
		CHECK(dup.error().what == "has a duplicate hash algorithm");

		/* Missing mandatory tags */
		auto no_h = parse_mi("m=4");
		REQUIRE(!no_h.has_value());
		CHECK(no_h.error().num == 4);
		CHECK(no_h.error().what == "tag=h missing");
		auto no_m = parse_mi("h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH);
		REQUIRE(!no_m.has_value());
		CHECK(no_m.error().num == 0);
		CHECK(no_m.error().what == "tag=m missing");

		/* Invalid m= */
		CHECK(!parse_mi("m=0; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		CHECK(!parse_mi("m=x; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		CHECK(!parse_mi("m=+1; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		CHECK(!parse_mi("m=1; m=1; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		/* Broken hash sets */
		CHECK(!parse_mi("m=1; h=sha256:" DKIM2_TEST_HH).has_value());
		CHECK(!parse_mi("m=1; h=").has_value());
		CHECK(!parse_mi("m=1; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH "|").has_value());
		CHECK(!parse_mi("m=1; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH ",").has_value());
		CHECK(!parse_mi("m=1; h=sha 256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());

		/* Too many hash sets */
		std::string many{"m=1; h="};
		for (std::size_t i = 0; i <= DKIM2_MAX_HASH_SETS; i++) {
			many.append(i ? "|" : "");
			many.append("alg");
			many.append(std::to_string(i));
			many.append(":" DKIM2_TEST_HH ":" DKIM2_TEST_BH);
		}
		CHECK(!parse_mi(many).has_value());
	}

	TEST_CASE("dkim2 parse_sig")
	{
		auto sig = parse_sig("i=2; m=1; t=1700000000; mf=" DKIM2_TEST_MF
							 "; rt=" DKIM2_TEST_RT "; d=example.com; "
							 "s=sel:ed25519-sha256:" DKIM2_TEST_SIG
							 "; f=feedhere, exploded,future-flag; n=abc123");
		REQUIRE(sig.has_value());
		CHECK(sig->i == 2);
		CHECK(sig->m == 1);
		CHECK(sig->t == 1700000000);
		CHECK(!sig->has_nd);
		CHECK(sig->mf == "<bounce@example.com>");
		REQUIRE(sig->rt.size() == 1);
		CHECK(sig->rt[0] == "<user@example.net>");
		CHECK(sig->domain == "example.com");
		REQUIRE(sig->sig_groups.size() == 1);
		REQUIRE(sig->sig_groups[0].size() == 1);
		CHECK(sig->sig_groups[0][0].selector == "sel");
		CHECK(sig->sig_groups[0][0].alg == "ed25519-sha256");
		CHECK(sig->sig_groups[0][0].sig == "0123456789abcdef");
		CHECK((sig->flags & DKIM2_SIG_FLAG_FEEDHERE) != 0);
		CHECK((sig->flags & DKIM2_SIG_FLAG_EXPLODED) != 0);
		CHECK((sig->flags & DKIM2_SIG_FLAG_FEEDBACK) == 0);
		CHECK(sig->nonce == "abc123");

		/* AND/OR algebra of signatures */
		auto sig2 = parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG
												  ",b:ed25519-sha256:" DKIM2_TEST_SIG
												  " | c.d:mldsa44:" DKIM2_TEST_SIG);
		REQUIRE(sig2.has_value());
		REQUIRE(sig2->sig_groups.size() == 2);
		CHECK(sig2->sig_groups[0].size() == 2);
		CHECK(sig2->sig_groups[0][1].selector == "b");
		REQUIRE(sig2->sig_groups[1].size() == 1);
		CHECK(sig2->sig_groups[1][0].selector == "c.d");
		CHECK(sig2->sig_groups[1][0].alg == "mldsa44");

		/* A Selector MUST NOT be present more than once */
		auto dup = parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG
												 "|A:ed25519-sha256:" DKIM2_TEST_SIG);
		REQUIRE(!dup.has_value());
		CHECK(dup.error().num == 1);
		CHECK(dup.error().what == "has a duplicate selector");

		/* An imaginary hop: nd= instead of mf= and rt= */
		auto nd = parse_sig("i=3; m=1; t=1700000000; d=example.com; nd=example.net; "
							"s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(nd.has_value());
		CHECK(nd->has_nd);
		CHECK(nd->nd == "example.net");
		CHECK(nd->rt.empty());

		auto nd_mf = parse_sig("i=3; m=1; t=1700000000; d=example.com; nd=example.net; mf=" DKIM2_TEST_MF
							   "; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(!nd_mf.has_value());
		CHECK(nd_mf.error().num == 3);
		CHECK(nd_mf.error().what == "tag=mf was unexpected");

		auto nd_rt = parse_sig("i=3; m=1; t=1700000000; d=example.com; nd=example.net; rt=" DKIM2_TEST_RT
							   "; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(!nd_rt.has_value());
		CHECK(nd_rt.error().what == "tag=rt was unexpected");

		/* Mandatory tags: i=, m=, t=, d=, s= and mf= with rt= */
		const std::pair<const char *, const char *> missing[] = {
			{"m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG, "tag=i missing"},
			{"i=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG, "tag=m missing"},
			{"i=1; m=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG, "tag=t missing"},
			{"i=1; m=1; t=1; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG, "tag=d missing"},
			{"i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT, "tag=s missing"},
			{"i=1; m=1; t=1; d=example.com; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG, "tag=mf missing"},
			{"i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; s=a:rsa-sha256:" DKIM2_TEST_SIG, "tag=rt missing"},
		};

		for (const auto &[value, what]: missing) {
			auto bad = parse_sig(value);
			REQUIRE(!bad.has_value());
			CHECK(bad.error().what == what);
		}

		/* The null reverse-path is a valid mf=, but not a valid recipient */
		auto bounce = parse_sig("i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_NULL
								"; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(bounce.has_value());
		CHECK(bounce->mf == "<>");
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF
						 "; rt=" DKIM2_TEST_NULL "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());

		/* Several recipients, FWS inside base64 is ignored */
		auto multi = parse_sig("i=1; m=1; t=1; d=example.com; mf=PGJvdW5jZUBleGFt cGxlLmNvbT4=; rt=" DKIM2_TEST_RT
							   " , " DKIM2_TEST_MF "; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(multi.has_value());
		CHECK(multi->mf == "<bounce@example.com>");
		REQUIRE(multi->rt.size() == 2);
		CHECK(multi->rt[1] == "<bounce@example.com>");

		/* The angle brackets MUST be included, no control characters */
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=Ym91bmNlQGV4YW1wbGUuY29t; rt=" DKIM2_TEST_RT
						 "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=PGEKYkBleGFtcGxlLmNvbT4=; rt=" DKIM2_TEST_RT
						 "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=@@@; rt=" DKIM2_TEST_RT
						 "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT
						 ",; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());

		/* base64strings are canonical: no stray characters, padded, zero bits */
		for (const char *mf: {"PD4", "PD4=!", "P!D4=", "PD5=", "PD4==", "=PD4", "PD=4",
							  "PGJvdW5jZUBleGFtcGxlLmNvbT4=PD4="}) {
			CAPTURE(mf);
			CHECK(!parse_sig(std::string{"i=1; m=1; t=1; d=example.com; rt=" DKIM2_TEST_RT
										 "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; mf="} +
							 mf)
					   .has_value());
		}
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:MDEy!MzQ1Njc4OWFiY2RlZg==").has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:MDEyMzQ1Njc4OWFiY2RlZg").has_value());
		/* Two paths cannot hide in one element */
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF
						 "; rt=PGFAeC5jb20+!PGJAeS5jb20+; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());

		/* Paths are bounded: base64 of "<x@" + 150 * "a." + "example.com>" */
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; rt=" DKIM2_TEST_RT
						 "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; mf=PHhAYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuYS5hLmEuZXhhbXBsZS5jb20+")
				   .has_value());
		/* base64("<@a.example:>"): a source route to nowhere */
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; rt=" DKIM2_TEST_RT
						 "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; mf=PEBhLmV4YW1wbGU6Pg==")
				   .has_value());
		/* base64("<x@..example.com>") */
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; rt=" DKIM2_TEST_RT
						 "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; mf=PHhALi5leGFtcGxlLmNvbT4=")
				   .has_value());
		/* base64("<x@[192.0.2.1]>"): a literal is a valid path that never matches */
		CHECK(parse_sig("i=1; m=1; t=1; d=example.com; rt=" DKIM2_TEST_RT
						"; s=a:rsa-sha256:" DKIM2_TEST_SIG "; mf=PHhAWzE5Mi4wLjIuMV0+")
				  .has_value());

		/* Domains and selectors end up in DNS names */
		for (const char *domain: {"exa mple.com", "example..com", ".example.com", "example.com.",
								  "exam/ple.com", ""}) {
			CHECK(!parse_sig(std::string{"i=1; m=1; t=1; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT
										 "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; d="} +
							 domain)
					   .has_value());
		}
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a/b:rsa-sha256:" DKIM2_TEST_SIG).has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=:rsa-sha256:" DKIM2_TEST_SIG).has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:").has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG "|").has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG ":x").has_value());

		/* t= is an unsigned decimal that is not limited to 32 bits */
		auto far = parse_sig("i=1; m=1; t=1000000000000; d=example.com; mf=" DKIM2_TEST_MF
							 "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(far.has_value());
		CHECK(far->t == 1000000000000ULL);
		CHECK(!parse_sig("i=1; m=1; t=-1; d=example.com; mf=" DKIM2_TEST_MF
						 "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());
		CHECK(!parse_sig("i=1; m=1; t=99999999999999999999999; d=example.com; mf=" DKIM2_TEST_MF
						 "; rt=" DKIM2_TEST_RT "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());

		/* The nonce is limited to 64 characters */
		CHECK(parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; n=" + std::string(64, 'x'))
				  .has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; n=" + std::string(65, 'x'))
				   .has_value());
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; n=a b").has_value());

		/* Flags that were removed from the draft are just unknown now */
		auto old_flags = parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG
													   "; f=donotmodify,donotexplode");
		REQUIRE(old_flags.has_value());
		CHECK(old_flags->flags == 0);
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=a:rsa-sha256:" DKIM2_TEST_SIG "; f=a b").has_value());

		std::string too_many_sets;
		for (std::size_t i = 0; i <= DKIM2_MAX_SIG_SETS_PER_HOP; i++) {
			too_many_sets.append(i ? (i % 2 ? "," : "|") : "");
			too_many_sets.append("s");
			too_many_sets.append(std::to_string(i));
			too_many_sets.append(":rsa-sha256:" DKIM2_TEST_SIG);
		}
		CHECK(!parse_sig(DKIM2_TEST_SIG_BASE "; s=" + too_many_sets).has_value());

		std::string too_many_recipients;
		for (std::size_t i = 0; i <= DKIM2_MAX_RT_ENTRIES; i++) {
			too_many_recipients.append(i ? "," : "");
			too_many_recipients.append(DKIM2_TEST_RT);
		}
		CHECK(!parse_sig("i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" +
						 too_many_recipients + "; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());
	}

	TEST_CASE("dkim2 valid_domain")
	{
		CHECK(valid_domain("example.com"));
		CHECK(valid_domain("a"));
		CHECK(valid_domain("sel_1.sub-domain.example.com"));
		CHECK(valid_domain("xn--e1afmkfd.xn--p1ai"));
		CHECK(!valid_domain(""));
		CHECK(!valid_domain("."));
		CHECK(!valid_domain("a..b"));
		CHECK(!valid_domain("a.b."));
		CHECK(!valid_domain("a b"));
		CHECK(!valid_domain("[192.0.2.1]"));
		CHECK(!valid_domain("caf\xc3\xa9.example"));
		CHECK(valid_domain(std::string(63, 'a') + ".com"));
		CHECK(!valid_domain(std::string(64, 'a') + ".com"));
		CHECK(!valid_domain(std::string(63, 'a') + "." + std::string(63, 'b') + "." +
							std::string(63, 'c') + "." + std::string(63, 'd')));
	}

	TEST_CASE("dkim2 is_unsigned_header")
	{
		for (const char *name: {"Received", "received", "Return-Path", "Delivered-To",
								"Apparently-To", "DL-Expansion-History", "Original-Recipient",
								"SIO-Label-History", "X400-Received", "X400-Trace",
								"Received-SPF", "received-anything", "DKIM-Signature",
								"ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results",
								"Authentication-Results", "X-Mailer", "x-", "Message-Instance",
								"DKIM2-Signature"}) {
			CAPTURE(name);
			CHECK(is_unsigned_header(name));
		}

		for (const char *name: {"From", "Subject", "To", "Date", "Message-ID", "List-Id",
								"ARC-Other", "X400-Originator", "Receivedx", "XMailer",
								"Resent-From", "MIME-Version", "Content-Type"}) {
			CAPTURE(name);
			CHECK(!is_unsigned_header(name));
		}
	}

	TEST_CASE("dkim2 scan_headers")
	{
		auto hdrs = scan_headers("From: a@example.com\r\n"
								 "Subject : folded\r\n"
								 "\t value \r\n"
								 " here\r\n"
								 "X-Empty:\r\n"
								 "1st_Odd-Name:x\n"
								 "To: b@example.com\r\n"
								 "\r\n"
								 "Body: not a header\r\n");
		REQUIRE(hdrs.has_value());
		REQUIRE(hdrs->size() == 5);
		CHECK((*hdrs)[0].name == "From");
		CHECK((*hdrs)[0].value == " a@example.com");
		/* WSP before the colon is not a part of the name; unfolding drops CRLF only */
		CHECK((*hdrs)[1].name == "Subject");
		CHECK((*hdrs)[1].value == " folded\t value  here");
		CHECK((*hdrs)[2].name == "X-Empty");
		CHECK((*hdrs)[2].value == "");
		/* Any printable name is a field name, and bare LF ends a line too */
		CHECK((*hdrs)[3].name == "1st_Odd-Name");
		CHECK((*hdrs)[3].value == "x");
		CHECK((*hdrs)[4].name == "To");

		/* No empty line and no final terminator */
		auto no_end = scan_headers("A: 1\r\nB: 2");
		REQUIRE(no_end.has_value());
		REQUIRE(no_end->size() == 2);
		CHECK((*no_end)[1].value == " 2");

		CHECK(scan_headers("")->empty());
		CHECK(scan_headers("\r\nA: 1\r\n")->empty());

		/*
		 * What a tolerant parser hides stays visible: text after a bare CR,
		 * NUL octets, form feeds after a fold
		 */
		auto hidden = scan_headers(std::string_view{
			"Subject: Meeting at 5\r- CANCELLED\r\n"
			"To: a\0b\r\n"
			"Cc: x\r\n \fy\r\n",
			54});
		REQUIRE(hidden.has_value());
		REQUIRE(hidden->size() == 3);
		CHECK((*hidden)[0].value == " Meeting at 5\r- CANCELLED");
		CHECK((*hidden)[1].value == std::string_view{" a\0b", 4});
		CHECK((*hidden)[2].value == " x \fy");

		/* What is not a header field is an error and is not skipped */
		CHECK(!scan_headers("A: 1\r\ngarbage line\r\nB: 2\r\n").has_value());
		CHECK(!scan_headers(" continuation first\r\nA: 1\r\n").has_value());
		CHECK(!scan_headers("Bad Name: 1\r\n").has_value());
		CHECK(!scan_headers(": no name\r\n").has_value());
		CHECK(!scan_headers("N\xc3\xa4me: 1\r\n").has_value());
		CHECK(!scan_headers("From x@example.com Mon Jan  1 00:00:00 2024\r\nA: 1\r\n").has_value());

		/* Nothing is dropped silently past a limit */
		std::string many;
		for (std::size_t i = 0; i < DKIM2_MAX_HEADER_FIELDS; i++) {
			many.append("X-P: 1\r\n");
		}
		auto at_limit = scan_headers(many);
		REQUIRE(at_limit.has_value());
		CHECK(at_limit->size() == DKIM2_MAX_HEADER_FIELDS);
		many.append("Reply-To: attacker@example.org\r\n");
		CHECK(!scan_headers(many).has_value());
	}

	TEST_CASE("dkim2 from_is_single_mailbox")
	{
		for (const char *ok: {"alice@example.com", "<alice@example.com>",
							  "Alice Example <alice@example.com>",
							  "\"Doe, John; jr @ home\" <john@example.com>",
							  "alice@example.com (work, @office; really)",
							  "\"a\\\"@b\" <alice@example.com>",
							  "(nested (comment @ ) here) alice@example.com"}) {
			CAPTURE(ok);
			CHECK(from_is_single_mailbox(ok));
		}

		for (const char *bad: {"", "no address", "alice@example.com, bob@example.com",
							   "ceo@bank.example x@attacker.example",
							   "<ceo@bank.example@attacker.example>",
							   "bank.example:x@attacker.example;",
							   "<x@attacker.example>, ceo", "group: a@example.com;",
							   "\"unterminated <alice@example.com>",
							   "(unterminated alice@example.com",
							   "\"alice@example.com\""}) {
			CAPTURE(bad);
			CHECK(!from_is_single_mailbox(bad));
		}
	}

	TEST_CASE("dkim2 canon_hash_line")
	{
		CHECK(canon_hash_line("Subject", "  Hello   world\t!  ") ==
			  "subject:Hello world !\r\n");
		CHECK(canon_hash_line("FROM", "Foo <foo@example.com>") ==
			  "from:Foo <foo@example.com>\r\n");
		CHECK(canon_hash_line("Subject ", "x") == "subject:x\r\n");
		CHECK(canon_hash_line("X-Empty", "") == "x-empty:\r\n");
		CHECK(canon_hash_line("To", "a@b, \tc@d") == "to:a@b, c@d\r\n");
		/* Only SP and HTAB are WSP: a stray CR is a part of the value */
		CHECK(canon_hash_line("Subject", "a\fb\vc") == "subject:a\fb\vc\r\n");
		CHECK(canon_hash_line("Subject", "a\rb") == "subject:a\rb\r\n");
		CHECK(canon_sig_line("Message-Instance", "m=1;\rh=x") == "message-instance:m=1;\rh=x\r\n");
		/* The case of the value is kept */
		CHECK(canon_hash_line("SUBJect", "AbC") == "subject:AbC\r\n");
	}

	TEST_CASE("dkim2 canon_sig_line and blank_sig_values")
	{
		auto line = canon_sig_line("DKIM2-Signature",
								   "i=1; m=1; d=example.com; s = sel : rsa-sha256 : AbCd ;");
		CHECK(line == "dkim2-signature:i=1;m=1;d=example.com;s=sel:rsa-sha256:AbCd;\r\n");

		CHECK(blank_sig_values(line) ==
			  "dkim2-signature:i=1;m=1;d=example.com;s=sel:rsa-sha256:;\r\n");

		/* Multiple signatures, s= tag in the middle */
		auto line2 = canon_sig_line("DKIM2-Signature",
									"i=1;s=a:rsa-sha256:XXX,b:ed25519-sha256:YYY;d=example.com");
		CHECK(blank_sig_values(line2) ==
			  "dkim2-signature:i=1;s=a:rsa-sha256:,b:ed25519-sha256:;d=example.com\r\n");

		/* The `:` `,` `|` punctuation remains */
		auto line3 = canon_sig_line("DKIM2-Signature",
									"s=a:rsa-sha256:XX==,b:ed25519-sha256:YY | c:mldsa44:ZZ; i=1");
		CHECK(blank_sig_values(line3) ==
			  "dkim2-signature:s=a:rsa-sha256:,b:ed25519-sha256:|c:mldsa44:;i=1\r\n");

		/* Only the s= tag is touched */
		auto line4 = canon_sig_line("DKIM2-Signature", "xs=a:b:c; s=a:b:c; ss=a:b:c");
		CHECK(blank_sig_values(line4) == "dkim2-signature:xs=a:b:c;s=a:b:;ss=a:b:c\r\n");

		/* Message-Instance lines only lose the whitespace */
		CHECK(canon_sig_line("Message-Instance", " m=1;\t h=sha256:AA : BB") ==
			  "message-instance:m=1;h=sha256:AA:BB\r\n");
	}

	TEST_CASE("dkim2 build_sig_input")
	{
		std::vector<std::string> mi_lines{
			"message-instance:m=1;h=sha256:AA:BB\r\n",
		};
		std::vector<std::string> prev_lines{
			"dkim2-signature:i=1;s=a:rsa-sha256:XXX;d=example.com\r\n",
		};

		auto input = build_sig_input(mi_lines, prev_lines,
									 "dkim2-signature:i=2;s=b:rsa-sha256:YYY;d=example.net\r\n");

		CHECK(input ==
			  "message-instance:m=1;h=sha256:AA:BB\r\n"
			  "dkim2-signature:i=1;s=a:rsa-sha256:XXX;d=example.com\r\n"
			  "dkim2-signature:i=2;s=b:rsa-sha256:;d=example.net\r\n");
	}

	TEST_CASE("dkim2 relaxed_domain_match")
	{
		CHECK(relaxed_domain_match("example.com", "example.com"));
		CHECK(relaxed_domain_match("bounce.example.com", "example.com"));
		CHECK(relaxed_domain_match("a.b.example.com", "example.com"));
		CHECK(relaxed_domain_match("EXAMPLE.com", "example.COM"));
		/* The match is asymmetric */
		CHECK(!relaxed_domain_match("example.com", "bounce.example.com"));
		/* Labels are removed whole */
		CHECK(!relaxed_domain_match("notexample.com", "example.com"));
		CHECK(!relaxed_domain_match("examplexcom", "example.com"));
		/* Siblings never match */
		CHECK(!relaxed_domain_match("a.example.com", "b.example.com"));
		CHECK(relaxed_domain_match("a.example.com", "com"));
		CHECK(!relaxed_domain_match("", "example.com"));
		CHECK(!relaxed_domain_match("example.com", ""));
		CHECK(!relaxed_domain_match("example.com.", ""));
		/* A domain literal never matches */
		CHECK(!relaxed_domain_match("[192.0.2.1]", "[192.0.2.1]"));
	}

	TEST_CASE("dkim2 smtp address helpers")
	{
		CHECK(smtp_addr_equal("<Foo@Example.COM>", "Foo@example.com"));
		CHECK(smtp_addr_equal("foo@example.com", "<foo@EXAMPLE.com>"));
		/* The local part is case-sensitive */
		CHECK(!smtp_addr_equal("<foo@example.com>", "Foo@example.com"));
		/* Null reverse-path */
		CHECK(smtp_addr_equal("<>", ""));
		CHECK(!smtp_addr_equal("<>", "foo@example.com"));
		CHECK(smtp_addr_is_null("<>"));
		CHECK(!smtp_addr_is_null("<a@b>"));

		CHECK(smtp_addr_domain("<foo@example.com>") == "example.com");
		CHECK(smtp_addr_domain("foo@example.com") == "example.com");
		CHECK(smtp_addr_domain("<\"a@b\"@example.com>") == "example.com");
		CHECK(smtp_addr_domain("<>") == "");
		CHECK(smtp_addr_domain("foo") == "");
		/* An obsolete source route is not a part of the address */
		CHECK(smtp_addr_key("<@a.example,@b.example:Foo@Example.COM>") == "Foo@example.com");
	}

	TEST_CASE("dkim2 check_custody")
	{
		/* A single hop: only d= against mf= */
		CHECK(!check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@mail.example.com>", {"<user@example.net>"})}));

		auto misaligned = check_custody(std::vector{
			make_hop(1, "mail.example.com", "<bounce@example.com>", {"<user@example.net>"})});
		REQUIRE(misaligned.has_value());
		CHECK(*misaligned == "DKIM2-Signature i=1 mf= and d= do not match");

		/* The null reverse-path needs no match with d= */
		CHECK(!check_custody(std::vector{
			make_hop(1, "example.com", "<>", {"<user@example.net>"})}));
		/* An address without a domain or with a domain literal never matches */
		CHECK(check_custody(std::vector{
								make_hop(1, "example.com", "<postmaster>", {"<user@example.net>"})})
				  .has_value());
		CHECK(check_custody(std::vector{
								make_hop(1, "example.com", "<a@[192.0.2.1]>", {"<user@example.net>"})})
				  .has_value());

		/* A forwarder: mf= of i=2 must match a recipient of i=1 */
		CHECK(!check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>",
					 {"<other@example.org>", "<list@example.net>"}),
			make_hop(2, "example.net", "<bounces@lists.example.net>", {"<user@example.org>"})}));

		auto broken = check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<list@lists.example.net>"}),
			make_hop(2, "example.net", "<bounces@example.net>", {"<user@example.org>"})});
		REQUIRE(broken.has_value());
		CHECK(*broken == "DKIM2-Signature i=2 mf= does not match the rt= of i=1");

		/* A replay: an unrelated domain signs on */
		CHECK(check_custody(std::vector{
								make_hop(1, "example.com", "<bounce@example.com>", {"<victim@example.net>"}),
								make_hop(2, "attacker.example", "<x@attacker.example>", {"<user@example.org>"})})
				  .has_value());

		/* A DSN: the null mf=, d= must be a recipient domain or its parent */
		CHECK(!check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@mx.example.net>"}),
			make_hop(2, "example.net", "<>", {"<bounce@example.com>"})}));

		auto dsn = check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@example.net>"}),
			make_hop(2, "mx.example.net", "<>", {"<bounce@example.com>"})});
		REQUIRE(dsn.has_value());
		CHECK(*dsn == "DKIM2-Signature i=2 d= does not match the rt= of i=1");

		/* An imaginary hop: nd= names the next signing domain */
		CHECK(!check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@example.net>"}),
			make_nd(2, "example.net", "example.org"),
			make_hop(3, "EXAMPLE.org", "<fwd@example.org>", {"<user@example.edu>"})}));

		auto nd_mismatch = check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@example.net>"}),
			make_nd(2, "example.net", "example.org"),
			make_hop(3, "sub.example.org", "<fwd@sub.example.org>", {"<user@example.edu>"})});
		REQUIRE(nd_mismatch.has_value());
		CHECK(*nd_mismatch == "DKIM2-Signature i=2 nd= does not match");

		/* The field with nd= itself must be signed by a recipient domain */
		auto nd_unrelated = check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@example.net>"}),
			make_nd(2, "attacker.example", "example.org"),
			make_hop(3, "example.org", "<fwd@example.org>", {"<user@example.edu>"})});
		REQUIRE(nd_unrelated.has_value());
		CHECK(*nd_unrelated == "DKIM2-Signature i=2 d= does not match the rt= of i=1");

		/* A sequence of nd= fields must end with a real hop */
		CHECK(!check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@example.net>"}),
			make_nd(2, "example.net", "example.org"),
			make_nd(3, "example.org", "example.edu"),
			make_hop(4, "example.edu", "<fwd@example.edu>", {"<user@example.int>"})}));

		auto trailing_nd = check_custody(std::vector{
			make_hop(1, "example.com", "<bounce@example.com>", {"<user@example.net>"}),
			make_nd(2, "example.net", "example.org")});
		REQUIRE(trailing_nd.has_value());
		CHECK(*trailing_nd == "DKIM2-Signature i=2 unexpected nd= tag");
	}

	TEST_CASE("dkim2 key and policy records")
	{
		key_record_t key;
		CHECK(parse_key_record("v=DKIM1; k=ed25519; p=AAAA BBBB", key) == record_status::ok);
		CHECK(key.k == "ed25519");
		CHECK(key.p == "AAAABBBB");
		CHECK(!key.revoked);

		/* k= defaults to rsa; the retired and unknown tags are ignored */
		key_record_t def;
		CHECK(parse_key_record("p=AAAA; h=sha1; s=email; t=y:s; n=note; g=*", def) ==
			  record_status::ok);
		CHECK(def.k == "rsa");

		/* An empty p= means that the key has been revoked */
		key_record_t revoked;
		CHECK(parse_key_record("v=DKIM1; p=", revoked) == record_status::ok);
		CHECK(revoked.revoked);

		/* Records that begin with another v= are not key records */
		key_record_t other;
		CHECK(parse_key_record("v=spf1 include:example.com ~all", other) ==
			  record_status::ignored);
		CHECK(parse_key_record("v=DKIM1.0; p=AAAA", other) == record_status::ignored);
		/* What remains must be usable */
		CHECK(parse_key_record("v=DKIM1; k=rsa", other) == record_status::syntax_error);
		CHECK(parse_key_record("k=rsa; v=DKIM1; p=AAAA", other) == record_status::syntax_error);
		CHECK(parse_key_record("some text", other) == record_status::syntax_error);
		/* ... whatever else such a record has */
		CHECK(parse_key_record("v=foo; bar baz", other) == record_status::ignored);
		CHECK(parse_key_record(" v = spf1 -all", other) == record_status::ignored);
		CHECK(parse_key_record("p=AAAA; p=BBBB", other) == record_status::syntax_error);

		policy_record_t policy;
		CHECK(parse_policy_record("v=DKIM1; f=strict", policy) == record_status::ok);
		CHECK(policy.strict);

		policy_record_t open;
		CHECK(parse_policy_record("v=DKIM1", open) == record_status::ok);
		CHECK(!open.strict);
		CHECK(parse_policy_record("v=DKIM1; f=other:Strict", open) == record_status::ok);
		CHECK(!open.strict);
		CHECK(parse_policy_record("v=DKIM1; f=other : strict", open) == record_status::ok);
		CHECK(open.strict);

		/* A key record of a wildcard is a policy record without flags */
		policy_record_t wildcard;
		CHECK(parse_policy_record("v=DKIM1; k=rsa; p=AAAA", wildcard) == record_status::ok);
		CHECK(!wildcard.strict);

		/* Purported records that do not begin with v=DKIM1 are ignored */
		policy_record_t ignored;
		CHECK(parse_policy_record("f=strict", ignored) == record_status::ignored);
		CHECK(parse_policy_record("o=~; r=postmaster@example.com", ignored) ==
			  record_status::ignored);
		CHECK(parse_policy_record("f=strict; v=DKIM1", ignored) == record_status::ignored);
		CHECK(parse_policy_record("random text", ignored) == record_status::ignored);
		CHECK(!ignored.strict);
		CHECK(parse_policy_record("v=DKIM1x; junk", ignored) == record_status::ignored);
		/* A broken policy record must not be read as a permissive one */
		CHECK(parse_policy_record("v=DKIM1; f=strict; f=strict", ignored) ==
			  record_status::syntax_error);
		CHECK(parse_policy_record("v = DKIM1; f=strict; f=strict", ignored) ==
			  record_status::syntax_error);

		CHECK(sig_alg_key_type("rsa-sha256") == "rsa");
		CHECK(sig_alg_key_type("ed25519-sha256") == "ed25519");
		CHECK(sig_alg_key_type("mldsa44") == "mldsa44");
		CHECK(sig_alg_key_type("rsa-sha1") == "");
		CHECK(sig_alg_key_type("RSA-SHA256") == "");
	}

	TEST_CASE("dkim2 split_body_lines")
	{
		/* A CR without LF does not end a line */
		auto cr = split_body_lines("foo\rbar\r\n", 100);
		REQUIRE(cr.has_value());
		REQUIRE(cr->size() == 1);
		CHECK((*cr)[0] == "foo\rbar");

		auto lines = split_body_lines("foo\r\nbar\nbaz", 100);
		REQUIRE(lines.has_value());
		REQUIRE(lines->size() == 3);
		CHECK((*lines)[0] == "foo");
		CHECK((*lines)[1] == "bar");
		CHECK((*lines)[2] == "baz");

		/* A trailing terminator does not produce an extra empty line */
		auto lines2 = split_body_lines("foo\r\n", 100);
		REQUIRE(lines2.has_value());
		CHECK(lines2->size() == 1);

		/* Empty lines are preserved */
		auto lines3 = split_body_lines("foo\r\n\r\nbar\r\n", 100);
		REQUIRE(lines3.has_value());
		REQUIRE(lines3->size() == 3);
		CHECK((*lines3)[1] == "");

		CHECK(split_body_lines("", 100)->empty());

		/* Line limit */
		CHECK(!split_body_lines("a\nb\nc\nd\n", 3).has_value());
	}

	TEST_CASE("dkim2 split_body_lines matches body canonicalization")
	{
		/*
		 * The line-based body hashing used for reconstructed instances must
		 * agree with the streaming canonicalization used for the current one
		 */
		const std::vector<std::string> bodies{
			"",
			"foo",
			"foo\r\n",
			"foo\r\n\r\n\r\n",
			"foo\nbar",
			"foo\rbar\r",
			"foo\r\r\n",
			"\r",
			"foo\n\r\n\n",
			"foo \r\n",
			" \r\n",
			"foo\r\n\r\nbar\r\n",
			"\r\n\r\n",
		};

		for (const auto &body: bodies) {
			auto lines = split_body_lines(body, 1000);
			REQUIRE(lines.has_value());

			auto nlines = lines->size();
			while (nlines > 0 && (*lines)[nlines - 1].empty()) {
				nlines--;
			}

			std::string from_lines;
			if (nlines == 0) {
				from_lines = "\r\n";
			}
			else {
				for (std::size_t k = 0; k < nlines; k++) {
					from_lines.append((*lines)[k]);
					from_lines.append("\r\n");
				}
			}

			CHECK(from_lines == body_canon_str(body));
		}
	}

	TEST_CASE("dkim2 parse_recipe")
	{
		recipe_limits_t limits;

		auto r = parse_recipe(
			R"( {"h":{"subject":[{"d":["old subject"]}],"to":[]},"b":[{"c":[1,3]},{"d":["a footer",""]},{"c":[5,5]}]} )",
			limits);
		REQUIRE(r.has_value());
		CHECK(r->has_headers);
		CHECK(r->has_body);
		CHECK(!r->body_null);
		REQUIRE(r->headers.size() == 2);
		CHECK(r->headers[0].first == "subject");
		REQUIRE(r->headers[0].second.size() == 1);
		CHECK(!r->headers[0].second[0].is_copy);
		REQUIRE(r->headers[0].second[0].data.size() == 1);
		CHECK(r->headers[0].second[0].data[0] == "old subject");
		/* An empty array removes all instances of the header field */
		CHECK(r->headers[1].first == "to");
		CHECK(r->headers[1].second.empty());
		REQUIRE(r->find_header("to") != nullptr);
		CHECK(r->find_header("from") == nullptr);
		REQUIRE(r->body.size() == 3);
		CHECK(r->body[0].is_copy);
		CHECK(r->body[0].start == 1);
		CHECK(r->body[0].end == 3);
		CHECK(!r->body[1].is_copy);
		REQUIRE(r->body[1].data.size() == 2);
		CHECK(r->body[1].data[1] == "");
		CHECK(r->body[2].start == 5);

		/* The previous state of the body cannot be recreated */
		auto r2 = parse_recipe(R"({"b":null})", limits);
		REQUIRE(r2.has_value());
		CHECK(r2->has_body);
		CHECK(r2->body_null);
		CHECK(!r2->has_headers);

		/* JSON escapes, including a surrogate pair */
		auto r3 = parse_recipe(R"({"b":[{"d":["a\tbé😀\"\\\/"]}]})", limits);
		REQUIRE(r3.has_value());
		CHECK(r3->body[0].data[0] == "a\tb\xc3\xa9\xf0\x9f\x98\x80\"\\/");

		/* "u" steps carry what is not valid UTF-8 */
		auto r4 = parse_recipe(R"({"b":[{"u":["AP8=","","Y2Fm6Q=="]}]})", limits);
		REQUIRE(r4.has_value());
		REQUIRE(r4->body[0].data.size() == 3);
		CHECK(r4->body[0].data[0] == std::string("\x00\xff", 2));
		CHECK(r4->body[0].data[1] == "");
		CHECK(r4->body[0].data[2] == "caf\xe9");

		/* Keys that the schema does not define are allowed */
		CHECK(parse_recipe(R"({"b":[],"x":{"y":[1,2.5e3,true,null,"z"]}})", limits).has_value());
	}

	TEST_CASE("dkim2 parse_recipe: not JSON")
	{
		using k = recipe_error_kind;

		CHECK(recipe_error_of("") == k::invalid_json);
		CHECK(recipe_error_of("garbage") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[])") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[]} x)") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[],})") == k::invalid_json);
		CHECK(recipe_error_of(R"({'b':[]})") == k::invalid_json);
		CHECK(recipe_error_of(R"({b:[]})") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b" = []})") == k::invalid_json);
		/* No comments, no macros, no includes */
		CHECK(recipe_error_of("{\"b\":[]} # comment") == k::invalid_json);
		CHECK(recipe_error_of("/* c */ {\"b\":[]}") == k::invalid_json);
		CHECK(recipe_error_of("{\"b\":[]}\n.include \"/etc/passwd\"") == k::invalid_json);
		/* Strings */
		CHECK(recipe_error_of("{\"b\":[{\"d\":[\"a\nb\"]}]}") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[{"d":["a\x"]}]})") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[{"d":["\ud83d"]}]})") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[{"d":["\ude00"]}]})") == k::invalid_json);
		CHECK(recipe_error_of(R"({"b":[{"d":["abc]}]})") == k::invalid_json);
		/* JSON text is UTF-8 */
		CHECK(recipe_error_of("{\"b\":[{\"d\":[\"caf\xe9\"]}]}") == k::invalid_json);
		CHECK(recipe_error_of("{\"b\":[{\"d\":[\"\xc0\xaf\"]}]}") == k::invalid_json);
	}

	TEST_CASE("dkim2 parse_recipe: invalid recipes")
	{
		using k = recipe_error_kind;

		/* Either "h" or "b" is required */
		CHECK(recipe_error_of(R"({})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"x":1})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"([1,2])") == k::invalid_recipe);
		CHECK(recipe_error_of(R"("b")") == k::invalid_recipe);

		/* Header recipes cannot be null or empty */
		CHECK(recipe_error_of(R"({"h":null})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"subject":null}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":[]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":{}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":"x"})") == k::invalid_recipe);

		/* Keys MUST be in lower case */
		CHECK(recipe_error_of(R"({"B":[]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"Subject":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"C":[1,2]}]})") == k::invalid_recipe);

		/* Keys MUST be unique */
		CHECK(recipe_error_of(R"({"b":[],"b":[]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":null,"b":[]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"to":[]},"h":{"cc":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"to":[{"d":["a"]}],"to":[{"d":["b"]}]}})") ==
			  k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1,2],"c":[1,2]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"d":["a"],"d":["b"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[],"x":{"y":1,"y":2}})") == k::invalid_recipe);

		/* Recipes MUST NOT be specified for header fields that are not signed */
		CHECK(recipe_error_of(R"({"h":{"received":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"x-mailer":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"dkim2-signature":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"":[]}})") == k::invalid_recipe);
		/* ... or for what is not a field name and would alias a real one */
		CHECK(recipe_error_of(R"({"h":{"from ":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{" x-foo":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"from\t":[]}})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"a:b":[]}})") == k::invalid_recipe);

		/* A step has exactly one key */
		CHECK(recipe_error_of(R"({"b":[{"c":[1,2],"d":["x"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"z":[1,2]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[[1,2]]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[1]})") == k::invalid_recipe);

		/* Copy steps: two integers from 1, end >= start */
		CHECK(recipe_error_of(R"({"b":[{"c":[3,1]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[0,1]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[-1,1]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1,2,3]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1.0,2]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1,2e0]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":["1","2"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[01,2]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1,99999999999999999999]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":1}]})") == k::invalid_recipe);

		/* Copy steps ascend and do not overlap: nothing can be duplicated */
		CHECK(recipe_error_of(R"({"b":[{"c":[1,2]},{"c":[2,3]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[1,5]},{"c":[1,5]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"c":[4,5]},{"d":["x"]},{"c":[1,2]}]})") ==
			  k::invalid_recipe);
		CHECK(!recipe_error_of(R"({"b":[{"c":[1,2]},{"d":["x"]},{"c":[3,3]}]})").has_value());

		/* Data steps: at least one string, no CR or LF */
		CHECK(recipe_error_of(R"({"b":[{"d":[]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"d":"x"}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"d":[1]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"d":["foo\r\nbar"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"d":["foo\u000abar"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"h":{"subject":[{"d":["a\nx-evil: 1"]}]}})") ==
			  k::invalid_recipe);

		/* "u" steps: canonical base64 without whitespace, no CR or LF inside */
		CHECK(recipe_error_of(R"({"b":[{"u":[]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["@@@@"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["AP8"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["AP 8="]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["!AAA"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["A=AA"]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["AB=="]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["DQo="]}]})") == k::invalid_recipe);
		CHECK(recipe_error_of(R"({"b":[{"u":["bGluZQ14"]}]})") == k::invalid_recipe);

		/* The offending step is quoted in the error */
		auto bad = parse_recipe(R"({"b":[{"c":[1,2]},{"c":[2,3]}]})", recipe_limits_t{});
		REQUIRE(!bad.has_value());
		CHECK(bad.error().what == R"({"c":[2,3]})");
	}

	TEST_CASE("dkim2 parse_recipe: limits")
	{
		using k = recipe_error_kind;

		recipe_limits_t small_limits;
		small_limits.max_steps = 2;
		CHECK(recipe_error_of(R"({"b":[{"c":[1,1]},{"c":[2,2]},{"c":[3,3]}]})",
							  small_limits) == k::too_complex);

		small_limits = recipe_limits_t{};
		small_limits.max_recipe_len = 10;
		CHECK(recipe_error_of(R"({"b":[{"c":[1,1]}]})", small_limits) == k::too_complex);

		small_limits = recipe_limits_t{};
		small_limits.max_data_lines = 3;
		CHECK(recipe_error_of(R"({"b":[{"d":["a","b"]},{"u":["","AP8="]}]})",
							  small_limits) == k::too_complex);

		small_limits = recipe_limits_t{};
		small_limits.max_names = 1;
		CHECK(recipe_error_of(R"({"h":{"to":[{"d":["x"]}],"cc":[{"d":["y"]}]}})",
							  small_limits) == k::too_complex);

		/* Deep nesting of what the schema does not define */
		std::string deep{R"({"b":[],"x":)"};
		deep.append(std::string(100, '['));
		deep.append(std::string(100, ']'));
		deep.append("}");
		CHECK(recipe_error_of(deep) == k::too_complex);
	}

	TEST_CASE("dkim2 apply_recipe_steps")
	{
		std::vector<std::string_view> current{"line1", "line2", "line3"};
		std::size_t budget = 1024;

		std::vector<recipe_step_t> steps;
		recipe_step_t copy_step;
		copy_step.is_copy = true;
		copy_step.start = 2;
		copy_step.end = 3;
		steps.push_back(copy_step);

		recipe_step_t data_step;
		data_step.data = {"inserted"};
		steps.push_back(data_step);

		auto out = apply_recipe_steps(current, steps, 100, budget);
		REQUIRE(out.has_value());
		REQUIRE(out->size() == 3);
		CHECK((*out)[0] == "line2");
		CHECK((*out)[1] == "line3");
		CHECK((*out)[2] == "inserted");
		/* 5 + 2 + 5 + 2 + 8 + 2 = 24 octets charged */
		CHECK(budget == 1024 - 24);

		/* No steps: everything is removed */
		std::size_t budget0 = 1024;
		auto none = apply_recipe_steps(current, {}, 100, budget0);
		REQUIRE(none.has_value());
		CHECK(none->empty());

		/* A copy of what does not exist is an invalid recipe */
		recipe_step_t oob;
		oob.is_copy = true;
		oob.start = 1;
		oob.end = 4;
		std::size_t budget2 = 1024;
		auto oob_res = apply_recipe_steps(current, {oob}, 100, budget2);
		REQUIRE(!oob_res.has_value());
		CHECK(oob_res.error().kind == recipe_error_kind::invalid_recipe);
		CHECK(oob_res.error().what == R"({"c":[1,4]})");

		/* The limits make a recipe too complex */
		recipe_step_t all;
		all.is_copy = true;
		all.start = 1;
		all.end = 3;
		std::size_t budget3 = 1024;
		auto too_many = apply_recipe_steps(current, {all}, 2, budget3);
		REQUIRE(!too_many.has_value());
		CHECK(too_many.error().kind == recipe_error_kind::too_complex);

		std::size_t budget4 = 10;
		auto too_much = apply_recipe_steps(current, {all}, 100, budget4);
		REQUIRE(!too_much.has_value());
		CHECK(too_much.error().kind == recipe_error_kind::too_complex);
	}

	TEST_CASE("dkim2 body canonicalization")
	{
		/* Empty body still hashes a CRLF */
		CHECK(body_canon_str("") == "\r\n");
		/* Missing final CRLF is added */
		CHECK(body_canon_str("foo") == "foo\r\n");
		CHECK(body_canon_str("foo\r\n") == "foo\r\n");
		/* Trailing empty lines are ignored */
		CHECK(body_canon_str("foo\r\n\r\n\r\n") == "foo\r\n");
		CHECK(body_canon_str("\r\n\r\n") == "\r\n");
		/* Bare line endings are normalized to CRLF */
		CHECK(body_canon_str("foo\nbar") == "foo\r\nbar\r\n");
		/* ... but a CR without LF is an octet as any other */
		CHECK(body_canon_str("foo\rbar\r") == "foo\rbar\r\r\n");
		CHECK(body_canon_str("foo\rbar\r\n") != body_canon_str("foo\r\nbar\r\n"));
		CHECK(body_canon_str("foo\n\n\n") == "foo\r\n");
		/* WSP-only lines are not empty per the spec */
		CHECK(body_canon_str("foo \r\n") == "foo \r\n");
		CHECK(body_canon_str(" \r\n") == " \r\n");
		/* Multi-line content */
		CHECK(body_canon_str("foo\r\nbar\r\nbaz") == "foo\r\nbar\r\nbaz\r\n");
		/* Empty lines in the middle are preserved */
		CHECK(body_canon_str("foo\r\n\r\nbar\r\n") == "foo\r\n\r\nbar\r\n");
	}

	TEST_CASE("dkim2 b64_encode")
	{
		CHECK(b64_encode("") == "");
		CHECK(b64_encode("<>") == "PD4=");
		CHECK(b64_encode("<bounce@example.com>") == DKIM2_TEST_MF);
		CHECK(b64_encode("<user@example.net>") == DKIM2_TEST_RT);
		CHECK(b64_encode(std::string_view{"\x00\xff", 2}) == "AP8=");

		/* What is encoded is what the strict decoder takes */
		for (std::size_t len = 0; len < 70; len++) {
			std::string data;

			for (std::size_t k = 0; k < len; k++) {
				data.push_back(static_cast<char>(k * 37 + len));
			}

			auto mf = parse_sig("i=1; m=1; t=1; d=example.com; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT
								"; s=a:rsa-sha256:" +
								b64_encode(data));

			if (len == 0) {
				CHECK(!mf.has_value());
			}
			else {
				REQUIRE(mf.has_value());
				CHECK(mf->sig_groups[0][0].sig == data);
			}
		}
	}

	TEST_CASE("dkim2 from_mailbox_domain")
	{
		CHECK(from_mailbox_domain("alice@example.com") == "example.com");
		CHECK(from_mailbox_domain("Alice <alice@Example.COM>") == "Example.COM");
		CHECK(from_mailbox_domain("alice@example.com (a comment @ here)") == "example.com");
		CHECK(from_mailbox_domain("\"a@b\" <alice@example.com> (x)") == "example.com");
		CHECK(from_mailbox_domain("alice@[192.0.2.1]") == "[192.0.2.1]");
		CHECK(!from_mailbox_domain("alice@example.com, bob@example.org").has_value());
		CHECK(!from_mailbox_domain("nobody").has_value());
	}

	TEST_CASE("dkim2 tag_list_builder")
	{
		tag_list_builder b;

		b.tag("i").text("1");
		b.tag("d").text("example.com");
		b.tag("rt").base64(std::string(40, 'A')).text(",").base64(std::string(100, 'B'));
		b.tag("s").text("sel:rsa-sha256:").base64(std::string(200, 'C'));

		auto flat = b.unfolded();
		CHECK(flat == "i=1; d=example.com; rt=" + std::string(40, 'A') + "," + std::string(100, 'B') +
						  "; s=sel:rsa-sha256:" + std::string(200, 'C'));

		auto folded = b.folded("\r\n");

		/* No line is long, and folding is undone by removing the whitespace */
		std::size_t line_start = 0;
		while (line_start < folded.size()) {
			auto line_end = folded.find("\r\n", line_start);
			auto line = folded.substr(line_start, line_end - line_start);
			CHECK(line.size() <= 78);
			if (line_end == std::string::npos) {
				break;
			}
			/* A continuation line starts with whitespace */
			REQUIRE(line_end + 2 < folded.size());
			CHECK(folded[line_end + 2] == '\t');
			line_start = line_end + 2;
		}

		auto hdrs = scan_headers("X: " + folded + "\r\n");
		REQUIRE(hdrs.has_value());
		REQUIRE(hdrs->size() == 1);
		CHECK(canon_sig_line("x", (*hdrs)[0].value) == canon_sig_line("x", flat));

		/* Text is never split: only base64 strings and tag boundaries fold */
		CHECK(folded.find("example.com;\r\n") != std::string::npos);
		CHECK(folded.find("sel:rsa-sha256:C") != std::string::npos);
		CHECK(b.folded("\n").find('\r') == std::string::npos);
	}

	TEST_CASE("dkim2 check_originator")
	{
		sign_fields_t fields;
		fields.domain = "example.com";
		fields.selector = "sel";
		fields.alg = "ed25519-sha256";
		fields.mf = "<bounce@mail.example.com>";
		fields.rt = {"<user@example.net>"};
		fields.t = 1700000000;

		auto check = [&](std::string_view header) {
			auto hdrs = scan_headers(header);
			REQUIRE(hdrs.has_value());
			return check_originator(*hdrs, fields);
		};

		CHECK(!check("From: Alice <alice@example.com>\r\nSubject: x\r\n"));
		/* The signing domain may be a parent or a subdomain of the From domain */
		CHECK(!check("From: alice@news.example.com\r\n"));
		fields.domain = "mail.example.com";
		CHECK(!check("From: alice@example.com\r\n"));
		fields.domain = "example.com";

		/* The From is not Authentic */
		CHECK(check("From: alice@example.org\r\n").has_value());
		CHECK(check("Subject: no from\r\n").has_value());
		CHECK(check("From: alice@example.com\r\nFrom: bob@example.com\r\n").has_value());
		CHECK(check("From: alice@example.com, bob@example.com\r\n").has_value());
		CHECK(check("From: alice@[192.0.2.1]\r\n").has_value());

		/* Not an original message */
		CHECK(check("Message-Instance: m=1; h=sha256:AA==:AA==\r\nFrom: alice@example.com\r\n").has_value());
		CHECK(check("dkim2-signature: i=1\r\nFrom: alice@example.com\r\n").has_value());

		/* d= is neither the MAIL FROM domain nor its parent */
		fields.mf = "<bounce@example.org>";
		CHECK(check("From: alice@example.com\r\n").has_value());
		fields.mf = "<bounce@example.com>";
		fields.domain = "mail.example.com";
		CHECK(check("From: alice@example.com\r\n").has_value());
		/* ... which does not matter for the null reverse-path */
		fields.mf = "<>";
		CHECK(!check("From: alice@example.com\r\n"));

		fields.domain = "example.com";
		fields.rt.clear();
		CHECK(check("From: alice@example.com\r\n").has_value());
		fields.rt = {"<user@example.net>"};
		fields.selector = "bad selector";
		CHECK(check("From: alice@example.com\r\n").has_value());
	}

	TEST_CASE("dkim2 sign_message")
	{
		sign_fields_t fields;
		fields.domain = "example.com";
		fields.selector = "sel";
		fields.alg = "ed25519-sha256";
		fields.mf = "<bounce@example.com>";
		fields.rt = {"<user@example.net>", "<other@example.org>"};
		fields.t = 1700000000;

		auto hdrs = scan_headers("Received: by mx\r\nFrom: alice@example.com\r\nSubject:  a \t test\r\n");
		REQUIRE(hdrs.has_value());

		std::string signed_digest;
		auto res = sign_message(*hdrs, "Hello\r\n\r\n", fields, "\r\n",
								[&](std::string_view digest) -> std::optional<std::string> {
									signed_digest = std::string{digest};
									return std::string(64, '\x5a');
								});
		REQUIRE(res.has_value());
		CHECK(signed_digest.size() == 32);

		/* What is produced is what the verifier parses */
		auto mi = parse_mi(res->mi_value);
		REQUIRE(mi.has_value());
		CHECK(mi->m == 1);
		REQUIRE(mi->hash_groups.size() == 1);
		CHECK(mi->hash_groups[0][0].alg == "sha256");
		CHECK(mi->hash_groups[0][0].header_hash.size() == 32);
		CHECK(!mi->has_recipe);

		auto sig = parse_sig(res->sig_value);
		REQUIRE(sig.has_value());
		CHECK(sig->i == 1);
		CHECK(sig->m == 1);
		CHECK(sig->t == 1700000000);
		CHECK(sig->domain == "example.com");
		CHECK(sig->mf == "<bounce@example.com>");
		REQUIRE(sig->rt.size() == 2);
		CHECK(sig->rt[1] == "<other@example.org>");
		CHECK(sig->sig_groups[0][0].selector == "sel");
		CHECK(sig->sig_groups[0][0].alg == "ed25519-sha256");
		CHECK(sig->sig_groups[0][0].sig == std::string(64, '\x5a'));
		CHECK(!check_custody(std::vector{*sig}));

		/* The folded forms unfold to the same fields */
		auto folded = scan_headers("Message-Instance: " + res->mi + "\r\nDKIM2-Signature: " + res->sig + "\r\n");
		REQUIRE(folded.has_value());
		REQUIRE(folded->size() == 2);
		CHECK(canon_sig_line("a", (*folded)[0].value) == canon_sig_line("a", res->mi_value));
		CHECK(canon_sig_line("a", (*folded)[1].value) == canon_sig_line("a", res->sig_value));

		/* The digest covers the instance and the field with a null signature */
		auto input = build_sig_input(std::vector{canon_sig_line("Message-Instance", res->mi_value)}, {},
									 canon_sig_line("DKIM2-Signature", res->sig_value));
		CHECK(input.find(":ed25519-sha256:\r\n") != std::string::npos);
		CHECK(input.find(std::string(8, 'W')) == std::string::npos);

		/* Unsigned header fields and trailing empty lines do not change the hashes */
		auto hdrs2 = scan_headers("X-Added: 1\r\nFrom: alice@example.com\r\nSubject: a test\r\n");
		REQUIRE(hdrs2.has_value());
		auto res2 = sign_message(*hdrs2, "Hello\r\n", fields, "\n",
								 [](std::string_view) -> std::optional<std::string> {
									 return std::string(64, '\x5a');
								 });
		REQUIRE(res2.has_value());
		CHECK(res2->mi_value == res->mi_value);
		CHECK(res2->sig.find('\r') == std::string::npos);

		/* A signing failure is an error */
		CHECK(!sign_message(*hdrs, "Hello\r\n", fields, "\r\n",
							[](std::string_view) -> std::optional<std::string> {
								return std::nullopt;
							})
				   .has_value());
	}
}

#endif /* RSPAMD_RSPAMD_CXX_UNIT_DKIM2_HXX */
