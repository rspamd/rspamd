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

#include <string>
#include <string_view>
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

		/* Tag without a name */
		CHECK(!parse_tag_list("=1").has_value());
		/* Invalid name */
		CHECK(!parse_tag_list("foo bar=1").has_value());
		/* Empty input is structurally fine */
		auto empty = parse_tag_list("");
		REQUIRE(empty.has_value());
		CHECK(empty->empty());
	}

	TEST_CASE("dkim2 parse_mi")
	{
		auto mi = parse_mi("m=1; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH);
		REQUIRE(mi.has_value());
		CHECK(mi->m == 1);
		REQUIRE(mi->hashes.size() == 1);
		CHECK(mi->hashes[0].alg == "sha256");
		CHECK(mi->hashes[0].header_hash == std::string(32, 'A'));
		CHECK(mi->hashes[0].body_hash == std::string(32, 'B'));
		CHECK(!mi->has_recipe);

		/* Multiple hash sets */
		auto mi2 = parse_mi("m=2; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH
							",sha512:" DKIM2_TEST_HH ":" DKIM2_TEST_BH);
		REQUIRE(mi2.has_value());
		CHECK(mi2->hashes.size() == 2);

		/* Missing mandatory tags */
		CHECK(!parse_mi("m=1").has_value());
		CHECK(!parse_mi("h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		/* Invalid m= */
		CHECK(!parse_mi("m=0; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		CHECK(!parse_mi("m=x; h=sha256:" DKIM2_TEST_HH ":" DKIM2_TEST_BH).has_value());
		/* Broken hash set */
		CHECK(!parse_mi("m=1; h=sha256:" DKIM2_TEST_HH).has_value());
	}

	TEST_CASE("dkim2 parse_sig")
	{
		auto sig = parse_sig("i=2; m=1; t=1700000000; mf=" DKIM2_TEST_MF
							 "; rt=" DKIM2_TEST_RT "; d=example.com; "
							 "s=sel:ed25519-sha256:" DKIM2_TEST_SIG "; f=donotmodify,exploded");
		REQUIRE(sig.has_value());
		CHECK(sig->i == 2);
		CHECK(sig->m == 1);
		CHECK(sig->t == 1700000000);
		CHECK(sig->mf == "<bounce@example.com>");
		REQUIRE(sig->rt.size() == 1);
		CHECK(sig->rt[0] == "<user@example.net>");
		CHECK(sig->domain == "example.com");
		REQUIRE(sig->sigs.size() == 1);
		CHECK(sig->sigs[0].selector == "sel");
		CHECK(sig->sigs[0].alg == "ed25519-sha256");
		CHECK(sig->sigs[0].sig == "0123456789abcdef");
		CHECK((sig->flags & DKIM2_SIG_FLAG_DONOTMODIFY) != 0);
		CHECK((sig->flags & DKIM2_SIG_FLAG_EXPLODED) != 0);
		CHECK((sig->flags & DKIM2_SIG_FLAG_FEEDBACK) == 0);

		/* Multiple signature sets */
		auto sig2 = parse_sig("i=1; m=1; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT
							  "; d=example.com; s=a:rsa-sha256:" DKIM2_TEST_SIG
							  ",b:ed25519-sha256:" DKIM2_TEST_SIG);
		REQUIRE(sig2.has_value());
		CHECK(sig2->sigs.size() == 2);
		CHECK(sig2->sigs[1].selector == "b");

		/* FWS inside base64 values is tolerated (folded header remnants) */
		auto sig3 = parse_sig("i=1; m=1; mf=PGJvdW5jZUBleGFt cGxlLmNvbT4=; rt=" DKIM2_TEST_RT
							  "; d=example.com; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(sig3.has_value());
		CHECK(sig3->mf == "<bounce@example.com>");

		/* Missing mandatory tag (d=) */
		auto bad = parse_sig("i=1; m=1; mf=" DKIM2_TEST_MF "; rt=" DKIM2_TEST_RT
							 "; s=a:rsa-sha256:" DKIM2_TEST_SIG);
		REQUIRE(!bad.has_value());
		CHECK(bad.error().find("d=") != std::string::npos);

		/* Invalid base64 in mf= */
		CHECK(!parse_sig("i=1; m=1; mf=@@@; rt=" DKIM2_TEST_RT
						 "; d=example.com; s=a:rsa-sha256:" DKIM2_TEST_SIG)
				   .has_value());
	}

	TEST_CASE("dkim2 canon_hash_line")
	{
		CHECK(canon_hash_line("Subject", "  Hello   world\t!  ") ==
			  "subject:Hello world !\r\n");
		CHECK(canon_hash_line("FROM", "Foo <foo@example.com>") ==
			  "from:Foo <foo@example.com>\r\n");
		CHECK(canon_hash_line("X-Empty", "") == "x-empty:\r\n");
		/* Unfolded continuation remnants are treated as WSP */
		CHECK(canon_hash_line("To", "a@b,\r\n\tc@d") == "to:a@b, c@d\r\n");
	}

	TEST_CASE("dkim2 canon_sig_line and blank_sig_values")
	{
		auto line = canon_sig_line("DKIM2-Signature",
								   "i=1; m=1; d=example.com; s = sel : rsa-sha256 : AbCd ;");
		CHECK(line == "dkim2-signature:i=1;m=1;d=example.com;s=sel:rsa-sha256:AbCd;\r\n");

		CHECK(blank_sig_values(line) ==
			  "dkim2-signature:i=1;m=1;d=example.com;s=sel:rsa-sha256:;\r\n");

		/* Multiple signature sets, s= tag in the middle */
		auto line2 = canon_sig_line("DKIM2-Signature",
									"i=1;s=a:rsa-sha256:XXX,b:ed25519-sha256:YYY;d=example.com");
		CHECK(blank_sig_values(line2) ==
			  "dkim2-signature:i=1;s=a:rsa-sha256:,b:ed25519-sha256:;d=example.com\r\n");
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
		CHECK(!relaxed_domain_match("example.com", "bounce.example.com"));
		CHECK(!relaxed_domain_match("examplexcom", "example.com"));
		CHECK(!relaxed_domain_match("", "example.com"));
		CHECK(!relaxed_domain_match("example.com", ""));
	}

	TEST_CASE("dkim2 smtp_addr_equal")
	{
		CHECK(smtp_addr_equal("<Foo@Example.COM>", "Foo@example.com"));
		CHECK(smtp_addr_equal("foo@example.com", "<foo@EXAMPLE.com>"));
		/* The local part is case-sensitive */
		CHECK(!smtp_addr_equal("<foo@example.com>", "Foo@example.com"));
		/* Null reverse-path */
		CHECK(smtp_addr_equal("<>", ""));
		CHECK(!smtp_addr_equal("<>", "foo@example.com"));
	}

	TEST_CASE("dkim2 smtp_addr_domain")
	{
		CHECK(smtp_addr_domain("<foo@example.com>") == "example.com");
		CHECK(smtp_addr_domain("foo@example.com") == "example.com");
		CHECK(smtp_addr_domain("<>") == "");
		CHECK(smtp_addr_domain("foo") == "");
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
		CHECK(body_canon_str("foo\rbar\r") == "foo\r\nbar\r\n");
		CHECK(body_canon_str("foo\n\n\n") == "foo\r\n");
		/* WSP-only lines are not empty per the spec */
		CHECK(body_canon_str("foo \r\n") == "foo \r\n");
		CHECK(body_canon_str(" \r\n") == " \r\n");
		/* Multi-line content */
		CHECK(body_canon_str("foo\r\nbar\r\nbaz") == "foo\r\nbar\r\nbaz\r\n");
		/* Empty lines in the middle are preserved */
		CHECK(body_canon_str("foo\r\n\r\nbar\r\n") == "foo\r\n\r\nbar\r\n");
	}
}

#endif /* RSPAMD_RSPAMD_CXX_UNIT_DKIM2_HXX */
