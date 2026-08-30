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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_TLD_LOOKUP_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_TLD_LOOKUP_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/tld_lookup.h"

#include <cstdio>
#include <string>

TEST_SUITE("tld_lookup")
{
	/* A representative fragment of the public suffix list: exact rules,
	 * wildcards, exceptions, unicode + punycode duals, private section */
	static const char test_psl[] =
		"// This is a comment\n"
		"// ===BEGIN ICANN DOMAINS===\n"
		"\n"
		"com\n"
		"org\n"
		"uk\n"
		"co.uk\n"
		"jp\n"
		"*.kobe.jp\n"
		"!city.kobe.jp\n"
		"*.ck\n"
		"!www.ck\n"
		"\xe4\xb8\xad\xe5\x9b\xbd\n" /* 中国 */
		"xn--fiqs8s\n"
		"// ===END ICANN DOMAINS===\n"
		"// ===BEGIN PRIVATE DOMAINS===\n"
		"github.io\n"
		"s3.amazonaws.com\n"
		"// ===END PRIVATE DOMAINS===\n";

	static auto make_lookup() -> rspamd_tld_lookup *
	{
		char path[PATH_MAX];
		const char *tmpdir = getenv("TMPDIR");

		rspamd_snprintf(path, sizeof(path), "%s%c%s", tmpdir ? tmpdir : "/tmp",
						G_DIR_SEPARATOR, "rspamd-test-tld-XXXXXX");

		int fd = g_mkstemp(path);
		REQUIRE(fd != -1);
		REQUIRE(write(fd, test_psl, sizeof(test_psl) - 1) == (ssize_t) (sizeof(test_psl) - 1));
		close(fd);

		auto *lookup = rspamd_tld_lookup_new(path);
		unlink(path);
		REQUIRE(lookup != nullptr);

		return lookup;
	}

	static auto registrable_of(rspamd_tld_lookup * l, const std::string &host) -> std::string
	{
		rspamd_ftok_t tok;

		if (!rspamd_tld_lookup_registrable(l, host.data(), host.size(), &tok)) {
			return "";
		}

		return std::string{tok.begin, tok.len};
	}

	static auto suffix_of(rspamd_tld_lookup * l, const std::string &host,
						  unsigned int *flags = nullptr) -> std::string
	{
		rspamd_ftok_t tok;

		if (!rspamd_tld_lookup_suffix(l, host.data(), host.size(), &tok, flags)) {
			return "";
		}

		return std::string{tok.begin, tok.len};
	}

	TEST_CASE("registrable domain: exact rules")
	{
		auto *l = make_lookup();

		CHECK(registrable_of(l, "example.com") == "example.com");
		CHECK(registrable_of(l, "mail.example.com") == "example.com");
		CHECK(registrable_of(l, "a.b.c.d.example.com") == "example.com");
		CHECK(registrable_of(l, "foo.co.uk") == "foo.co.uk");
		CHECK(registrable_of(l, "a.b.foo.co.uk") == "foo.co.uk");
		/* Longest suffix must win over the shorter one */
		CHECK(registrable_of(l, "foo.uk") == "foo.uk");

		/* A host that is itself a public suffix resolves to the whole host */
		CHECK(registrable_of(l, "com") == "com");
		CHECK(registrable_of(l, "co.uk") == "co.uk");

		/* No rule matched at all */
		CHECK(registrable_of(l, "localhost") == "");
		CHECK(registrable_of(l, "foo.unknown") == "");
		CHECK(registrable_of(l, "") == "");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("registrable domain: wildcard rules")
	{
		auto *l = make_lookup();

		/* *.kobe.jp: any single label under kobe.jp is a public suffix */
		CHECK(registrable_of(l, "kobe.jp") == "kobe.jp");
		CHECK(registrable_of(l, "x.kobe.jp") == "x.kobe.jp");
		CHECK(registrable_of(l, "y.x.kobe.jp") == "y.x.kobe.jp");
		CHECK(registrable_of(l, "z.y.x.kobe.jp") == "y.x.kobe.jp");

		/* *.ck with no bare "ck" rule */
		CHECK(registrable_of(l, "other.ck") == "other.ck");
		CHECK(registrable_of(l, "x.other.ck") == "x.other.ck");
		CHECK(registrable_of(l, "y.x.other.ck") == "x.other.ck");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("registrable domain: exception rules")
	{
		auto *l = make_lookup();

		/* !city.kobe.jp cancels *.kobe.jp */
		CHECK(registrable_of(l, "city.kobe.jp") == "city.kobe.jp");
		CHECK(registrable_of(l, "a.city.kobe.jp") == "city.kobe.jp");
		CHECK(registrable_of(l, "b.a.city.kobe.jp") == "city.kobe.jp");

		/* !www.ck cancels *.ck */
		CHECK(registrable_of(l, "www.ck") == "www.ck");
		CHECK(registrable_of(l, "sub.www.ck") == "www.ck");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("registrable domain: unicode and punycode")
	{
		auto *l = make_lookup();

		CHECK(registrable_of(l, "foo.\xe4\xb8\xad\xe5\x9b\xbd") ==
			  "foo.\xe4\xb8\xad\xe5\x9b\xbd");
		CHECK(registrable_of(l, "foo.xn--fiqs8s") == "foo.xn--fiqs8s");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("registrable domain: case and trailing dot")
	{
		auto *l = make_lookup();

		/* Case-insensitive match, output preserves the original case */
		CHECK(registrable_of(l, "FOO.Example.COM") == "Example.COM");
		CHECK(registrable_of(l, "EXAMPLE.COM") == "EXAMPLE.COM");

		/* FQDN form: single trailing dot is ignored */
		CHECK(registrable_of(l, "example.com.") == "example.com");
		CHECK(registrable_of(l, "com.") == "com");
		CHECK(registrable_of(l, ".") == "");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("registrable domain: edge cases")
	{
		auto *l = make_lookup();

		/* Deeply nested host: probing is bounded but must still match */
		CHECK(registrable_of(l, "a.b.c.d.e.f.g.h.i.j.example.com") == "example.com");

		/* 63-char label */
		std::string long_label(63, 'x');
		CHECK(registrable_of(l, long_label + ".com") == long_label + ".com");

		/* Oversized host (over the stack buffer) must still work */
		std::string big_host;
		for (int i = 0; i < 100; i++) {
			big_host += "verylonglabel.";
		}
		big_host += "example.com";
		CHECK(registrable_of(l, big_host) == "example.com");

		/* Empty label inside the host must not confuse the search */
		CHECK(registrable_of(l, "foo..com") == ".com");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("public suffix and flags")
	{
		auto *l = make_lookup();
		unsigned int flags = 0;

		CHECK(suffix_of(l, "foo.co.uk", &flags) == "co.uk");
		CHECK(flags == 0);

		CHECK(suffix_of(l, "z.y.x.kobe.jp", &flags) == "x.kobe.jp");
		CHECK((flags & RSPAMD_TLD_SUFFIX_WILDCARD) != 0);

		CHECK(suffix_of(l, "a.city.kobe.jp", &flags) == "kobe.jp");
		CHECK((flags & RSPAMD_TLD_SUFFIX_EXCEPTION) != 0);

		CHECK(suffix_of(l, "foo.github.io", &flags) == "github.io");
		CHECK((flags & RSPAMD_TLD_SUFFIX_PRIVATE) != 0);
		CHECK(registrable_of(l, "foo.github.io") == "foo.github.io");

		/* Private multi-label rule */
		CHECK(registrable_of(l, "bucket.s3.amazonaws.com") == "bucket.s3.amazonaws.com");
		CHECK(registrable_of(l, "s3.amazonaws.com") == "s3.amazonaws.com");

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("final labels")
	{
		auto *l = make_lookup();

		CHECK(rspamd_tld_lookup_is_final_label(l, "com", 3));
		CHECK(rspamd_tld_lookup_is_final_label(l, "COM", 3));
		CHECK(rspamd_tld_lookup_is_final_label(l, "uk", 2));
		CHECK(rspamd_tld_lookup_is_final_label(l, "jp", 2));
		/* Final label of wildcard and exception rules */
		CHECK(rspamd_tld_lookup_is_final_label(l, "ck", 2));
		/* Private section */
		CHECK(rspamd_tld_lookup_is_final_label(l, "io", 2));
		/* Unicode */
		CHECK(rspamd_tld_lookup_is_final_label(l, "\xe4\xb8\xad\xe5\x9b\xbd", 6));

		CHECK_FALSE(rspamd_tld_lookup_is_final_label(l, "zz", 2));
		CHECK_FALSE(rspamd_tld_lookup_is_final_label(l, "", 0));
		CHECK_FALSE(rspamd_tld_lookup_is_final_label(l, "kobe.jp", 7));

		rspamd_tld_lookup_destroy(l);
	}

	TEST_CASE("nrules and missing file")
	{
		auto *l = make_lookup();

		CHECK(rspamd_tld_lookup_nrules(l) == 13);
		rspamd_tld_lookup_destroy(l);

		CHECK(rspamd_tld_lookup_new("/nonexistent/tld/file") == nullptr);
		CHECK(rspamd_tld_lookup_nrules(nullptr) == 0);
	}
}

#endif
