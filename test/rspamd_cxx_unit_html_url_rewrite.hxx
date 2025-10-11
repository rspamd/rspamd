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

/* Unit tests for HTML URL rewriting */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_HTML_URL_REWRITE_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_HTML_URL_REWRITE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/html/html_url_rewrite.hxx"

#include <vector>
#include <string>
#include <string_view>

using namespace rspamd::html;

TEST_SUITE("html_url_rewrite")
{
	TEST_CASE("validate_patches - empty patches")
	{
		std::vector<rewrite_patch> patches;
		CHECK(validate_patches(patches) == true);
	}

	TEST_CASE("validate_patches - single patch")
	{
		std::vector<rewrite_patch> patches{
			{0, 10, 5, "replacement"}};
		CHECK(validate_patches(patches) == true);
	}

	TEST_CASE("validate_patches - multiple patches without overlap")
	{
		std::vector<rewrite_patch> patches{
			{0, 10, 5, "repl1"},
			{0, 20, 5, "repl2"},
			{0, 30, 5, "repl3"}};
		CHECK(validate_patches(patches) == true);
	}

	TEST_CASE("validate_patches - patches with overlap")
	{
		std::vector<rewrite_patch> patches{
			{0, 10, 10, "repl1"},// offset 10, len 10 -> ends at 20
			{0, 15, 5, "repl2"}  // offset 15 -> overlaps!
		};
		CHECK(validate_patches(patches) == false);
	}

	TEST_CASE("validate_patches - patches exactly adjacent (no overlap)")
	{
		std::vector<rewrite_patch> patches{
			{0, 10, 10, "repl1"},// offset 10, len 10 -> ends at 20
			{0, 20, 5, "repl2"}  // offset 20 -> starts exactly where prev ends
		};
		CHECK(validate_patches(patches) == true);
	}

	TEST_CASE("validate_patches - multiple parts without overlap")
	{
		std::vector<rewrite_patch> patches{
			{0, 10, 5, "repl1"},
			{0, 20, 5, "repl2"},
			{1, 10, 5, "repl3"},// different part
			{1, 20, 5, "repl4"} // different part
		};
		CHECK(validate_patches(patches) == true);
	}

	TEST_CASE("validate_patches - unsorted patches (should sort and validate)")
	{
		std::vector<rewrite_patch> patches{
			{0, 30, 5, "repl3"},
			{0, 10, 5, "repl1"},
			{0, 20, 5, "repl2"}};
		CHECK(validate_patches(patches) == true);
	}

	TEST_CASE("validate_patches - unsorted with overlap")
	{
		std::vector<rewrite_patch> patches{
			{0, 20, 10, "repl2"},// ends at 30
			{0, 25, 5, "repl3"}  // overlaps with first
		};
		CHECK(validate_patches(patches) == false);
	}

	TEST_CASE("apply_patches - empty patches")
	{
		std::string_view original = "hello world";
		std::vector<rewrite_patch> patches;
		auto result = apply_patches(original, patches);
		CHECK(result == "hello world");
	}

	TEST_CASE("apply_patches - single replacement")
	{
		std::string_view original = "hello world";
		std::vector<rewrite_patch> patches{
			{0, 6, 5, "earth"}// replace "world" with "earth"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "hello earth");
	}

	TEST_CASE("apply_patches - multiple replacements")
	{
		std::string_view original = "hello world foo bar";
		std::vector<rewrite_patch> patches{
			{0, 0, 5, "hi"},   // replace "hello" with "hi"
			{0, 6, 5, "earth"},// replace "world" with "earth"
			{0, 12, 3, "baz"}, // replace "foo" with "baz"
			{0, 16, 3, "qux"}  // replace "bar" with "qux"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "hi earth baz qux");
	}

	TEST_CASE("apply_patches - replacement at beginning")
	{
		std::string_view original = "hello world";
		std::vector<rewrite_patch> patches{
			{0, 0, 5, "hi"}// replace "hello" with "hi"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "hi world");
	}

	TEST_CASE("apply_patches - replacement at end")
	{
		std::string_view original = "hello world";
		std::vector<rewrite_patch> patches{
			{0, 6, 5, "earth"}// replace "world" with "earth"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "hello earth");
	}

	TEST_CASE("apply_patches - replacement with longer string")
	{
		std::string_view original = "a b c";
		std::vector<rewrite_patch> patches{
			{0, 2, 1, "longer"}// replace "b" with "longer"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "a longer c");
	}

	TEST_CASE("apply_patches - replacement with shorter string")
	{
		std::string_view original = "a longword c";
		std::vector<rewrite_patch> patches{
			{0, 2, 8, "b"}// replace "longword" with "b"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "a b c");
	}

	TEST_CASE("apply_patches - replacement with empty string")
	{
		std::string_view original = "a b c";
		std::vector<rewrite_patch> patches{
			{0, 2, 1, ""}// replace "b" with empty string
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "a  c");
	}

	TEST_CASE("apply_patches - HTML attribute value replacement")
	{
		std::string_view original = R"(<a href="http://evil.com">link</a>)";
		std::vector<rewrite_patch> patches{
			{0, 9, 15, "http://safe.com"}// replace URL (15 chars)
		};
		auto result = apply_patches(original, patches);
		CHECK(result == R"(<a href="http://safe.com">link</a>)");
	}

	TEST_CASE("apply_patches - multiple HTML attributes")
	{
		std::string_view original = R"(<a href="http://a.com">A</a> <a href="http://b.com">B</a>)";
		std::vector<rewrite_patch> patches{
			{0, 9, 12, "http://x.com"},// first URL (12 chars)
			{0, 38, 12, "http://y.com"}// second URL (12 chars)
		};
		auto result = apply_patches(original, patches);
		CHECK(result == R"(<a href="http://x.com">A</a> <a href="http://y.com">B</a>)");
	}

	TEST_CASE("apply_patches - consecutive replacements")
	{
		std::string_view original = "abcdef";
		std::vector<rewrite_patch> patches{
			{0, 0, 2, "XY"},// replace "ab" with "XY"
			{0, 2, 2, "Z"}, // replace "cd" with "Z"
			{0, 4, 2, "W"}  // replace "ef" with "W"
		};
		auto result = apply_patches(original, patches);
		CHECK(result == "XYZW");
	}

	TEST_CASE("apply_patches - sorted by offset")
	{
		std::string_view original = "123456789";
		// Patches intentionally unsorted - function should handle it after validate_patches sorts
		std::vector<rewrite_patch> patches{
			{0, 6, 3, "ghi"},
			{0, 0, 3, "abc"},
			{0, 3, 3, "def"}};
		// Note: apply_patches expects sorted patches, so validate_patches should be called first
		validate_patches(patches);
		auto result = apply_patches(original, patches);
		CHECK(result == "abcdefghi");
	}
}

#endif
