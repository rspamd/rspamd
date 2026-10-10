/*
 * Copyright 2024 Vsevolod Stakhov
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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_RFC2047_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_RFC2047_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include <string>
#include <vector>
#include "libutil/mem_pool.h"
#include "libmime/mime_headers.h"

TEST_SUITE("rfc2047 encode")
{
	TEST_CASE("rspamd_mime_header_encode issue sample and invariants")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "¡Con estos precios, el norte es tuyo! 🏜️";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// All encoded-words must be <= 76 chars
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 76);
			pos = end + 2;
		}
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("rspamd_mime_header_encode handles invalid UTF-8 bytes safely")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = std::string("Invalid: ") + std::string("\xC3\x28", 2) + " end";// invalid UTF-8 sequence C3 28
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// Encoded-words length constraint
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 76);
			pos = end + 2;
		}
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		// Expect replacement with '?' (current decoder policy) and the literal '(' from the invalid pair
		CHECK(decoded.find("?") != std::string::npos);
		CHECK(decoded.find("(") != std::string::npos);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("structured ASCII value is unchanged")
	{
		// Encoding ASCII specials would break the address structure
		for (const std::string input: {"Price, list (v2) - update", "John via list <a@b.c>"}) {
			char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), true);
			CHECK(std::string(output_cstr) == input);
			g_free(output_cstr);
		}
	}

	TEST_CASE("mixed ASCII/UTF/punct/spacing/emoji encodes and decodes correctly")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Hello, 世界!   Tabs\too — and emojis: ";
		// Long emoji sequence
		for (int i = 0; i < 16; i++) {
			input += "😀";
		}
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// Token length invariant for every encoded-word
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 76);
			pos = end + 2;
		}
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		// Decoder normalizes tabs to spaces; adapt expected accordingly
		std::string expected_decoded = input;
		for (char &ch: expected_decoded) {
			if (ch == '\t') ch = ' ';
		}
		CHECK(decoded == expected_decoded);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("ASCII-only string is unchanged")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Hello World";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("Hello World"));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Mixed ASCII with Cyrillic encodes Cyrillic segment only")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Hello Мир";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("Hello =?UTF-8?Q?=D0=9C=D0=B8=D1=80?="));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Cyrillic around parentheses is encoded with its words")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "ололо (ололо test)    test";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// Unstructured text has no comments: "(" is part of the word, and an
		// encoded-word must be delimited by whitespace
		CHECK(output == std::string("=?UTF-8?Q?=D0=BE=D0=BB=D0=BE=D0=BB=D0=BE_=28=D0=BE=D0=BB=D0=BE=D0=BB?= =?UTF-8?Q?=D0=BE?= test)    test"));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Russian text with multiple spaces is encoded and preserved")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Привет    мир Как дела?";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// Invariant: every encoded-word <= 76 chars
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 76);
			pos = end + 2;
		}
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Empty input yields empty output")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string(""));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Japanese with parentheses is encoded as one word")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "こんにちは(世界)";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string(
							"=?UTF-8?Q?=E3=81=93=E3=82=93=E3=81=AB=E3=81=A1=E3=81=AF=28=E4=B8=96?= "
							"=?UTF-8?Q?=E7=95=8C=29?="));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Parentheses-only input is unchanged")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "(Hello)";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("(Hello)"));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("ASCII with trailing parenthesis is unchanged")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Hello)";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("Hello)"));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Chinese text is Q-encoded in a single encoded-word if fits")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "你好世界";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("=?UTF-8?Q?=E4=BD=A0=E5=A5=BD=E4=B8=96=E7=95=8C?="));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("ASCII prefix with long UTF-8 suffix encodes suffix only")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "ASCII_Text これは非常に長い非ASCIIテキストで、エンコードが必要になります。";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// Keep ASCII prefix and ensure at least one encoded-word exists
		CHECK(output.find("ASCII_Text ") == 0);
		CHECK(output.find("=?UTF-8?Q?") != std::string::npos);
		// Invariant: each encoded-word <= 76 chars
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 76);
			pos = end + 2;
		}
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Very long non-ASCII string splits across multiple encoded-words")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input =
			"非常に長い非ASCII文字列を使用してエンコードワードの分割をテストします。データが長すぎる場合、正しく分割されるべきです。";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		// Invariant: encoded-words present and each <= 76 chars
		CHECK(output.find("=?UTF-8?Q?") != std::string::npos);
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 76);
			pos = end + 2;
		}
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Mixed ASCII with Cyrillic inside brackets encodes the whole word")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "PDF_LONG_TRAILER (0.20)[Док.за 10102024.pdf:416662]";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("PDF_LONG_TRAILER =?UTF-8?Q?=280=2E20=29=5B=D0=94=D0=BE=D0=BA=2E=D0=B7=D0=B0?= 10102024.pdf:416662]"));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	static std::string encode_header(const std::string &input, bool structured)
	{
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), structured);
		std::string output(output_cstr);
		g_free(output_cstr);
		return output;
	}

	static std::string decode_header(const std::string &input)
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		gboolean invalid_utf = FALSE;
		std::string decoded(rspamd_mime_header_decode(pool, input.c_str(), input.size(), &invalid_utf));
		rspamd_mempool_delete(pool);
		return decoded;
	}

	TEST_CASE("unstructured word with an ASCII prefix is encoded as a whole")
	{
		// An encoded-word glued to text ("Pr=?UTF-8?Q?...") is invalid
		CHECK(encode_header("Prüfung möglich", false) == "=?UTF-8?Q?Pr=C3=BCfung_m=C3=B6glich?=");
		CHECK(encode_header("Müller, Hans", false) == "=?UTF-8?Q?M=C3=BCller=2C?= Hans");
		CHECK(decode_header(encode_header("Prüfung möglich", false)) == "Prüfung möglich");
	}

	TEST_CASE("adjacent encoded-words are separated by whitespace")
	{
		std::string input;
		for (int i = 0; i < 40; i++) {
			input += "ü";
		}
		auto output = encode_header(input, false);
		CHECK(output.find("?==?") == std::string::npos);
		size_t pos = 0;
		while (true) {
			size_t start = output.find("=?UTF-8?Q?", pos);
			if (start == std::string::npos) break;
			size_t end = output.find("?=", start);
			REQUIRE(end != std::string::npos);
			CHECK(end + 2 - start <= 75);
			pos = end + 2;
		}
		CHECK(decode_header(output) == input);
	}

	TEST_CASE("a fold inside a run keeps the separator in the encoded text")
	{
		// Whitespace between encoded-words is dropped when decoding, so the tab
		// that separates the words once unfolded is repeated inside the second
		// encoded-word, while the fold itself stays in place
		CHECK(encode_header("Prüfung\r\n\tmöglich", false) ==
			  "=?UTF-8?Q?Pr=C3=BCfung?=\r\n\t=?UTF-8?Q?=09m=C3=B6glich?=");
		CHECK(encode_header("Prüfung \n möglich", false) ==
			  "=?UTF-8?Q?Pr=C3=BCfung_?=\n =?UTF-8?Q?_m=C3=B6glich?=");
		CHECK(decode_header(encode_header("Prüfung\r\n möglich", false)) == "Prüfung möglich");
		// A line break without whitespace after it is not a fold and ends the run
		CHECK(encode_header("Prüfung\r\nmöglich", false) ==
			  "=?UTF-8?Q?Pr=C3=BCfung?=\r\n=?UTF-8?Q?m=C3=B6glich?=");
	}

	TEST_CASE("an encoded-word lookalike next to encoded text is encoded")
	{
		// Left as is, "=?utf-8?q?x?=" would be decoded and glued to the
		// preceding encoded-word
		auto output = encode_header("Привет =?utf-8?q?x?=", false);
		CHECK(output.find("=?utf-8?q?x?=") == std::string::npos);
		CHECK(decode_header(output) == "Привет =?utf-8?q?x?=");
		// a 7-bit value is never touched
		CHECK(encode_header("Re: =?utf-8?q?x?=", false) == "Re: =?utf-8?q?x?=");
	}

	TEST_CASE("a run spans whitespace-only continuation lines")
	{
		// Each continuation line keeps its whitespace inside an encoded-word
		CHECK(encode_header("Привет\r\n \r\n мир", false) ==
			  "=?UTF-8?Q?=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82?=\r\n =?UTF-8?Q?_?=\r\n "
			  "=?UTF-8?Q?_=D0=BC=D0=B8=D1=80?=");
		CHECK(decode_header(encode_header("Привет\r\n \r\n мир", false)) == "Привет  мир");
	}

	TEST_CASE("structured address list encodes names and comments only")
	{
		const std::vector<std::pair<std::string, std::string>> cases{
			{"Jörg <third@example.com> (Kommentar)",
			 "=?UTF-8?Q?J=C3=B6rg?= <third@example.com> (Kommentar)"},
			{"Jörg <third@example.com> (Kommentär)",
			 "=?UTF-8?Q?J=C3=B6rg?= <third@example.com> (=?UTF-8?Q?Komment=C3=A4r?=)"},
			{"\"Jörg Müller\" <sender@example.com>",
			 "=?UTF-8?Q?J=C3=B6rg_M=C3=BCller?= <sender@example.com>"},
			// parentheses inside a quoted name are text, not a comment
			{"\"Ö (x)\" <b@example.com>",
			 "=?UTF-8?Q?=C3=96_=28x=29?= <b@example.com>"},
			{"\"Änne Example\" <first@example.com>, <second@example.com>",
			 "=?UTF-8?Q?=C3=84nne_Example?= <first@example.com>, <second@example.com>"},
			{"Gruppe Ä: <a@example.com>, b@example.com;",
			 "=?UTF-8?Q?Gruppe_=C3=84?=: <a@example.com>, b@example.com;"},
			{"John Q. Müller <j@example.com>",
			 "=?UTF-8?Q?John_Q=2E_M=C3=BCller?= <j@example.com>"},
			{"Jörg via list <a@b.c>",
			 "=?UTF-8?Q?J=C3=B6rg_via_list?= <a@b.c>"},
			// a phrase alone, without an address
			{"Jörg Müller", "=?UTF-8?Q?J=C3=B6rg_M=C3=BCller?="},
		};

		for (const auto &c: cases) {
			CAPTURE(c.first);
			CHECK(encode_header(c.first, true) == c.second);
		}

		CHECK(decode_header(encode_header("Jörg <third@example.com> (Kommentär)", true)) ==
			  "Jörg <third@example.com> (Kommentär)");
	}

	TEST_CASE("structured parts without an RFC 2047 form are kept as they are")
	{
		const std::vector<std::pair<std::string, std::string>> cases{
			{"jörg@example.com", "jörg@example.com"},
			{"Jörg <jörg@example.com>", "=?UTF-8?Q?J=C3=B6rg?= <jörg@example.com>"},
			// unbalanced syntax cannot be tokenized
			{"\"Jörg <a@example.com>", "\"Jörg <a@example.com>"},
			{"Jörg (x <a@example.com>", "Jörg (x <a@example.com>"},
			// encoding would turn inner parentheses into text
			{"Jörg (a (ä) b) <a@example.com>", "=?UTF-8?Q?J=C3=B6rg?= (a (ä) b) <a@example.com>"},
		};

		for (const auto &c: cases) {
			CAPTURE(c.first);
			CHECK(encode_header(c.first, true) == c.second);
		}
	}

	TEST_CASE("rspamd_mime_header_encode handles long ASCII input without encoding")
	{
		// Input string consisting of repeated ASCII characters
		std::string input_str(100, 'A');// 100 'A's
		const char *input = input_str.c_str();
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = input_str;
		CHECK(output == expected_output);
		g_free(output_cstr);
	}
}
#endif
