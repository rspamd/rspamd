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
		// Expect a replacement char (U+FFFD) and the literal '(' from the invalid pair
		CHECK(decoded.find("\xEF\xBF\xBD") != std::string::npos);
		CHECK(decoded.find("(") != std::string::npos);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("structured header encodes ASCII punctuation as Q-words")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Price, list (v2) - update";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), true);
		std::string output(output_cstr);
		// Should contain at least one encoded-word when structured
		CHECK(output.find("=?UTF-8?Q?") != std::string::npos);
		// Token length invariant
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

	TEST_CASE("mixed ASCII/UTF/punct/spacing/emoji encodes and decodes correctly")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "Hello, 世界!   Tabs\ttoo — and emojis: ";
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
		CHECK(decoded == input);
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

	TEST_CASE("Cyrillic around parentheses splits encoded-words correctly")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "ололо (ололо test)    test";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("=?UTF-8?Q?=D0=BE=D0=BB=D0=BE=D0=BB=D0=BE?= (=?UTF-8?Q?=D0=BE=D0=BB=D0=BE=D0=BB=D0=BE?= test)    test"));
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
		CHECK(output == std::string(
							"=?UTF-8?Q?=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82____=D0=BC=D0=B8=D1=80_=D0?="
							"=?UTF-8?Q?=9A=D0=B0=D0=BA_=D0=B4=D0=B5=D0=BB=D0=B0?=?"));
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

	TEST_CASE("Japanese with parentheses keeps parentheses outside encoded-words")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "こんにちは(世界)";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string(
							"=?UTF-8?Q?=E3=81=93=E3=82=93=E3=81=AB=E3=81=A1=E3=81=AF?=(=?UTF-8?Q?=E4=B8=96=E7=95=8C?=)"));
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
		std::string expected =
			"ASCII_Text "
			"=?UTF-8?Q?=E3=81=93=E3=82=8C=E3=81=AF=E9=9D=9E=E5=B8=B8=E3=81?="
			"=?UTF-8?Q?=AB=E9=95=B7=E3=81=84=E9=9D=9EASCII=E3=83=86=E3=82=AD=E3=82%B9?="
			"=?UTF-8?Q?=E3=83=88=E3=81=A7=E3=80=81=E3=82%A8=E3=83%B3=E3=82%B3=E3=83%BC?="
			"=?UTF-8?Q?=E3=83%89=E3=81=8C=E5%BF%85=E8%A6%81=E3=81=AB=E3=81%AA=E3=82%8A?="
			"=?UTF-8?Q?=E3=81=BE=E3=81=99=E3=80=82?=";
		CHECK(output == expected);
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
		std::string expected =
			"=?UTF-8?Q?=E9=9D=9E=E5=B8%B8=E3=81=AB=E9=95%B7=E3=81=84=E9=9D=9EASCII=E6?="
			"=?UTF-8?Q?=96=87=E5%AD=97=E5%88%97=E3=82%92=E4%BD%BF=E7=94=A8=E3=81=97=E3?="
			"=?UTF-8?Q?=81=A6=E3=82%A8=E3=83%B3=E3=82%B3=E3=83%BC=E3=83%89=E3=83%AF=E3?="
			"=?UTF-8?Q?=83=BC=E3=83%89=E3=81=AE=E5%88%86=E5%89%B2=E3=82%92=E3=83%86=E3?="
			"=?UTF-8?Q?=82%B9=E3=83%88=E3=81=97=E3=81%BE=E3=81=99=E3=80=82=E3=83%87=E3?="
			"=?UTF-8?Q?=83=BC=E3=82%BF=E3=81=8C=E9=95%B7=E3=81=99=E3=81%8E=E3=82%8B=E5?="
			"=?UTF-8?Q?=A0=B4=E5%90%88=E3=80%81=E6=AD=A3=E3=81=97=E3=81%8F=E5%88%86=E5?="
			"=?UTF-8?Q?=89%B2=E3=82%8C=E3=82%8B=E3=81%B9=E3=81%8D=E3=81%A7=E3=81%99=E3=80%82?=";
		CHECK(output == expected);
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("Mixed ASCII with Cyrillic inside brackets encodes inner Cyrillic only")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::string input = "PDF_LONG_TRAILER (0.20)[Док.за 10102024.pdf:416662]";
		char *output_cstr = rspamd_mime_header_encode(input.c_str(), input.size(), false);
		std::string output(output_cstr);
		CHECK(output == std::string("PDF_LONG_TRAILER (0.20)[=?UTF-8?Q?=D0=94=D0=BE=D0=BA=2E=D0=B7=D0=B0?= 10102024.pdf:416662]"));
		gboolean invalid_utf = FALSE;
		char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
		std::string decoded(decoded_cstr);
		CHECK(invalid_utf == FALSE);
		CHECK(decoded == input);
		g_free(output_cstr);
		rspamd_mempool_delete(pool);
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
