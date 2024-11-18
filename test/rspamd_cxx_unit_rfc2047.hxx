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
	TEST_CASE("rspamd_mime_header_encode handles ASCII-only input")
	{
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "rfc2047", 0);
		std::vector<std::pair<std::string, std::string>> cases = {
			{"Hello World", "Hello World"},
			{"Hello Мир", "Hello =?UTF-8?Q?=D0=9C=D0=B8=D1=80?="}};

		for (const auto &c: cases) {
			SUBCASE(c.first.c_str())
			{
				gboolean invalid_utf = FALSE;
				const char *input = c.first.c_str();
				char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
				std::string output(output_cstr);
				std::string expected_output = c.second;
				CHECK(output == expected_output);
				char *decoded_cstr = rspamd_mime_header_decode(pool, output_cstr, strlen(output_cstr), &invalid_utf);
				std::string decoded(decoded_cstr);
				CHECK(invalid_utf == FALSE);
				CHECK(decoded == input);
				g_free(output_cstr);
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("rspamd_mime_header_encode handles input with non-ASCII characters")
	{
		const char *input = "Hello Мир";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "Hello =?UTF-8?Q?=D0=9C=D0=B8=D1=80?=";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles mixed input with separators")
	{
		const char *input = "ололо (ололо test)    test";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "=?UTF-8?Q?=D0=BE=D0=BB=D0=BE=D0=BB=D0=BE?= "
									  "(=?UTF-8?Q?=D0=BE=D0=BB=D0=BE=D0=BB=D0=BE?= test)    test";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles multiple spaces and separators")
	{
		const char *input = "Привет    мир\nКак дела?";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "=?UTF-8?Q?=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82?=    "
									  "=?UTF-8?Q?=D0=BC=D0=B8=D1=80?=\n"
									  "=?UTF-8?Q?=D0=9A=D0=B0=D0=BA?= "
									  "=?UTF-8?Q?=D0=B4=D0=B5=D0=BB=D0=B0=3F?=";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles empty input")
	{
		const char *input = "";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr ? output_cstr : "");
		std::string expected_output = "";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles input with only separators")
	{
		const char *input = " \r\n()";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = " \r\n()";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles non-ASCII separators")
	{
		const char *input = "こんにちは(世界)";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "=?UTF-8?Q?=E3=81=93=E3=82=93=E3=81=AB=E3=81=A1=E3=81=AF?="
									  "(=?UTF-8?Q?=E4=B8=96=E7=95=8C?=)";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles input starting with separator")
	{
		const char *input = " (Hello)";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = " (Hello)";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles input ending with separator")
	{
		const char *input = "Hello) ";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "Hello) ";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("rspamd_mime_header_encode handles consecutive non-ASCII pieces")
	{
		const char *input = "你好世界";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "=?UTF-8?Q?=E4=BD=A0=E5=A5=BD=E4=B8=96=E7=95=8C?=";
		CHECK(output == expected_output);
		g_free(output_cstr);
	}
	TEST_CASE("rspamd_mime_header_encode handles long non-ASCII input requiring encoded-word splitting")
	{
		// Input string consisting of repeated non-ASCII characters
		const char *input = "これはとても長いテキストで、エンコードされたワードが76文字を超える必要があります。";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);
		std::string expected_output = "=?UTF-8?Q?=E3=81=93=E3=82=8C=E3=81=AF=E3=81=A8=E3=81=A6=E3=82=82=E9=95=B7?="
									  "=?UTF-8?Q?=E3=81=84=E3=83=86=E3=82=AD=E3=82=B9=E3=83=88=E3=81=A7=E3=80=81?="
									  "=?UTF-8?Q?=E3=82=A8=E3=83=B3=E3=82=B3=E3=83=BC=E3=83=89=E3=81=95=E3=82=8C?="
									  "=?UTF-8?Q?=E3=81=9F=E3=83=AF=E3=83=BC=E3=83=89=E3=81=8C76=E6=96=87=E5=AD?="
									  "=?UTF-8?Q?=97=E3=82=92=E8=B6=85=E3=81=88=E3=82=8B=E5=BF=85=E8=A6=81=E3=81?="
									  "=?UTF-8?Q?=8C=E3=81=82=E3=82=8A=E3=81=BE=E3=81=99=E3=80=82?=";

		CHECK(output == expected_output);
		g_free(output_cstr);
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

	TEST_CASE("rspamd_mime_header_encode handles long mixed input requiring encoded-word splitting")
	{
		// Input string with mix of ASCII and non-ASCII characters forming long pieces
		const char *input = "ASCII_Text "
							"これは非常に長い非ASCIIテキストで、エンコードが必要になります。";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);

		// Expected output: ASCII text as-is, non-ASCII text encoded and split accordingly
		std::string expected_output = "ASCII_Text "
									  "=?UTF-8?Q?=E3=81=93=E3=82=8C=E3=81=AF=E9=9D=9E=E5=B8=B8=E3=81=AB=E9=95=B7?="
									  "=?UTF-8?Q?=E3=81=84=E9=9D=9EASCII=E3=83=86=E3=82=AD=E3=82=B9=E3=83=88=E3?="
									  "=?UTF-8?Q?=81=A7=E3=80=81=E3=82=A8=E3=83=B3=E3=82=B3=E3=83=BC=E3=83=89=E3?="
									  "=?UTF-8?Q?=81=8C=E5=BF=85=E8=A6=81=E3=81=AB=E3=81=AA=E3=82=8A=E3=81=BE=E3?="
									  "=?UTF-8?Q?=81=99=E3=80=82?=";

		CHECK(output == expected_output);
		g_free(output_cstr);
	}

	TEST_CASE("process_string handles very long non-ASCII word requiring multiple splits")
	{
		const char *input =
			"非常に長い非ASCII文字列を使用してエンコードワードの分割をテストします。"
			"データが長すぎる場合、正しく分割されるべきです。";
		char *output_cstr = rspamd_mime_header_encode(input, strlen(input), false);
		std::string output(output_cstr);

		std::string expected_output =
			"=?UTF-8?Q?=E9=9D=9E=E5=B8=B8=E3=81=AB=E9=95=B7=E3=81=84=E9=9D=9EASCII=E6?="
			"=?UTF-8?Q?=96=87=E5=AD=97=E5=88=97=E3=82=92=E4=BD=BF=E7=94=A8=E3=81=97=E3?="
			"=?UTF-8?Q?=81=A6=E3=82=A8=E3=83=B3=E3=82=B3=E3=83=BC=E3=83=89=E3=83=AF=E3?="
			"=?UTF-8?Q?=83=BC=E3=83=89=E3=81=AE=E5=88=86=E5=89=B2=E3=82=92=E3=83=86=E3?="
			"=?UTF-8?Q?=82=B9=E3=83=88=E3=81=97=E3=81=BE=E3=81=99=E3=80=82=E3=83=87=E3?="
			"=?UTF-8?Q?=83=BC=E3=82=BF=E3=81=8C=E9=95=B7=E3=81=99=E3=81=8E=E3=82=8B=E5?="
			"=?UTF-8?Q?=A0=B4=E5=90=88=E3=80=81=E6=AD=A3=E3=81=97=E3=81=8F=E5=88=86=E5?="
			"=?UTF-8?Q?=89=B2=E3=81=95=E3=82=8C=E3=82=8B=E3=81=B9=E3=81=8D=E3=81=A7=E3?="
			"=?UTF-8?Q?=81=99=E3=80=82?=";// ≤76 chars

		CHECK(output == expected_output);
		g_free(output_cstr);
	}
}
#endif
