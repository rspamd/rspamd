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

#ifndef RSPAMD_CXX_UNIT_CONTENT_NEGOTIATION_HXX
#define RSPAMD_CXX_UNIT_CONTENT_NEGOTIATION_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http_content_negotiation.h"

#include <cstring>

namespace {
rspamd_ftok_t cn_tok(const char *s)
{
	rspamd_ftok_t t;
	t.begin = s;
	t.len = s ? strlen(s) : 0;
	return t;
}

/* Same preference order the /checkv3 reply uses */
const enum rspamd_http_content_type cn_v3_desired[] = {
	RSPAMD_HTTP_CTYPE_MULTIPART_FORM,
	RSPAMD_HTTP_CTYPE_MESSAGE_RFC822,
	RSPAMD_HTTP_CTYPE_JSON,
	RSPAMD_HTTP_CTYPE_MSGPACK,
	RSPAMD_HTTP_CTYPE_UNKNOWN,
};

enum rspamd_http_content_type cn_match(const char *accept)
{
	rspamd_ftok_t tok = cn_tok(accept);
	return rspamd_http_parse_accept_header(&tok, cn_v3_desired, nullptr);
}
}// namespace

TEST_SUITE("content_negotiation")
{
	TEST_CASE("explicit media types map to their representation")
	{
		CHECK(cn_match("application/json") == RSPAMD_HTTP_CTYPE_JSON);
		CHECK(cn_match("application/msgpack") == RSPAMD_HTTP_CTYPE_MSGPACK);
		CHECK(cn_match("message/rfc822") == RSPAMD_HTTP_CTYPE_MESSAGE_RFC822);
		CHECK(cn_match("multipart/form-data") == RSPAMD_HTTP_CTYPE_MULTIPART_FORM);
	}

	TEST_CASE("wildcards resolve to the first desired (multipart/form-data)")
	{
		CHECK(cn_match("*/*") == RSPAMD_HTTP_CTYPE_MULTIPART_FORM);
		CHECK(cn_match("multipart/*") == RSPAMD_HTTP_CTYPE_MULTIPART_FORM);
	}

	TEST_CASE("type wildcard picks the matching subtype family")
	{
		/* an application type-wildcard should match a desired application
		 * subtype (json comes first) */
		CHECK(cn_match("application/*") == RSPAMD_HTTP_CTYPE_JSON);
	}

	TEST_CASE("unsupported media type yields UNKNOWN (caller maps to 406)")
	{
		CHECK(cn_match("application/xml") == RSPAMD_HTTP_CTYPE_UNKNOWN);
		CHECK(cn_match("text/html") == RSPAMD_HTTP_CTYPE_UNKNOWN);
	}

	TEST_CASE("empty / null Accept yields UNKNOWN (caller uses default)")
	{
		rspamd_ftok_t empty = cn_tok("");
		CHECK(rspamd_http_parse_accept_header(&empty, cn_v3_desired, nullptr) ==
			  RSPAMD_HTTP_CTYPE_UNKNOWN);
		CHECK(rspamd_http_parse_accept_header(nullptr, cn_v3_desired, nullptr) ==
			  RSPAMD_HTTP_CTYPE_UNKNOWN);
	}

	TEST_CASE("q-values select the highest-quality acceptable type")
	{
		CHECK(cn_match("application/json;q=0.3, multipart/form-data;q=0.9") ==
			  RSPAMD_HTTP_CTYPE_MULTIPART_FORM);
		CHECK(cn_match("application/json;q=0.9, multipart/form-data;q=0.3") ==
			  RSPAMD_HTTP_CTYPE_JSON);
	}

	TEST_CASE("browser-style Accept falls back to the wildcard default")
	{
		CHECK(cn_match("text/html, application/xhtml+xml, */*;q=0.8") ==
			  RSPAMD_HTTP_CTYPE_MULTIPART_FORM);
	}

	TEST_CASE("Accept-Encoding zstd detection")
	{
		rspamd_ftok_t zstd = cn_tok("zstd");
		rspamd_ftok_t gzip = cn_tok("gzip");
		rspamd_ftok_t both = cn_tok("gzip, zstd");

		CHECK((rspamd_http_parse_accept_encoding(&zstd) & RSPAMD_HTTP_COMPRESS_ZSTD) != 0);
		CHECK((rspamd_http_parse_accept_encoding(&gzip) & RSPAMD_HTTP_COMPRESS_ZSTD) == 0);
		CHECK((rspamd_http_parse_accept_encoding(&both) & RSPAMD_HTTP_COMPRESS_ZSTD) != 0);
		CHECK(rspamd_http_parse_accept_encoding(nullptr) == RSPAMD_HTTP_COMPRESS_NONE);
	}
}

#endif// RSPAMD_CXX_UNIT_CONTENT_NEGOTIATION_HXX
