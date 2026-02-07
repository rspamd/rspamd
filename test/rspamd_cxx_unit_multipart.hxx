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

#ifndef RSPAMD_CXX_UNIT_MULTIPART_HXX
#define RSPAMD_CXX_UNIT_MULTIPART_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/multipart_form.hxx"
#include "libserver/multipart_response.hxx"

#include <string>
#include <string_view>

TEST_SUITE("multipart_form")
{
	TEST_CASE("basic two-part form")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"metadata\"\r\n"
			"Content-Type: application/json\r\n"
			"\r\n"
			"{\"from\":\"test@example.com\"}\r\n"
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"message\"\r\n"
			"\r\n"
			"Subject: test\r\n\r\nHello world\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 2);
		CHECK(result->parts[0].name == "metadata");
		CHECK(result->parts[0].data == "{\"from\":\"test@example.com\"}");
		CHECK(result->parts[1].name == "message");
		CHECK(result->parts[1].data == "Subject: test\r\n\r\nHello world");
	}

	TEST_CASE("LF-only line endings")
	{
		std::string body =
			"--boundary\n"
			"Content-Disposition: form-data; name=\"metadata\"\n"
			"\n"
			"meta-data-here\n"
			"--boundary\n"
			"Content-Disposition: form-data; name=\"message\"\n"
			"\n"
			"message-data-here\n"
			"--boundary--\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 2);
		CHECK(result->parts[0].name == "metadata");
		CHECK(result->parts[0].data == "meta-data-here");
		CHECK(result->parts[1].name == "message");
		CHECK(result->parts[1].data == "message-data-here");
	}

	TEST_CASE("single part")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"metadata\"\r\n"
			"\r\n"
			"{\"file\":\"/tmp/test.eml\"}\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 1);
		CHECK(result->parts[0].name == "metadata");
	}

	TEST_CASE("find_part by name")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"metadata\"\r\n"
			"\r\n"
			"meta\r\n"
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"message\"\r\n"
			"\r\n"
			"msg\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());

		auto *meta = rspamd::http::find_part(*result, "metadata");
		REQUIRE(meta != nullptr);
		CHECK(meta->data == "meta");

		auto *msg = rspamd::http::find_part(*result, "message");
		REQUIRE(msg != nullptr);
		CHECK(msg->data == "msg");

		auto *none = rspamd::http::find_part(*result, "nonexistent");
		CHECK(none == nullptr);
	}

	TEST_CASE("content-type and encoding headers")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"metadata\"\r\n"
			"Content-Type: application/json\r\n"
			"Content-Encoding: zstd\r\n"
			"\r\n"
			"data\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts[0].content_type == "application/json");
		CHECK(result->parts[0].content_encoding == "zstd");
	}

	TEST_CASE("filename in content-disposition")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"file\"; filename=\"test.eml\"\r\n"
			"\r\n"
			"file-data\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts[0].name == "file");
		CHECK(result->parts[0].filename == "test.eml");
	}

	TEST_CASE("empty part data")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"empty\"\r\n"
			"\r\n"
			"\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts[0].name == "empty");
		CHECK(result->parts[0].data.empty());
	}

	TEST_CASE("empty boundary")
	{
		auto result = rspamd::http::parse_multipart_form("some data", "");
		CHECK(!result.has_value());
	}

	TEST_CASE("empty data")
	{
		auto result = rspamd::http::parse_multipart_form("", "boundary");
		CHECK(!result.has_value());
	}

	TEST_CASE("missing closing boundary")
	{
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"part1\"\r\n"
			"\r\n"
			"data1\r\n"
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"part2\"\r\n"
			"\r\n"
			"data2";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		/* Parser should return the first part it found before the second boundary */
		CHECK(result->parts.size() >= 1);
		CHECK(result->parts[0].name == "part1");
		CHECK(result->parts[0].data == "data1");
	}

	TEST_CASE("max parts limit")
	{
		std::string body;
		for (int i = 0; i < 10; i++) {
			body += "--boundary\r\n";
			body += "Content-Disposition: form-data; name=\"part" + std::to_string(i) + "\"\r\n";
			body += "\r\n";
			body += "data" + std::to_string(i) + "\r\n";
		}
		body += "--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 8);
	}

	TEST_CASE("garbage data")
	{
		std::string garbage = "this is just random garbage with no boundary markers at all";
		auto result = rspamd::http::parse_multipart_form(garbage, "boundary");
		CHECK(!result.has_value());
	}

	TEST_CASE("boundary embedded in content")
	{
		/* The boundary string appears in the part body but not preceded by \r\n-- */
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"test\"\r\n"
			"\r\n"
			"This text mentions boundary as a word\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 1);
		CHECK(result->parts[0].data == "This text mentions boundary as a word");
	}

	TEST_CASE("message with own MIME boundaries")
	{
		/* The message part contains a multipart/alternative email with its own
		 * MIME boundaries. The outer form-data boundary must not be confused
		 * by the inner MIME boundary markers. */
		std::string mime_message =
			"From: test@example.com\r\n"
			"To: rcpt@example.com\r\n"
			"Subject: multipart test\r\n"
			"MIME-Version: 1.0\r\n"
			"Content-Type: multipart/alternative; boundary=\"inner-mime-boundary\"\r\n"
			"\r\n"
			"--inner-mime-boundary\r\n"
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n"
			"\r\n"
			"Plain text part\r\n"
			"\r\n"
			"--inner-mime-boundary\r\n"
			"Content-Type: text/html; charset=\"UTF-8\"\r\n"
			"\r\n"
			"<html><body>HTML part</body></html>\r\n"
			"\r\n"
			"--inner-mime-boundary--\r\n";

		std::string body =
			"--outer-form-boundary\r\n"
			"Content-Disposition: form-data; name=\"metadata\"\r\n"
			"Content-Type: application/json\r\n"
			"\r\n"
			"{\"from\":\"test@example.com\"}\r\n"
			"--outer-form-boundary\r\n"
			"Content-Disposition: form-data; name=\"message\"\r\n"
			"\r\n" +
			mime_message +
			"\r\n"
			"--outer-form-boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "outer-form-boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 2);

		auto *meta = rspamd::http::find_part(*result, "metadata");
		REQUIRE(meta != nullptr);
		CHECK(meta->data == "{\"from\":\"test@example.com\"}");

		auto *msg = rspamd::http::find_part(*result, "message");
		REQUIRE(msg != nullptr);
		/* The entire MIME message must be preserved intact */
		CHECK(msg->data == mime_message);
		/* Verify inner MIME boundaries are present in the data */
		CHECK(msg->data.find("--inner-mime-boundary") != std::string_view::npos);
		CHECK(msg->data.find("--inner-mime-boundary--") != std::string_view::npos);
		CHECK(msg->data.find("Plain text part") != std::string_view::npos);
		CHECK(msg->data.find("<html><body>HTML part</body></html>") != std::string_view::npos);
	}

	TEST_CASE("message with nested multipart/mixed MIME")
	{
		/* A more complex case: multipart/mixed with attachments.
		 * The inner boundaries contain -- prefixes and look similar
		 * to form-data boundaries but must not interfere. */
		std::string mime_message =
			"From: sender@test.com\r\n"
			"Content-Type: multipart/mixed; boundary=\"----=_Part_123\"\r\n"
			"\r\n"
			"------=_Part_123\r\n"
			"Content-Type: text/plain\r\n"
			"\r\n"
			"Body text\r\n"
			"\r\n"
			"------=_Part_123\r\n"
			"Content-Type: application/pdf; name=\"doc.pdf\"\r\n"
			"\r\n"
			"fake-pdf-content\r\n"
			"\r\n"
			"------=_Part_123--\r\n";

		std::string body =
			"--formbnd\r\n"
			"Content-Disposition: form-data; name=\"metadata\"\r\n"
			"\r\n"
			"{}\r\n"
			"--formbnd\r\n"
			"Content-Disposition: form-data; name=\"message\"\r\n"
			"\r\n" +
			mime_message +
			"\r\n"
			"--formbnd--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "formbnd");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 2);

		auto *msg = rspamd::http::find_part(*result, "message");
		REQUIRE(msg != nullptr);
		/* Message data must contain the full MIME structure */
		CHECK(msg->data == mime_message);
		CHECK(msg->data.find("------=_Part_123") != std::string_view::npos);
		CHECK(msg->data.find("fake-pdf-content") != std::string_view::npos);
	}

	TEST_CASE("no headers in part")
	{
		/* Part has no Content-Disposition header, just raw data after boundary.
		 * Without a proper header block (\r\n\r\n separator), the parser treats
		 * the entire part content as data (including the leading \r\n). */
		std::string body =
			"--boundary\r\n"
			"\r\n"
			"raw data without headers\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 1);
		CHECK(result->parts[0].name.empty());
		/* Data includes the leading \r\n since no header separator was found */
		CHECK(result->parts[0].data == "\r\nraw data without headers");
	}

	TEST_CASE("mixed CRLF and LF")
	{
		/* When the body between parts uses LF-only to separate from the
		 * next boundary, the parser should find both parts via lf_delim fallback. */
		std::string body =
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"part1\"\r\n"
			"\r\n"
			"data1\n"
			"--boundary\r\n"
			"Content-Disposition: form-data; name=\"part2\"\r\n"
			"\r\n"
			"data2\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts.size() == 2);
		CHECK(result->parts[0].name == "part1");
		CHECK(result->parts[0].data == "data1");
		CHECK(result->parts[1].name == "part2");
		CHECK(result->parts[1].data == "data2");
	}

	TEST_CASE("case-insensitive header names")
	{
		std::string body =
			"--boundary\r\n"
			"content-disposition: form-data; name=\"lower\"\r\n"
			"content-type: text/plain\r\n"
			"content-encoding: gzip\r\n"
			"\r\n"
			"test\r\n"
			"--boundary--\r\n";

		auto result = rspamd::http::parse_multipart_form(body, "boundary");
		REQUIRE(result.has_value());
		CHECK(result->parts[0].name == "lower");
		CHECK(result->parts[0].content_type == "text/plain");
		CHECK(result->parts[0].content_encoding == "gzip");
	}
}

TEST_SUITE("multipart_response")
{
	TEST_CASE("single part serialization")
	{
		rspamd::http::multipart_response resp;
		std::string data = "{\"action\":\"reject\"}";
		resp.add_part("result", "application/json", data);

		auto serialized = resp.serialize();
		auto boundary = std::string(resp.get_boundary());

		CHECK(serialized.find("--" + boundary) != std::string::npos);
		CHECK(serialized.find("Content-Disposition: form-data; name=\"result\"") != std::string::npos);
		CHECK(serialized.find("Content-Type: application/json") != std::string::npos);
		CHECK(serialized.find(data) != std::string::npos);
		CHECK(serialized.find("--" + boundary + "--") != std::string::npos);
	}

	TEST_CASE("two parts serialization")
	{
		rspamd::http::multipart_response resp;
		std::string result_data = "{\"action\":\"reject\"}";
		std::string body_data = "rewritten body";
		resp.add_part("result", "application/json", result_data);
		resp.add_part("body", "message/rfc822", body_data);

		auto serialized = resp.serialize();

		/* Both parts present */
		CHECK(serialized.find("name=\"result\"") != std::string::npos);
		CHECK(serialized.find("name=\"body\"") != std::string::npos);
		CHECK(serialized.find(result_data) != std::string::npos);
		CHECK(serialized.find(body_data) != std::string::npos);

		/* result appears before body */
		CHECK(serialized.find("name=\"result\"") < serialized.find("name=\"body\""));
	}

	TEST_CASE("content_type includes boundary")
	{
		rspamd::http::multipart_response resp;
		auto ct = resp.content_type();

		CHECK(ct.find("multipart/mixed") != std::string::npos);
		CHECK(ct.find("boundary=\"") != std::string::npos);
		CHECK(ct.find(std::string(resp.get_boundary())) != std::string::npos);
	}

	TEST_CASE("unique boundaries")
	{
		rspamd::http::multipart_response resp1;
		rspamd::http::multipart_response resp2;
		CHECK(resp1.get_boundary() != resp2.get_boundary());
	}

	TEST_CASE("empty data part")
	{
		rspamd::http::multipart_response resp;
		std::string empty;
		resp.add_part("empty", "application/octet-stream", empty);

		auto serialized = resp.serialize();
		CHECK(serialized.find("name=\"empty\"") != std::string::npos);
		CHECK(serialized.find("Content-Type: application/octet-stream") != std::string::npos);
	}
}

TEST_SUITE("multipart_roundtrip")
{
	TEST_CASE("build then parse")
	{
		rspamd::http::multipart_response resp;
		std::string result_data = "{\"action\":\"reject\",\"score\":15.0}";
		std::string body_data = "Subject: test\r\n\r\nRewritten body content";
		resp.add_part("result", "application/json", result_data);
		resp.add_part("body", "message/rfc822", body_data);

		auto serialized = resp.serialize();
		auto boundary = std::string(resp.get_boundary());

		auto parsed = rspamd::http::parse_multipart_form(serialized, boundary);
		REQUIRE(parsed.has_value());
		CHECK(parsed->parts.size() == 2);

		auto *result_part = rspamd::http::find_part(*parsed, "result");
		REQUIRE(result_part != nullptr);
		CHECK(result_part->data == result_data);
		CHECK(result_part->content_type == "application/json");

		auto *body_part = rspamd::http::find_part(*parsed, "body");
		REQUIRE(body_part != nullptr);
		CHECK(body_part->data == body_data);
	}

	TEST_CASE("build then parse single part")
	{
		rspamd::http::multipart_response resp;
		std::string data = "{\"action\":\"no action\"}";
		resp.add_part("result", "application/json", data);

		auto serialized = resp.serialize();
		auto boundary = std::string(resp.get_boundary());

		auto parsed = rspamd::http::parse_multipart_form(serialized, boundary);
		REQUIRE(parsed.has_value());
		CHECK(parsed->parts.size() == 1);

		auto *result_part = rspamd::http::find_part(*parsed, "result");
		REQUIRE(result_part != nullptr);
		CHECK(result_part->data == data);
	}
}

#endif// RSPAMD_CXX_UNIT_MULTIPART_HXX
