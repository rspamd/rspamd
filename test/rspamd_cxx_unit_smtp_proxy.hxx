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

#ifndef RSPAMD_CXX_UNIT_SMTP_PROXY_HXX
#define RSPAMD_CXX_UNIT_SMTP_PROXY_HXX

#pragma once

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/smtp_proxy/smtp_proxy.hxx"
#include "libserver/smtp_proxy/eod_scanner.hxx"

TEST_SUITE("smtp_proxy")
{

	TEST_CASE("ring_buffer: basic operations")
	{
		rspamd::io::ring_buffer<256> buf;

		CHECK(buf.empty());
		CHECK(buf.size() == 0);
		CHECK(buf.available_space() == 256);

		// Write some data
		std::string_view test_data = "Hello, World!";
		auto written = buf.write(test_data);
		CHECK(written == test_data.size());
		CHECK(buf.size() == test_data.size());
		CHECK(!buf.empty());

		// Peek at data
		char peek_buf[32];
		auto peeked = buf.peek(peek_buf, sizeof(peek_buf));
		CHECK(peeked == test_data.size());
		CHECK(std::string_view(peek_buf, peeked) == test_data);

		// Consume data
		buf.consume(5);// "Hello"
		CHECK(buf.size() == test_data.size() - 5);

		// Reset
		buf.reset();
		CHECK(buf.empty());
	}

	TEST_CASE("ring_buffer: wrap-around")
	{
		rspamd::io::ring_buffer<16> buf;

		// Fill near end
		std::string data1 = "AAAAAAAAAA";// 10 bytes
		buf.write(data1);
		buf.consume(8);// Consume 8, leaving 2 at position 8-9

		// Write more data that wraps
		std::string data2 = "BBBBBBBBBB";// 10 bytes
		auto written = buf.write(data2);
		CHECK(written == 10);// Should wrap and fill

		// Total should be 12 bytes (2 A's + 10 B's)
		CHECK(buf.size() == 12);

		// Peek should give correct data
		char peek_buf[16];
		auto peeked = buf.peek(peek_buf, sizeof(peek_buf));
		CHECK(peeked == 12);
		CHECK(std::string_view(peek_buf, 2) == "AA");
		CHECK(std::string_view(peek_buf + 2, 10) == "BBBBBBBBBB");
	}

	TEST_CASE("eod_scanner: basic EOD detection")
	{
		rspamd::smtp::eod_scanner scanner;

		// Standard EOD sequence
		const char *data = "Message body\r\n.\r\n";
		auto result = scanner.feed(data, strlen(data), 0);
		REQUIRE(result.has_value());
		CHECK(result->found);
		CHECK(result->eod_start == 12);// Position of first \r
		CHECK(result->eod_length == 5);// \r\n.\r\n
		CHECK(!result->had_violation);
	}

	TEST_CASE("eod_scanner: bare LF violation")
	{
		rspamd::smtp::eod_scanner scanner;

		// Bare LF EOD sequence
		const char *data = "Message body\n.\n";
		auto result = scanner.feed(data, strlen(data), 0);
		REQUIRE(result.has_value());
		CHECK(result->found);
		CHECK(result->had_violation);
	}

	TEST_CASE("eod_scanner: incremental feeding")
	{
		rspamd::smtp::eod_scanner scanner;

		// Feed data in chunks
		const char *chunk1 = "Message body\r";
		const char *chunk2 = "\n.\r";
		const char *chunk3 = "\n";

		auto result = scanner.feed(chunk1, strlen(chunk1), 0);
		CHECK(!result.has_value());

		result = scanner.feed(chunk2, strlen(chunk2), strlen(chunk1));
		CHECK(!result.has_value());

		result = scanner.feed(chunk3, strlen(chunk3), strlen(chunk1) + strlen(chunk2));
		REQUIRE(result.has_value());
		CHECK(result->found);
	}

	TEST_CASE("eod_scanner: no EOD")
	{
		rspamd::smtp::eod_scanner scanner;

		const char *data = "No end of data here";
		auto result = scanner.feed(data, strlen(data), 0);
		CHECK(!result.has_value());
	}

	TEST_CASE("crlf_scanner: CRLF detection")
	{
		rspamd::smtp::crlf_scanner scanner;

		const char *data = "EHLO example.com\r\n";
		auto result = scanner.scan(data, strlen(data), 0);
		REQUIRE(result.has_value());
		CHECK(result->found);
		CHECK(result->line_end == 16);
		CHECK(result->next_line == 18);
		CHECK(!result->bare_lf);
	}

	TEST_CASE("crlf_scanner: bare LF detection")
	{
		rspamd::smtp::crlf_scanner scanner;

		const char *data = "Line1\nLine2";
		auto result = scanner.scan(data, strlen(data), 0);
		REQUIRE(result.has_value());
		CHECK(result->found);
		CHECK(result->line_end == 5);
		CHECK(result->bare_lf);
	}

	TEST_CASE("crlf_scanner: incremental scan")
	{
		rspamd::smtp::crlf_scanner scanner;

		// CR at end of first chunk
		const char *chunk1 = "Hello\r";
		auto result = scanner.scan(chunk1, strlen(chunk1), 0);
		CHECK(!result.has_value());
		CHECK(scanner.has_pending_cr());

		// LF at start of next chunk
		const char *chunk2 = "\nWorld";
		result = scanner.scan(chunk2, strlen(chunk2), strlen(chunk1));
		REQUIRE(result.has_value());
		CHECK(result->found);
		CHECK(result->line_end == 5);
		CHECK(result->next_line == 7);
	}

	TEST_CASE("nul_scanner: NUL detection")
	{
		const char data[] = "Hello\0World";
		auto result = rspamd::smtp::nul_scanner::scan(data, sizeof(data) - 1, 0);
		REQUIRE(result.has_value());
		CHECK(result->found);
		CHECK(result->position == 5);
	}

	TEST_CASE("nul_scanner: no NUL")
	{
		const char *data = "Hello World";
		auto result = rspamd::smtp::nul_scanner::scan(data, strlen(data), 0);
		CHECK(!result.has_value());
	}

	TEST_CASE("line_reader: basic line reading")
	{
		rspamd::io::ring_buffer<256> buf;
		rspamd::smtp::line_reader reader;

		buf.write("EHLO example.com\r\n");

		auto result = reader.try_read_line(buf);
		CHECK(result.state == rspamd::smtp::line_result::status::ok);
		CHECK(result.line == "EHLO example.com");
		CHECK(result.raw_line == "EHLO example.com\r\n");
		CHECK(result.bytes_consumed == 18);
		CHECK(buf.empty());
	}

	TEST_CASE("line_reader: incomplete line")
	{
		rspamd::io::ring_buffer<256> buf;
		rspamd::smtp::line_reader reader;

		buf.write("EHLO example.com");// No CRLF

		auto result = reader.try_read_line(buf);
		CHECK(result.state == rspamd::smtp::line_result::status::incomplete);
	}

	TEST_CASE("line_reader: line too long")
	{
		rspamd::io::ring_buffer<256> buf;
		rspamd::smtp::line_reader reader(10);// Max 10 chars

		buf.write("This line is way too long\r\n");

		auto result = reader.try_read_line(buf);
		CHECK(result.state == rspamd::smtp::line_result::status::violation);
		CHECK(result.violation_type == rspamd::smtp::line_violation::line_too_long);
	}

	TEST_CASE("line_reader: bare LF violation")
	{
		rspamd::io::ring_buffer<256> buf;
		rspamd::smtp::line_reader reader;

		buf.write("Invalid\nline\r\n");

		auto result = reader.try_read_line(buf);
		CHECK(result.state == rspamd::smtp::line_result::status::violation);
		CHECK(result.violation_type == rspamd::smtp::line_violation::bare_lf);
	}

	TEST_CASE("command_parser: EHLO command")
	{
		rspamd::smtp::command_parser parser;

		auto cmd = parser.parse("EHLO mail.example.com");
		CHECK(cmd.type == rspamd::smtp::command_type::ehlo);
		CHECK(cmd.verb == "EHLO");
		CHECK(cmd.argument == "mail.example.com");
	}

	TEST_CASE("command_parser: MAIL FROM with params")
	{
		rspamd::smtp::command_parser parser;

		auto cmd = parser.parse("MAIL FROM:<user@example.com> SIZE=1024 BODY=8BITMIME");
		CHECK(cmd.type == rspamd::smtp::command_type::mail_from);
		CHECK(cmd.argument == "<user@example.com>");
		CHECK(cmd.params.size() == 2);
		CHECK(cmd.has_param("SIZE"));
		CHECK(cmd.has_param("BODY"));
		CHECK(cmd.get_param("SIZE").value() == "1024");
		CHECK(cmd.get_param("BODY").value() == "8BITMIME");
	}

	TEST_CASE("command_parser: RCPT TO")
	{
		rspamd::smtp::command_parser parser;

		auto cmd = parser.parse("RCPT TO:<recipient@example.com>");
		CHECK(cmd.type == rspamd::smtp::command_type::rcpt_to);
		CHECK(cmd.argument == "<recipient@example.com>");
	}

	TEST_CASE("command_parser: simple commands")
	{
		rspamd::smtp::command_parser parser;

		CHECK(parser.parse("DATA").type == rspamd::smtp::command_type::data);
		CHECK(parser.parse("RSET").type == rspamd::smtp::command_type::rset);
		CHECK(parser.parse("NOOP").type == rspamd::smtp::command_type::noop);
		CHECK(parser.parse("QUIT").type == rspamd::smtp::command_type::quit);
		CHECK(parser.parse("STARTTLS").type == rspamd::smtp::command_type::starttls);
	}

	TEST_CASE("command_parser: case insensitive")
	{
		rspamd::smtp::command_parser parser;

		CHECK(parser.parse("ehlo example.com").type == rspamd::smtp::command_type::ehlo);
		CHECK(parser.parse("Ehlo example.com").type == rspamd::smtp::command_type::ehlo);
		CHECK(parser.parse("mail from:<a@b.c>").type == rspamd::smtp::command_type::mail_from);
	}

	TEST_CASE("command_parser: pipelining classification")
	{
		using rspamd::smtp::command_parser;
		using rspamd::smtp::command_type;

		CHECK(command_parser::is_pipelineable(command_type::mail_from));
		CHECK(command_parser::is_pipelineable(command_type::rcpt_to));
		CHECK(command_parser::is_pipelineable(command_type::rset));
		CHECK(command_parser::is_pipelineable(command_type::noop));

		CHECK(!command_parser::is_pipelineable(command_type::ehlo));
		CHECK(!command_parser::is_pipelineable(command_type::data));
		CHECK(!command_parser::is_pipelineable(command_type::quit));

		CHECK(command_parser::is_sync_command(command_type::ehlo));
		CHECK(command_parser::is_sync_command(command_type::data));
		CHECK(command_parser::is_sync_command(command_type::starttls));
		CHECK(command_parser::is_sync_command(command_type::quit));
	}

	TEST_CASE("reply_parser: single line reply")
	{
		rspamd::smtp::reply_parser parser;

		auto line = parser.parse_line("250 OK");
		REQUIRE(line.has_value());
		CHECK(line->code == 250);
		CHECK(line->is_final);
		CHECK(line->text == "OK");
		CHECK(line->is_success());
	}

	TEST_CASE("reply_parser: multiline reply")
	{
		rspamd::smtp::reply_parser parser;
		rspamd::smtp::smtp_reply reply;

		// First line
		auto line1 = parser.parse_line("250-mail.example.com");
		REQUIRE(line1.has_value());
		CHECK(line1->code == 250);
		CHECK(!line1->is_final);
		parser.accumulate(reply, *line1);

		// Middle line
		auto line2 = parser.parse_line("250-PIPELINING");
		REQUIRE(line2.has_value());
		parser.accumulate(reply, *line2);

		// Final line
		auto line3 = parser.parse_line("250 SIZE 10240000");
		REQUIRE(line3.has_value());
		CHECK(line3->is_final);
		bool complete = parser.accumulate(reply, *line3);

		CHECK(complete);
		CHECK(reply.is_complete());
		CHECK(reply.code == 250);
		CHECK(reply.lines.size() == 3);
	}

	TEST_CASE("reply_parser: EHLO capability parsing")
	{
		rspamd::smtp::reply_parser parser;
		rspamd::smtp::smtp_reply reply;

		parser.accumulate(reply, *parser.parse_line("250-mail.example.com"));
		parser.accumulate(reply, *parser.parse_line("250-PIPELINING"));
		parser.accumulate(reply, *parser.parse_line("250-SIZE 10240000"));
		parser.accumulate(reply, *parser.parse_line("250-AUTH PLAIN LOGIN"));
		parser.accumulate(reply, *parser.parse_line("250-8BITMIME"));
		parser.accumulate(reply, *parser.parse_line("250 STARTTLS"));

		auto ehlo = parser.parse_ehlo_response(reply);

		CHECK(ehlo.greeting == "mail.example.com");
		CHECK(ehlo.has_capability("PIPELINING"));
		CHECK(ehlo.has_capability("SIZE"));
		CHECK(ehlo.has_capability("AUTH"));
		CHECK(ehlo.has_capability("8BITMIME"));
		CHECK(ehlo.has_capability("STARTTLS"));
		CHECK(!ehlo.has_capability("CHUNKING"));

		auto size_limit = ehlo.get_size_limit();
		REQUIRE(size_limit.has_value());
		CHECK(*size_limit == 10240000);
	}

	TEST_CASE("reply_parser: error codes")
	{
		rspamd::smtp::reply_parser parser;

		auto temp_fail = parser.parse_line("450 4.7.1 Temporary failure");
		REQUIRE(temp_fail.has_value());
		CHECK(temp_fail->is_temp_failure());
		CHECK(!temp_fail->is_perm_failure());

		auto perm_fail = parser.parse_line("550 5.7.1 Access denied");
		REQUIRE(perm_fail.has_value());
		CHECK(perm_fail->is_perm_failure());
		CHECK(!perm_fail->is_temp_failure());

		auto intermediate = parser.parse_line("354 Start mail input");
		REQUIRE(intermediate.has_value());
		CHECK(intermediate->is_intermediate());
	}

	TEST_CASE("pipelining_tracker: basic tracking")
	{
		rspamd::smtp::pipelining_tracker tracker(10);
		rspamd::smtp::command_parser parser;

		CHECK(!tracker.has_pending());
		CHECK(tracker.outstanding_count() == 0);

		auto cmd = parser.parse("MAIL FROM:<a@b.c>");
		tracker.command_sent(cmd);

		CHECK(tracker.has_pending());
		CHECK(tracker.outstanding_count() == 1);
	}

	TEST_CASE("pipelining_tracker: response handling")
	{
		rspamd::smtp::pipelining_tracker tracker;
		rspamd::smtp::command_parser parser;

		tracker.command_sent(parser.parse("MAIL FROM:<a@b.c>"));
		tracker.command_sent(parser.parse("RCPT TO:<x@y.z>"));

		CHECK(tracker.outstanding_count() == 2);

		auto resp1 = tracker.response_received(250, true);
		REQUIRE(resp1.has_value());
		CHECK(*resp1 == rspamd::smtp::command_type::mail_from);
		CHECK(tracker.outstanding_count() == 1);

		auto resp2 = tracker.response_received(250, true);
		REQUIRE(resp2.has_value());
		CHECK(*resp2 == rspamd::smtp::command_type::rcpt_to);
		CHECK(tracker.outstanding_count() == 0);
	}

	TEST_CASE("pipelining_tracker: too many outstanding")
	{
		rspamd::smtp::pipelining_tracker tracker(3);
		rspamd::smtp::command_parser parser;

		// Simulate EHLO with PIPELINING enabled
		tracker.command_sent(parser.parse("EHLO test.com"));
		tracker.response_received(250, true);
		tracker.enable_pipelining(true);

		// Add commands up to limit
		for (int i = 0; i < 3; ++i) {
			auto cmd = parser.parse("RCPT TO:<test@test.com>");
			auto violation = tracker.check_command(cmd);
			CHECK(violation == rspamd::smtp::pipelining_violation::none);
			tracker.command_sent(cmd);
		}

		// Next command should trigger violation
		auto cmd = parser.parse("RCPT TO:<test@test.com>");
		auto violation = tracker.check_command(cmd);
		CHECK(violation == rspamd::smtp::pipelining_violation::too_many_outstanding);
	}

	TEST_CASE("pipelining_tracker: DATA state transitions")
	{
		rspamd::smtp::pipelining_tracker tracker;
		rspamd::smtp::command_parser parser;

		tracker.command_sent(parser.parse("DATA"));
		CHECK(tracker.get_data_state() == rspamd::smtp::data_state::wait_354);

		// 354 response starts data transfer
		tracker.response_received(354, true);
		CHECK(tracker.get_data_state() == rspamd::smtp::data_state::receiving);
		CHECK(tracker.is_in_data());

		// End of data
		tracker.data_transfer_complete();
		CHECK(tracker.get_data_state() == rspamd::smtp::data_state::completed);

		// Final response
		tracker.data_response_received();
		CHECK(tracker.get_data_state() == rspamd::smtp::data_state::none);
	}

	TEST_CASE("unified violation types")
	{
		using namespace rspamd::smtp;

		// Line violations
		CHECK(to_violation_type(line_violation::bare_lf) == violation_type::bare_lf);
		CHECK(to_violation_type(line_violation::line_too_long) == violation_type::line_too_long);

		// Pipelining violations
		CHECK(to_violation_type(pipelining_violation::too_many_outstanding) ==
			  violation_type::too_many_outstanding);
		CHECK(to_violation_type(pipelining_violation::data_before_354) ==
			  violation_type::data_before_354);

		// String representation
		CHECK(std::string(violation_to_string(violation_type::bare_lf)) == "bare LF without CR");
	}

}// TEST_SUITE

#endif// RSPAMD_CXX_UNIT_SMTP_PROXY_HXX
