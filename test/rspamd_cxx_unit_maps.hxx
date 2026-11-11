/*
 * Copyright 2026 Alexander Moisseev
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

/* Unit tests for maps helpers */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_MAPS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_MAPS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include <vector>
#include <utility>
#include <string>
#include <cstring>

#include "rspamd.h"
#include "libcryptobox/cryptobox.h"
#include "libserver/cfg_file.h"
#include "libserver/maps/map_helpers.h"
#include "libserver/maps/map_private.h"
#include "contrib/libev/ev.h"

/* Declared non-static in src/libserver/maps/map.c for unit testing */
extern "C" char *rspamd_map_uri_redacted(const char *uri);

TEST_SUITE("rspamd_maps")
{

	TEST_CASE("rspamd_map_uri_redacted")
	{
		std::vector<std::pair<std::string, std::string>> cases{
			/* No scheme separator: returned verbatim */
			{"not-a-url", "not-a-url"},
			{"/etc/rspamd/list.map", "/etc/rspamd/list.map"},
			/* No userinfo: returned verbatim */
			{"http://example.com/path", "http://example.com/path"},
			{"http://example.com:8080/path", "http://example.com:8080/path"},
			{"http://[::1]:8080/path", "http://[::1]:8080/path"},
			{"http://[::1]/path", "http://[::1]/path"},
			/* Userinfo redacted */
			{"http://user:pass@example.com/path", "http://***@example.com/path"},
			{"http://user@example.com/path", "http://***@example.com/path"},
			{"http://@example.com/path", "http://***@example.com/path"},
			{"https://u:p@host:8443/p?q#f", "https://***@host:8443/p?q#f"},
			{"https://u:p@host", "https://***@host"},
			/* IPv6 host literal is preserved (it follows the userinfo) */
			{"http://user:pass@[::1]:8080/path", "http://***@[::1]:8080/path"},
			{"http://u:p@[2001:db8::1]/path", "http://***@[2001:db8::1]/path"},
			/* Malformed input with several '@': redact up to the last one */
			{"http://a@b:p@host/path", "http://***@host/path"},
			/* '@' outside of the authority (in path / query) must not be touched */
			{"http://host/path@x", "http://host/path@x"},
			{"http://host?u@p", "http://host?u@p"},
		};

		for (const auto &c: cases) {
			SUBCASE(("redact " + c.first).c_str())
			{
				auto *out = rspamd_map_uri_redacted(c.first.c_str());
				CHECK(std::string{out} == c.second);
				g_free(out);
			}
		}
	}

	TEST_CASE("regexp map skips an invalid regexp given twice")
	{
		struct rspamd_map map;
		memset(&map, 0, sizeof(map));
		map.name = (char *) "test";
		rspamd_strlcpy(map.tag, "test", sizeof(map.tag));

		auto *re_map = rspamd_map_helper_new_regexp(&map, (enum rspamd_regexp_map_flags) 0);

		/* The second line used to read the value the first one never stored, and crash */
		rspamd_map_helper_insert_re(re_map, "[invalid", "1");
		rspamd_map_helper_insert_re(re_map, "[invalid", "2");
		rspamd_map_helper_insert_re(re_map, "^valid$", "3");

		auto *found = (const char *) rspamd_match_regexp_map_single(re_map, "valid", 5);
		REQUIRE(found != nullptr);
		CHECK(std::string{found} == "3");
		CHECK(rspamd_match_regexp_map_single(re_map, "[invalid", 8) == nullptr);

		rspamd_map_helper_destroy_regexp(re_map);
	}

	TEST_CASE("regexp map leaves out an invalid regexp")
	{
		/* On x86, finalising the map reads the CPU flags from the config */
		struct rspamd_external_libs_ctx libs_ctx;
		memset(&libs_ctx, 0, sizeof(libs_ctx));
		libs_ctx.crypto_ctx = rspamd_cryptobox_init();
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		cfg->libs_ctx = &libs_ctx;

		struct rspamd_map map;
		memset(&map, 0, sizeof(map));
		map.name = (char *) "test";
		map.cfg = cfg;
		rspamd_strlcpy(map.tag, "test", sizeof(map.tag));

		struct map_cb_data cbd;
		memset(&cbd, 0, sizeof(cbd));
		cbd.map = &map;

		char data[] = "[invalid\n^valid$\n";
		rspamd_regexp_list_read_single(data, sizeof(data) - 1, &cbd, TRUE);
		void *re_map = nullptr;
		rspamd_regexp_list_fin(&cbd, &re_map);
		REQUIRE(re_map != nullptr);

		/*
		 * The key of the invalid regexp used to stay in the map with no value:
		 * it was counted, and walking the map (WebUI, map:foreach) crashed on it
		 */
		CHECK(map.nelts == 1);

		int nkeys = 0;
		auto count_key = [](gconstpointer, gconstpointer, gsize, gpointer ud) -> gboolean {
			(*(int *) ud)++;
			return TRUE;
		};
		map.traverse_function(re_map, count_key, &nkeys, FALSE);
		CHECK(nkeys == 1);

		rspamd_map_helper_destroy_regexp((struct rspamd_regexp_map_helper *) re_map);
		cfg->libs_ctx = nullptr;
		rspamd_config_free(cfg);
	}

	TEST_CASE("map HTTP failures are classified")
	{
		for (int code: {301, 302, 400, 401, 403, 404, 410, 451}) {
			CAPTURE(code);
			CHECK(rspamd_map_http_error_class(code, false) == RSPAMD_MAP_ERROR_PERMANENT);
			CHECK(rspamd_map_http_error_class(code, true) == RSPAMD_MAP_ERROR_PERMANENT);
		}

		for (int code: {408, 500, 502, 503, 504}) {
			CAPTURE(code);
			CHECK(rspamd_map_http_error_class(code, false) == RSPAMD_MAP_ERROR_TRANSIENT);
		}

		/* Rate limiting with no time given backs off as hard as a refusal */
		CHECK(rspamd_map_http_error_class(429, false) == RSPAMD_MAP_ERROR_PERMANENT);
		CHECK(rspamd_map_http_error_class(429, true) == RSPAMD_MAP_ERROR_TRANSIENT);
	}

	TEST_CASE("map retry delay after a failure")
	{
		const double poll = 300.0;
		const auto delays = [&](enum rspamd_map_error_class cls, bool has_data) {
			std::vector<double> out;

			for (unsigned int streak = 1; streak <= 7; streak++) {
				out.push_back(rspamd_map_error_delay(poll, cls, streak, has_data, false, 0));
			}

			return out;
		};

		SUBCASE("transient failure of a map with no data never waits past the poll interval")
		{
			CHECK(delays(RSPAMD_MAP_ERROR_TRANSIENT, false) ==
				  std::vector<double>{10, 20, 40, 80, 160, 300, 300});
			CHECK(rspamd_map_error_delay(poll, RSPAMD_MAP_ERROR_TRANSIENT, 1000000, false, false, 0) == poll);
		}

		SUBCASE("transient failure of a map with data backs off up to 20 poll intervals")
		{
			CHECK(delays(RSPAMD_MAP_ERROR_TRANSIENT, true) ==
				  std::vector<double>{300, 600, 1200, 2400, 4800, 6000, 6000});
			CHECK(rspamd_map_error_delay(poll, RSPAMD_MAP_ERROR_TRANSIENT, 1000000, true, false, 0) == 6000);
		}

		SUBCASE("permanent failure of a map with no data is tried once more at the poll interval")
		{
			CHECK(delays(RSPAMD_MAP_ERROR_PERMANENT, false) ==
				  std::vector<double>{300, 6000, 6000, 6000, 6000, 6000, 6000});
		}

		SUBCASE("permanent failure of a map with data backs off at once")
		{
			CHECK(delays(RSPAMD_MAP_ERROR_PERMANENT, true) ==
				  std::vector<double>{6000, 6000, 6000, 6000, 6000, 6000, 6000});
		}

		SUBCASE("Retry-After is honoured within limits")
		{
			for (auto cls: {RSPAMD_MAP_ERROR_TRANSIENT, RSPAMD_MAP_ERROR_PERMANENT}) {
				for (bool has_data: {false, true}) {
					CHECK(rspamd_map_error_delay(poll, cls, 1, has_data, true, 120) == 120);
					CHECK(rspamd_map_error_delay(poll, cls, 5, has_data, true, 120) == 120);
					CHECK(rspamd_map_error_delay(poll, cls, 1, has_data, true, 100000) == 6000);
					CHECK(rspamd_map_error_delay(poll, cls, 1, has_data, true, 0.5) == 2);
					/* Zero is a valid request to retry at once, not a missing header */
					CHECK(rspamd_map_error_delay(poll, cls, 1, has_data, true, 0) == 2);
				}
			}

			/* Without the header, a zero value means nothing */
			CHECK(rspamd_map_error_delay(poll, RSPAMD_MAP_ERROR_TRANSIENT, 1, false, false, 0) == 10);
			CHECK(rspamd_map_error_delay(poll, RSPAMD_MAP_ERROR_PERMANENT, 1, false, false, 0) == poll);
		}

		SUBCASE("poll interval shorter than the first transient retry")
		{
			CHECK(rspamd_map_error_delay(5, RSPAMD_MAP_ERROR_TRANSIENT, 1, false, false, 0) == 5);
			CHECK(rspamd_map_error_delay(5, RSPAMD_MAP_ERROR_TRANSIENT, 4, false, false, 0) == 5);
			CHECK(rspamd_map_error_delay(5, RSPAMD_MAP_ERROR_TRANSIENT, 4, true, false, 0) == 40);
		}
	}

	TEST_CASE("map Retry-After header parsing")
	{
		/* Thu, 01 Jan 2026 00:00:00 GMT */
		const time_t now = 1767225600;
		const auto parse = [&](const char *value, double &delay) -> bool {
			rspamd_ftok_t tok;
			tok.begin = value;
			tok.len = strlen(value);

			return rspamd_map_parse_retry_after(&tok, now, &delay);
		};
		double delay = -1;

		CHECK(parse("30", delay));
		CHECK(delay == 30);
		CHECK(parse("0", delay));
		CHECK(delay == 0);
		CHECK(parse("Thu, 01 Jan 2026 00:02:00 GMT", delay));
		CHECK(delay == 120);
		/* A date that has passed asks to retry at once */
		CHECK(parse("Wed, 31 Dec 2025 23:59:00 GMT", delay));
		CHECK(delay == 0);

		CHECK_FALSE(parse("", delay));
		CHECK_FALSE(parse("soon", delay));
		CHECK_FALSE(parse("-5", delay));
		CHECK_FALSE(rspamd_map_parse_retry_after(nullptr, now, &delay));
	}

	TEST_CASE("map retry after a failure is not moved by the data expiry")
	{
		struct rspamd_map map;
		memset(&map, 0, sizeof(map));
		map.name = (char *) "test";
		rspamd_strlcpy(map.tag, "test", sizeof(map.tag));
		void *data = nullptr;
		map.user_data = &data;
		map.event_loop = ev_loop_new(EVFLAG_AUTO);
		map.poll_timeout = 60;
		map.non_trivial = true;
		map.active_http = true;
		map.error_class = RSPAMD_MAP_ERROR_TRANSIENT;
		map.error_streak = 1;

		/* Arms the timer the way a failed update does, returns its delay */
		const auto retry_delay = [&]() {
			rspamd_map_schedule_periodic(&map, RSPAMD_MAP_SCHEDULE_ERROR);
			REQUIRE(map.scheduled_check != nullptr);
			auto delay = ev_timer_remaining(map.event_loop, &map.scheduled_check->ev);
			ev_timer_stop(map.event_loop, &map.scheduled_check->ev);
			g_free(map.scheduled_check);
			map.scheduled_check = nullptr;

			return delay;
		};
		const auto now = (time_t) rspamd_get_calendar_ticks();

		SUBCASE("Retry-After of one backend wins over a far expiry from another")
		{
			map.next_check = now + 3600;
			map.error_has_retry_after = true;
			map.error_retry_after = 30;
			auto delay = retry_delay();
			CHECK(delay >= 30);
			CHECK(delay <= 60);
			CHECK(map.next_check == 0);
		}

		SUBCASE("Retry-After wins over a near expiry")
		{
			map.next_check = now + 5;
			map.error_has_retry_after = true;
			map.error_retry_after = 30;
			auto delay = retry_delay();
			CHECK(delay >= 30);
			CHECK(delay <= 60);
		}

		SUBCASE("Retry-After: 0 retries at the minimum interval")
		{
			map.next_check = now + 3600;
			map.error_has_retry_after = true;
			map.error_retry_after = 0;
			auto delay = retry_delay();
			CHECK(delay >= 2);
			CHECK(delay <= 4);
		}

		SUBCASE("backoff without Retry-After ignores the expiry too")
		{
			map.next_check = now + 3600;
			auto delay = retry_delay();
			/* First transient failure of a map with no data: 10s, jittered */
			CHECK(delay >= 10);
			CHECK(delay <= 20);
		}

		ev_loop_destroy(map.event_loop);
	}
}

#endif
