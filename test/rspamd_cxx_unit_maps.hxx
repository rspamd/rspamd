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
}

#endif
