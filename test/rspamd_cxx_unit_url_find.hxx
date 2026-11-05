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

/* URL discovery in free text: the scanned buffer is length-delimited */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_URL_FIND_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_URL_FIND_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/url.h"
#include "libutil/mem_pool.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

struct url_find_hit {
	std::string url;
	gsize start;
	gsize end;
};

static gboolean
url_find_collect_cb(struct rspamd_url *u, gsize start, gsize end, gpointer ud)
{
	auto *hits = static_cast<std::vector<url_find_hit> *>(ud);

	hits->push_back({std::string{u->string, u->urllen}, start, end});

	return TRUE;
}

/* rspamd_url_find_single initialises the default scanner on its first use */
static void
url_find_ensure_scanner(rspamd_mempool_t *pool)
{
	std::vector<url_find_hit> hits;

	rspamd_url_find_single(pool, " ", 1, RSPAMD_URL_FIND_ALL,
						   url_find_collect_cb, &hits);
}

}// namespace

TEST_SUITE("url_find")
{
	TEST_CASE("file scheme at the end of a non NUL-terminated text")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "url_find", 0);
		url_find_ensure_scanner(pool);

		for (const std::string text: {"file://", "file:\\\\", "see file://", "file:///", "file:\\\\/"}) {
			CAPTURE(text);
			const auto len = text.size();
			/* An exact-size heap copy, as a text part buffer can be */
			auto buf = std::make_unique<char[]>(len);
			memcpy(buf.get(), text.data(), len);
			std::vector<url_find_hit> hits;

			rspamd_url_find_single(pool, buf.get(), len, RSPAMD_URL_FIND_ALL,
								   url_find_collect_cb, &hits);
			rspamd_url_find_multiple(pool, buf.get(), len, RSPAMD_URL_FIND_ALL,
									 nullptr, url_find_collect_cb, &hits, nullptr);

			for (const auto &h: hits) {
				CAPTURE(h.url);
				CHECK(h.start < h.end);
				CHECK(h.end <= len);
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("file scheme does not take the byte past the text end")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "url_find", 0);
		url_find_ensure_scanner(pool);

		for (const std::string text: {"file://", "file:\\\\", "see file://"}) {
			CAPTURE(text);
			const auto len = text.size();
			/* The bytes past the scanned length are a '/' and an opening brace */
			std::string storage{text};
			storage += "/(";
			char *url_str = nullptr;
			goffset url_pos = -1;

			if (rspamd_url_find(pool, storage.data(), len, &url_str,
								RSPAMD_URL_FIND_ALL, &url_pos, nullptr) &&
				url_str != nullptr) {
				const std::string found{url_str};
				CAPTURE(found);
				CHECK(url_pos >= 0);
				CHECK((gsize) url_pos + strlen(url_str) <= len);
			}
		}

		/* A file url that fits in the text is still found */
		const std::string text{"file:///etc/passwd"};
		char *url_str = nullptr;
		goffset url_pos = -1;

		REQUIRE(rspamd_url_find(pool, text.data(), text.size(), &url_str,
								RSPAMD_URL_FIND_ALL, &url_pos, nullptr));
		CHECK(url_pos == 0);
		CHECK(url_str != nullptr);

		rspamd_mempool_delete(pool);
	}
}

#endif
