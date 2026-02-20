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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_HTML_CTA_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_HTML_CTA_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/mem_pool.h"
#include "libserver/html/html.hxx"
#include "libserver/html/html.h"
#include "libserver/url.h"

#include <string>
#include <string_view>

using namespace rspamd::html;

namespace {

struct html_fixture {
	rspamd_mempool_t *pool = nullptr;
	html_content *hc = nullptr;

	explicit html_fixture(std::string_view html)
	{
		pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), nullptr, 0);
		auto *input = g_byte_array_sized_new(html.size());
		g_byte_array_append(input, reinterpret_cast<const guint8 *>(html.data()), html.size());
		auto *parsed = rspamd_html_process_part(pool, input);
		g_byte_array_free(input, TRUE);
		hc = html_content::from_ptr(parsed);
	}

	~html_fixture()
	{
		if (pool != nullptr) {
			rspamd_mempool_delete(pool);
		}
	}

	[[nodiscard]] auto weight_for(std::string_view url) const -> float
	{
		for (const auto &[u, weight]: hc->url_button_weights) {
			if (!u || !u->string) {
				continue;
			}
			std::string_view current(u->string, u->urllen);
			if (current == url) {
				return weight;
			}
		}
		return 0.0f;
	}
};

}// namespace

TEST_SUITE("html_cta_scoring")
{
	TEST_CASE("button-like anchors outrank technical resources")
	{
		const auto html = R"HTML(
		<html><body>
		<a href="https://example.com/cta" class="btn primary">Click now</a>
		<link rel="stylesheet" href="https://cdn.example.com/style.css" />
		<a href="mailto:info@example.com">Email us</a>
		</body></html>
	)HTML";
		html_fixture fx{html};

		CHECK(fx.weight_for("https://example.com/cta") > 0.6f);
		CHECK(fx.weight_for("https://cdn.example.com/style.css") == doctest::Approx(0.0f));
		CHECK(fx.weight_for("mailto:info@example.com") < 0.3f);
	}

	TEST_CASE("footer links and hidden buttons are de-emphasised")
	{
		const auto html = R"HTML(
		<html><body>
		<a href="https://shop.example.com/buy" class="cta-button">BUY NOW!</a>
		<div class="footer">
			<a href="https://shop.example.com/privacy" class="footer-link">Privacy policy</a>
		</div>
		<div style="display:none">
			<a href="https://shop.example.com/hidden" class="btn">Hidden CTA</a>
		</div>
		</body></html>
	)HTML";
		html_fixture fx{html};

		CHECK(fx.weight_for("https://shop.example.com/buy") > 0.6f);
		CHECK(fx.weight_for("https://shop.example.com/privacy") < 0.2f);
		CHECK(fx.weight_for("https://shop.example.com/hidden") == doctest::Approx(0.0f));
	}
}

#endif
