/*-
 * Copyright 2021 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "css.h"
#include "css.hxx"
#include "css_style.hxx"
#include "css_parser.hxx"
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"

rspamd_css
rspamd_css_parse_style (rspamd_mempool_t *pool, const guchar *begin, gsize len,
						GError **err)
{
	auto parse_res = rspamd::css::parse_css(pool, {(const char* )begin, len});

	if (parse_res.has_value()) {
		return reinterpret_cast<rspamd_css>(parse_res.value().release());
	}
	else {
		g_set_error(err, g_quark_from_static_string("css"),
				static_cast<int>(parse_res.error().type),
				"parse error");
		return nullptr;
	}
}

namespace rspamd::css {

INIT_LOG_MODULE_PUBLIC(css);

class css_style_sheet::impl {

};

css_style_sheet::css_style_sheet () : pimpl(new impl) {}
css_style_sheet::~css_style_sheet () {}

}