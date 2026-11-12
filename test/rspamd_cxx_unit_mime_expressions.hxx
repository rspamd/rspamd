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

#ifndef RSPAMD_CXX_UNIT_MIME_EXPRESSIONS_HXX
#define RSPAMD_CXX_UNIT_MIME_EXPRESSIONS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libmime/mime_expressions.h"

#include <cstring>

/*
 * Atoms used here are rejected (or kept as plain strings) before the parser
 * touches the config, so no rspamd_config is needed.
 */
TEST_SUITE("mime expressions")
{
	TEST_CASE("regexp atom without a usable type is rejected")
	{
		/*
		 * Each atom gets past the flags parsing and is then rejected:
		 * no type, header type without a header name, selector type without
		 * a selector. The flags buffer must be released on these paths
		 * (LSan reports it otherwise).
		 */
		static const char *const atoms[] = {
			"/foo/",
			"/foo/i",
			"/foo/H",
			"/foo/X",
			"/foo/B",
			"/foo/{header}",
			"/foo/$",
			"/foo/{selector}",
		};
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"mime-expr-test", 0);
		struct rspamd_mime_expr_ud ud = {nullptr, nullptr};

		for (const auto *atom: atoms) {
			CAPTURE(atom);
			GError *err = nullptr;

			auto *res = mime_expr_subr.parse(atom, strlen(atom), pool, &ud, &err);
			CHECK(res == nullptr);
			REQUIRE(err != nullptr);
			CHECK(err->code == 200);
			g_error_free(err);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("several invalid slashed function arguments fall back to strings")
	{
		/*
		 * Every argument fails to compile as a regexp; the error of the first
		 * one must not be reused for the next ones (use after free).
		 */
		static const char *const exprs[] = {
			"header_exists(/[/, /[/)",
			"header_exists(/[/, /?/, /[a/)",
		};
		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
													"mime-expr-test", 0);
		struct rspamd_mime_expr_ud ud = {nullptr, nullptr};

		for (const auto *expr: exprs) {
			CAPTURE(expr);
			GError *err = nullptr;

			/* No target: the expression and its atoms are destroyed at once */
			CHECK(rspamd_parse_expression(expr, 0, &mime_expr_subr, &ud, pool,
										  &err, nullptr));
			CHECK(err == nullptr);

			if (err) {
				g_error_free(err);
			}
		}

		rspamd_mempool_delete(pool);
	}
}

#endif
