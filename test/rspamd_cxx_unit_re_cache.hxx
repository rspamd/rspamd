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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_RE_CACHE_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_RE_CACHE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/re_cache.h"
#include "libutil/regexp.h"

/*
 * `regexp.max_size` bounds the amount of data any regexp in the cache is
 * matched against. Named scopes live in their own cache structures, so the
 * limit must be propagated to the scopes that already exist and inherited by
 * the ones registered later, otherwise scoped regexps would scan unbounded
 * input. The limit is only observable through the previous value returned by
 * the setters, which is what these tests assert on.
 */
TEST_SUITE("re cache limits")
{
	/* Registers a regexp in `scope`, creating the scope cache as a side effect */
	static void re_cache_add_scope(struct rspamd_re_cache * *head, const char *scope,
								   const char *pattern)
	{
		auto *re = rspamd_regexp_new(pattern, nullptr, nullptr);
		REQUIRE(re != nullptr);
		REQUIRE(rspamd_re_cache_add_scoped(head, scope, re, RSPAMD_RE_BODY,
										   nullptr, 0, -1) != nullptr);
		rspamd_regexp_unref(re);
	}

	TEST_CASE("scope created after the limit inherits it")
	{
		struct rspamd_re_cache *head = rspamd_re_cache_new();

		rspamd_re_cache_set_limit_all_scopes(head, 1024);
		re_cache_add_scope(&head, "late_scope", "/late/");

		/* Setting the limit anew reports the inherited one */
		CHECK(rspamd_re_cache_set_limit_scoped(head, "late_scope", 0) == 1024);

		rspamd_re_cache_unref_scoped(head);
	}

	TEST_CASE("scope created before the limit gets it too")
	{
		struct rspamd_re_cache *head = rspamd_re_cache_new();

		re_cache_add_scope(&head, "early_scope", "/early/");
		CHECK(rspamd_re_cache_set_limit_all_scopes(head, 2048) == 0);

		CHECK(rspamd_re_cache_set_limit_scoped(head, "early_scope", 0) == 2048);
		/* The default scope (the list head) is set as well */
		CHECK(rspamd_re_cache_set_limit(head, 0) == 2048);

		rspamd_re_cache_unref_scoped(head);
	}

	TEST_CASE("all scopes are covered")
	{
		struct rspamd_re_cache *head = rspamd_re_cache_new();

		re_cache_add_scope(&head, "scope1", "/one/");
		re_cache_add_scope(&head, "scope2", "/two/");
		re_cache_add_scope(&head, "scope3", "/three/");

		rspamd_re_cache_set_limit_all_scopes(head, 4096);

		CHECK(rspamd_re_cache_set_limit_scoped(head, "scope1", 0) == 4096);
		CHECK(rspamd_re_cache_set_limit_scoped(head, "scope2", 0) == 4096);
		CHECK(rspamd_re_cache_set_limit_scoped(head, "scope3", 0) == 4096);

		rspamd_re_cache_unref_scoped(head);
	}
}

#endif
