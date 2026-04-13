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

#ifndef RSPAMD_CXX_UNIT_SETTINGS_MERGE_HXX
#define RSPAMD_CXX_UNIT_SETTINGS_MERGE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/settings_merge.h"
#include "libserver/cfg_file.h"
#include "mem_pool.h"
#include <ucl.h>
#include <string>

/* Helper to parse UCL from string */
static ucl_object_t *
ucl_parse_string(const char *str)
{
	auto *parser = ucl_parser_new(0);
	ucl_parser_add_string(parser, str, strlen(str));
	auto *obj = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
	return obj;
}

/* Helper to check if a UCL array contains a string */
static bool
ucl_array_has_string(const ucl_object_t *arr, const char *str)
{
	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur;

	while ((cur = ucl_object_iterate(arr, &it, true)) != nullptr) {
		if (ucl_object_type(cur) == UCL_STRING &&
			strcmp(ucl_object_tostring(cur), str) == 0) {
			return true;
		}
	}
	return false;
}

TEST_SUITE("settings_merge")
{

	TEST_CASE("single layer passthrough")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);
		auto *layer = ucl_parse_string(R"({"actions":{"reject":15.0},"symbols_enabled":["FOO"]})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "test", 0, layer);
		ucl_object_unref(layer);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		/* Single layer: returned as-is (ref'd) */
		auto *actions = ucl_object_lookup(result, "actions");
		REQUIRE(actions != nullptr);
		auto *reject = ucl_object_lookup(actions, "reject");
		CHECK(ucl_object_todouble(reject) == doctest::Approx(15.0));

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("actions override by higher layer")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *low = ucl_parse_string(R"({"actions":{"reject":15.0,"greylist":4.0}})");
		auto *high = ucl_parse_string(R"({"actions":{"reject":20.0}})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, low);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_HTTP, "http", 0, high);
		ucl_object_unref(low);
		ucl_object_unref(high);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *actions = ucl_object_lookup(result, "actions");
		REQUIRE(actions != nullptr);

		SUBCASE("higher layer reject wins")
		{
			auto *reject = ucl_object_lookup(actions, "reject");
			REQUIRE(reject != nullptr);
			CHECK(ucl_object_todouble(reject) == doctest::Approx(20.0));
		}

		SUBCASE("lower layer greylist preserved")
		{
			auto *greylist = ucl_object_lookup(actions, "greylist");
			REQUIRE(greylist != nullptr);
			CHECK(ucl_object_todouble(greylist) == doctest::Approx(4.0));
		}

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("scores override by higher layer")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *low = ucl_parse_string(R"({"scores":{"SYM_A":1.0,"SYM_B":2.0}})");
		auto *high = ucl_parse_string(R"({"scores":{"SYM_A":5.0,"SYM_C":3.0}})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_PROFILE, "profile", 0, low);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_PER_USER, "user", 0, high);
		ucl_object_unref(low);
		ucl_object_unref(high);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *scores = ucl_object_lookup(result, "scores");
		REQUIRE(scores != nullptr);

		CHECK(ucl_object_todouble(ucl_object_lookup(scores, "SYM_A")) == doctest::Approx(5.0));
		CHECK(ucl_object_todouble(ucl_object_lookup(scores, "SYM_B")) == doctest::Approx(2.0));
		CHECK(ucl_object_todouble(ucl_object_lookup(scores, "SYM_C")) == doctest::Approx(3.0));

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("symbols_enabled union across layers")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *layer1 = ucl_parse_string(R"({"symbols_enabled":["SYM_A","SYM_B"]})");
		auto *layer2 = ucl_parse_string(R"({"symbols_enabled":["SYM_B","SYM_C"]})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, layer1);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_PER_USER, "user", 0, layer2);
		ucl_object_unref(layer1);
		ucl_object_unref(layer2);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *enabled = ucl_object_lookup(result, "symbols_enabled");
		REQUIRE(enabled != nullptr);

		/* Union: A, B, C all present */
		CHECK(ucl_array_has_string(enabled, "SYM_A"));
		CHECK(ucl_array_has_string(enabled, "SYM_B"));
		CHECK(ucl_array_has_string(enabled, "SYM_C"));

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("enable vs disable conflict resolution")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		/* Lower layer disables SYM_A, higher layer enables it */
		auto *low = ucl_parse_string(R"({"symbols_disabled":["SYM_A","SYM_B"]})");
		auto *high = ucl_parse_string(R"({"symbols_enabled":["SYM_A"]})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, low);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_HTTP, "http", 0, high);
		ucl_object_unref(low);
		ucl_object_unref(high);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *enabled = ucl_object_lookup(result, "symbols_enabled");
		auto *disabled = ucl_object_lookup(result, "symbols_disabled");

		SUBCASE("SYM_A enabled by higher layer wins over lower disable")
		{
			REQUIRE(enabled != nullptr);
			CHECK(ucl_array_has_string(enabled, "SYM_A"));
			/* SYM_A should NOT be in disabled */
			if (disabled) {
				CHECK_FALSE(ucl_array_has_string(disabled, "SYM_A"));
			}
		}

		SUBCASE("SYM_B remains disabled (no conflicting enable)")
		{
			REQUIRE(disabled != nullptr);
			CHECK(ucl_array_has_string(disabled, "SYM_B"));
		}

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("same layer same specificity disable wins")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		/* Same layer has both enable and disable for SYM_A */
		auto *layer = ucl_parse_string(R"({"symbols_enabled":["SYM_A"],"symbols_disabled":["SYM_A"]})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, layer);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_HTTP, "http", 0, layer);
		ucl_object_unref(layer);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *disabled = ucl_object_lookup(result, "symbols_disabled");
		REQUIRE(disabled != nullptr);
		CHECK(ucl_array_has_string(disabled, "SYM_A"));

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("whitelist any layer wins")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *no_wl = ucl_parse_string(R"({"actions":{"reject":15.0}})");
		auto *wl = ucl_parse_string(R"({"whitelist":true})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, no_wl);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_HTTP, "http", 0, wl);
		ucl_object_unref(no_wl);
		ucl_object_unref(wl);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *whitelist = ucl_object_lookup(result, "whitelist");
		REQUIRE(whitelist != nullptr);
		CHECK(ucl_object_toboolean(whitelist));

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("merge metadata is present")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *l1 = ucl_parse_string(R"({"actions":{"reject":10}})");
		auto *l2 = ucl_parse_string(R"({"actions":{"reject":20}})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_PROFILE, "inbound", 42, l1);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_PER_USER, "redis_user", 0, l2);
		ucl_object_unref(l1);
		ucl_object_unref(l2);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *meta = ucl_object_lookup(result, "_merge_info");
		REQUIRE(meta != nullptr);
		CHECK(ucl_object_type(meta) == UCL_ARRAY);

		/* Should have 2 entries */
		int count = 0;
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;
		while ((cur = ucl_object_iterate(meta, &it, true)) != nullptr) {
			count++;
		}
		CHECK(count == 2);

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("no layers returns null")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);
		auto *result = rspamd_settings_merge_finalize(ctx);
		CHECK(result == nullptr);

		rspamd_config_free(cfg);
	}

	TEST_CASE("flags union across layers")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *l1 = ucl_parse_string(R"({"flags":["no_stat"]})");
		auto *l2 = ucl_parse_string(R"({"flags":["skip"]})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, l1);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_HTTP, "http", 0, l2);
		ucl_object_unref(l1);
		ucl_object_unref(l2);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *flags = ucl_object_lookup(result, "flags");
		REQUIRE(flags != nullptr);
		CHECK(ucl_array_has_string(flags, "no_stat"));
		CHECK(ucl_array_has_string(flags, "skip"));

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}

	TEST_CASE("subject highest layer wins")
	{
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		auto *pool = cfg->cfg_pool;

		auto *ctx = rspamd_settings_merge_ctx_create(pool, cfg);

		auto *l1 = ucl_parse_string(R"({"subject":"[SPAM] %s"})");
		auto *l2 = ucl_parse_string(R"({"subject":"[JUNK] %s"})");

		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_RULE, "rule", 0, l1);
		rspamd_settings_merge_add_layer(ctx, RSPAMD_SETTINGS_LAYER_HTTP, "http", 0, l2);
		ucl_object_unref(l1);
		ucl_object_unref(l2);

		auto *result = rspamd_settings_merge_finalize(ctx);
		REQUIRE(result != nullptr);

		auto *subject = ucl_object_lookup(result, "subject");
		REQUIRE(subject != nullptr);
		CHECK(std::string(ucl_object_tostring(subject)) == "[JUNK] %s");

		ucl_object_unref(result);
		rspamd_config_free(cfg);
	}
}

#endif//RSPAMD_CXX_UNIT_SETTINGS_MERGE_HXX
