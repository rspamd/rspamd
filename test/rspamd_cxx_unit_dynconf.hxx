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

/* Dynamic configuration: the C subscriber round trip and the per-task trigger */

#ifndef RSPAMD_CXX_UNIT_DYNCONF_HXX
#define RSPAMD_CXX_UNIT_DYNCONF_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include "libserver/cfg_file.h"
#include "libserver/cfg_file_private.h"
#include "libserver/cfg_dynamic.h"
#include "libserver/rspamd_symcache.h"
#include "lua/lua_common.h"

#include "contrib/libev/ev.h"
#include <cmath>
#include <cstdio>
#include <string>
#include <unistd.h>

namespace rspamd_dynconf_test {

struct subscriber_state {
	int calls = 0;
	bool reject = false;
	bool has_a = false;
	double a = 0;
	bool has_x_c = false;
	double x_c = 0;
};

static gboolean
test_apply(struct rspamd_config *cfg, const char *module,
		   const ucl_object_t *dyn_values, void *ud,
		   struct rspamd_dynconf_apply_info *info, GError **err)
{
	auto *st = static_cast<subscriber_state *>(ud);

	st->calls++;

	if (st->reject) {
		g_set_error(err, g_quark_from_static_string("dynconf_test"), EINVAL, "rejected");
		return FALSE;
	}

	st->has_a = false;
	st->has_x_c = false;

	if (dyn_values) {
		auto *elt = ucl_object_lookup(dyn_values, "a");

		if (elt) {
			st->has_a = ucl_object_todouble_safe(elt, &st->a);
		}

		auto *b = ucl_object_lookup(dyn_values, "b");

		if (b) {
			auto *x = ucl_object_lookup(b, "x");

			if (x) {
				auto *c = ucl_object_lookup(x, "c");

				if (c) {
					st->has_x_c = ucl_object_todouble_safe(c, &st->x_c);
				}
			}
		}
	}

	return TRUE;
}

/* Runs a Lua chunk that returns a string (error text or "ok") */
static auto run_lua(lua_State *L, const char *code) -> std::string
{
	auto top = lua_gettop(L);

	if (luaL_loadstring(L, code) != 0 || lua_pcall(L, 0, 1, 0) != 0) {
		std::string err = lua_tostring(L, -1);
		lua_settop(L, top);
		return "lua error: " + err;
	}

	std::string res = lua_isstring(L, -1) ? lua_tostring(L, -1) : "";
	lua_settop(L, top);

	return res;
}

/* Installs a static configuration: overrides can only select entries that exist in it */
static void set_static_config(struct rspamd_config *cfg, const char *text)
{
	auto *parser = ucl_parser_new(0);

	REQUIRE(ucl_parser_add_string(parser, text, 0));
	cfg->cfg_ucl_obj = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
}

class dynconf_fixture {
public:
	dynconf_fixture()
	{
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		L = RSPAMD_LUA_CFG_STATE(cfg);
		REQUIRE(L != nullptr);
		/* lualib comes from the installed tree, LUALIBDIR overrides it */
		rspamd_lua_set_path(L, nullptr, nullptr);
		rspamd_lua_set_globals(cfg, L);
		loop = ev_loop_new(0);
		REQUIRE(loop != nullptr);
	}

	dynconf_fixture(const dynconf_fixture &) = delete;
	dynconf_fixture &operator=(const dynconf_fixture &) = delete;

	~dynconf_fixture()
	{
		ev_loop_destroy(loop);
		rspamd_config_free(cfg);
	}

	struct rspamd_config *cfg;
	lua_State *L;
	struct ev_loop *loop;
};

}// namespace rspamd_dynconf_test

TEST_SUITE("dynconf")
{
	using namespace rspamd_dynconf_test;

	static const char *const paths[] = {"a", "b.*.c", nullptr};

	TEST_CASE("subscriber receives the effective values of dynamic paths")
	{
		dynconf_fixture f;
		subscriber_state st;

		set_static_config(f.cfg, "dyntest { b { x { c = 1; } } }");
		REQUIRE(rspamd_dynconf_register_module(f.cfg, "dyntest", paths, test_apply, &st));
		CHECK(rspamd_dynconf_generation(f.cfg) == 0);

		/* An entry that is not in the static configuration cannot be created by an override */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok = d.apply('t', 'dyntest', {b = {nope = {c = 1}}}, 1)
			return ok and 'must be rejected' or 'ok'
		)lua") == "ok");
		CHECK(st.calls == 0);

		/* An override of a plain option and of a wildcard one, a non-dynamic one is rejected */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'dyntest', {a = 5, b = {x = {c = 7}}}, 1)
			if not ok then return 'apply failed: ' .. tostring(err) end
			return 'ok'
		)lua") == "ok");

		CHECK(st.calls == 1);
		REQUIRE(st.has_a);
		CHECK(st.a == doctest::Approx(5));
		REQUIRE(st.has_x_c);
		CHECK(st.x_c == doctest::Approx(7));
		CHECK(rspamd_dynconf_generation(f.cfg) == 1);

		/* Not a dynamic path: the registry rejects it before the subscriber is involved */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'dyntest', {a = 5, zzz = 1}, 2)
			if ok then return 'must be rejected' end
			return 'ok'
		)lua") == "ok");
		CHECK(st.calls == 1);
		CHECK(rspamd_dynconf_generation(f.cfg) == 1);

		/* An unchanged update does not wake the subscriber */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'dyntest', {a = 5, b = {x = {c = 7}}}, 3)
			if not ok then return 'apply failed: ' .. tostring(err) end
			return 'ok'
		)lua") == "ok");
		CHECK(st.calls == 1);

		/* Removing the override: the static value is delivered, `a` is absent (the module default) */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'dyntest', nil, 4)
			if not ok then return 'apply failed: ' .. tostring(err) end
			return 'ok'
		)lua") == "ok");
		CHECK(st.calls == 2);
		CHECK(!st.has_a);
		REQUIRE(st.has_x_c);
		CHECK(st.x_c == doctest::Approx(1));
		CHECK(rspamd_dynconf_generation(f.cfg) == 2);
	}

	TEST_CASE("a rejecting subscriber leaves the registry untouched")
	{
		dynconf_fixture f;
		subscriber_state st;

		REQUIRE(rspamd_dynconf_register_module(f.cfg, "dyntest", paths, test_apply, &st));
		st.reject = true;

		/* The update is refused as a whole, with the error of the subscriber */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'dyntest', {a = 1}, 1)
			if ok then return 'must fail' end
			if d.get('dyntest').a ~= nil then return 'the value has been kept' end
			if d.generation() ~= 0 then return 'generation changed' end
			return tostring(err):match('rejected') and 'ok' or tostring(err)
		)lua") == "ok");
		CHECK(st.calls == 1);
		CHECK(rspamd_dynconf_generation(f.cfg) == 0);

		/* Accepted again as soon as the subscriber agrees */
		st.reject = false;
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'dyntest', {a = 1}, 1)
			if not ok then return 'apply failed: ' .. tostring(err) end
			return d.get('dyntest').a == 1 and 'ok' or 'wrong value'
		)lua") == "ok");
		st.reject = true;

		/* The binding reports the error of the subscriber */
		CHECK(run_lua(f.L, R"lua(
			local ok, err = rspamd_config:dynconf_notify('dyntest', {a = 2})
			if ok then return 'must fail' end
			return err
		)lua") == "rejected");

		/* ... and for a module without a subscriber */
		CHECK(run_lua(f.L, R"lua(
			local ok, err = rspamd_config:dynconf_notify('nosuchmodule', {})
			if ok then return 'must fail' end
			return 'ok'
		)lua") == "ok");
	}

	TEST_CASE("per-task trigger")
	{
		dynconf_fixture f;

		/* Disarmed by default: nothing is called */
		CHECK(f.cfg->dyn_next_check == 0.0);
		rspamd_dynconf_maybe_check(f.cfg, f.loop, ev_time() + 1000.0);

		CHECK(run_lua(f.L, R"lua(
			dynconf_test_calls = 0
			dynconf_test_loop = nil
			rspamd_config:dynconf_arm(require("rspamd_util").get_time() + 3600, function(_, loop)
				dynconf_test_calls = dynconf_test_calls + 1
				dynconf_test_loop = type(loop)
			end)
			return 'ok'
		)lua") == "ok");

		auto now = ev_time();
		CHECK(f.cfg->dyn_next_check > now);

		/* Too early */
		rspamd_dynconf_maybe_check(f.cfg, f.loop, now);
		CHECK(run_lua(f.L, "return tostring(dynconf_test_calls)") == "0");

		/* Due: the function is called once with an event loop, then the trigger backs off */
		auto later = now + 7200.0;
		rspamd_dynconf_maybe_check(f.cfg, f.loop, later);
		CHECK(run_lua(f.L, "return tostring(dynconf_test_calls)") == "1");
		CHECK(run_lua(f.L, "return dynconf_test_loop") == "userdata");
		CHECK(f.cfg->dyn_next_check > later);

		rspamd_dynconf_maybe_check(f.cfg, f.loop, later);
		CHECK(run_lua(f.L, "return tostring(dynconf_test_calls)") == "1");

		/* A task without an event loop cannot start a check and leaves it for the next one */
		rspamd_dynconf_maybe_check(f.cfg, nullptr, later + 10.0);
		CHECK(run_lua(f.L, "return tostring(dynconf_test_calls)") == "1");

		/* A failing function is logged and does not hurt */
		CHECK(run_lua(f.L, R"lua(
			rspamd_config:dynconf_arm(require("rspamd_util").get_time(), function() error('boom') end)
			return 'ok'
		)lua") == "ok");
		rspamd_dynconf_maybe_check(f.cfg, f.loop, ev_time() + 1.0);
		CHECK(f.cfg->dyn_next_check > 0.0);

		/* A function that re-arms with a zero interval does not defeat the backoff */
		CHECK(run_lua(f.L, R"lua(
			local function trigger()
				rspamd_config:dynconf_arm(require("rspamd_util").get_time(), trigger)
			end
			rspamd_config:dynconf_arm(require("rspamd_util").get_time(), trigger)
			return 'ok'
		)lua") == "ok");
		auto before_check = ev_time();
		rspamd_dynconf_maybe_check(f.cfg, f.loop, before_check + 1.0);
		CHECK(f.cfg->dyn_next_check >= before_check + 1.0);

		/* Disarming */
		CHECK(run_lua(f.L, R"lua(
			rspamd_config:dynconf_arm(0)
			return 'ok'
		)lua") == "ok");
		CHECK(f.cfg->dyn_next_check == 0.0);
		rspamd_dynconf_maybe_check(f.cfg, f.loop, ev_time() + 100000.0);
	}

	/* The metric as dynamic configuration: actions, scores and symbols */

	static void
	dummy_symbol_cb(struct rspamd_task * task, struct rspamd_symcache_dynamic_item * item, gpointer ud)
	{
	}

	/* Defines an action the way the configuration does: with the priority of the file that holds it */
	static void
	add_static_action(struct rspamd_config * cfg, const char *name, double threshold, unsigned int priority = 0)
	{
		auto *obj = ucl_object_fromdouble(threshold);

		ucl_object_set_priority(obj, priority);
		REQUIRE(rspamd_config_set_action_score(cfg, name, obj));
		ucl_object_unref(obj);
	}

	/* A configuration with a small metric and the metric modules registered */
	class metric_fixture : public dynconf_fixture {
	public:
		metric_fixture()
		{
			/*
			 * The main file has the priority 0, `local.d` 1 (lower than the dynamic configuration, 3),
			 * `override.d` 10 (higher)
			 */
			add_static_action(cfg, "reject", 15.0, 0);
			add_static_action(cfg, "add header", 6.0, 1);
			add_static_action(cfg, "greylist", 4.0, 10);

			REQUIRE(rspamd_config_add_symbol(cfg, "DYN_SYM_A", 2.0, nullptr, nullptr, 0, 0, 1));
			REQUIRE(rspamd_config_add_symbol(cfg, "DYN_SYM_FIXED", 3.0, nullptr, nullptr, 0, 10, 1));
			REQUIRE(rspamd_config_add_symbol(cfg, "DYN_SYM_NEG", -1.0, nullptr, nullptr, 0, 0, 1));

			REQUIRE(rspamd_symcache_add_symbol(cfg->cache, "DYN_SYM_A", 0, dummy_symbol_cb, nullptr,
											   SYMBOL_TYPE_NORMAL, -1) >= 0);
			REQUIRE(rspamd_symcache_add_symbol(cfg->cache, "DYN_SYM_B", 0, dummy_symbol_cb, nullptr,
											   SYMBOL_TYPE_NORMAL, -1) >= 0);
			REQUIRE(rspamd_dynconf_register_metric_modules(cfg));
		}

		auto action(const char *name) -> struct rspamd_action *
		{
			auto *act = rspamd_config_get_action(cfg, name);
			REQUIRE(act != nullptr);
			return act;
		}

		auto score(const char *name) -> double
		{
			auto *sym = static_cast<struct rspamd_symbol *>(g_hash_table_lookup(cfg->symbols, name));
			REQUIRE(sym != nullptr);
			REQUIRE(*sym->weight_ptr == sym->score);
			return sym->score;
		}

		/*
		 * Applies (`values` is a Lua table constructor) or removes (`nil`) an override of a module.
		 * `opts` is the Lua constructor of the options of `lua_dynconf.apply` (how strict the subscriber
		 * is): a strict update by default, `{lenient = true}` for what a backend delivers. The result is
		 * `ok`, or the error; `ok; reason; reason` lists what the subscriber has skipped
		 */
		auto apply(const char *module, const char *values, const char *opts = "nil") -> std::string
		{
			auto code = std::string{R"lua(
				local d = require "lua_dynconf"
				local ok, err, _, skipped = d.apply('t', ')lua"} +
						module + "', " + values + ", 1, " + opts + R"lua()
				if not ok then return tostring(err) end
				if skipped then return 'ok; ' .. table.concat(skipped, '; ') end
				return 'ok'
			)lua";

			return run_lua(L, code.c_str());
		}

		auto apply_lenient(const char *module, const char *values) -> std::string
		{
			return apply(module, values, "{lenient = true}");
		}
	};

	TEST_CASE("actions: thresholds are applied, restored and respect priorities")
	{
		metric_fixture f;
		double thr;
		gboolean overridden;

		/* The registry holds overrides only: the static state is remembered by the subscriber */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			return #d.dump({module = 'actions'}).modules.actions.dynamic == 1 and 'ok' or 'wrong paths'
		)lua") == "ok");

		CHECK(f.apply("actions", "{reject = 20, ['add header'] = 9}") == "ok");
		CHECK(f.action("reject")->threshold == doctest::Approx(20.0));
		CHECK(f.action("reject")->priority == 3);
		CHECK(f.action("add header")->threshold == doctest::Approx(9.0));

		/* The static values and the state are still known */
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "actions", "reject", &thr, &overridden, nullptr));
		CHECK(thr == doctest::Approx(15.0));
		CHECK(overridden);
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "actions", "add_header", &thr, &overridden, nullptr));
		CHECK(thr == doctest::Approx(6.0));
		CHECK(overridden);

		/* The thresholds stay sorted, so the highest one is still the last */
		{
			double prev = -1e9;
			rspamd_config_actions_foreach(
				f.cfg, [](struct rspamd_action *act, void *d) {
					auto *prev = static_cast<double *>(d);

					if (!std::isnan(act->threshold)) {
						CHECK(act->threshold >= *prev);
						*prev = act->threshold;
					}
				},
				&prev);
		}

		/* Another spelling of an action name is the same action; a part of the overrides can go away */
		CHECK(f.apply("actions", "{add_header = 7}") == "ok");
		CHECK(f.action("add header")->threshold == doctest::Approx(7.0));
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));
		CHECK(f.action("reject")->priority == 0);

		/* Two spellings of one action are ambiguous */
		CHECK(f.apply("actions", "{add_header = 7, ['add header'] = 8}").find("twice") != std::string::npos);
		CHECK(f.action("add header")->threshold == doctest::Approx(7.0));

		/*
		 * An action that override.d defines (the priority 10) wins over the dynamic threshold (3): a write is
		 * rejected with an error that says so, what a backend delivers is skipped and reported
		 */
		auto masked = f.apply("actions", "{greylist = 2, reject = 21}");
		CHECK(masked.find("greylist") != std::string::npos);
		CHECK(masked.find("priority 10") != std::string::npos);
		CHECK(f.action("greylist")->threshold == doctest::Approx(4.0));
		CHECK(f.action("greylist")->priority == 10);
		/* nothing of the rejected update has been applied */
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));
		auto skipped = f.apply_lenient("actions", "{greylist = 2, reject = 21}");
		CHECK(skipped.find("ok; the threshold of the action greylist is defined with the priority 10") == 0);
		CHECK(f.action("greylist")->threshold == doctest::Approx(4.0));
		CHECK(f.action("greylist")->priority == 10);
		CHECK(f.action("reject")->threshold == doctest::Approx(21.0));
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "actions", "greylist", &thr, &overridden, nullptr));
		CHECK(thr == doctest::Approx(4.0));
		CHECK(!overridden);
		CHECK(f.apply_lenient("actions", "{add_header = 7}") == "ok");
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));

		/* An unknown action, or a value that is not a number, rejects a strict update as a whole */
		CHECK(f.apply("actions", "{reject = 30, nosuchaction = 5}").find("unknown action") != std::string::npos);
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));
		CHECK(f.apply("actions", "{reject = 'high'}").find("must be a number") != std::string::npos);
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));
		CHECK(f.apply("actions", "{reject = 0/0}").find("must be a number") != std::string::npos);
		/* a malformed value is not a stale name: a lenient update rejects it too */
		CHECK(f.apply_lenient("actions", "{reject = 'high'}").find("must be a number") != std::string::npos);
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));

		/* Removal restores everything */
		CHECK(f.apply("actions", "nil") == "ok");
		CHECK(f.action("reject")->threshold == doctest::Approx(15.0));
		CHECK(f.action("add header")->threshold == doctest::Approx(6.0));
		CHECK(f.action("add header")->priority == 1);
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "actions", "reject", &thr, &overridden, nullptr));
		CHECK(!overridden);
	}

	TEST_CASE("actions: a disabled action round-trips")
	{
		metric_fixture f;
		double thr;

		/* Not configured actions have no threshold, but can get one dynamically */
		CHECK(std::isnan(f.action("rewrite subject")->threshold));
		gboolean known = FALSE;

		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "actions", "rewrite subject", &thr, nullptr, &known));
		/* ... which is not the same as an action that does not exist */
		CHECK(known);
		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "actions", "no such action", &thr, nullptr, &known));
		CHECK(!known);

		CHECK(f.apply("actions", "{['rewrite subject'] = 8}") == "ok");
		CHECK(f.action("rewrite subject")->threshold == doctest::Approx(8.0));

		/* A no_threshold action (soft reject) becomes a threshold action and goes back */
		auto flags = f.action("soft reject")->flags;
		CHECK((flags & RSPAMD_ACTION_NO_THRESHOLD) != 0);
		CHECK(f.apply("actions", "{['soft reject'] = 3, ['rewrite subject'] = 8}") == "ok");
		CHECK(f.action("soft reject")->threshold == doctest::Approx(3.0));
		CHECK((f.action("soft reject")->flags & RSPAMD_ACTION_NO_THRESHOLD) == 0);
		CHECK((f.action("soft reject")->flags & RSPAMD_ACTION_HAM) != 0);

		CHECK(f.apply("actions", "nil") == "ok");
		CHECK(std::isnan(f.action("rewrite subject")->threshold));
		CHECK(std::isnan(f.action("soft reject")->threshold));
		CHECK(f.action("soft reject")->flags == flags);
		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "actions", "soft reject", &thr, nullptr, nullptr));
	}

	TEST_CASE("scores: symbol scores are applied, restored and respect priorities")
	{
		metric_fixture f;
		double score;
		gboolean overridden;

		CHECK(f.apply("scores", "{DYN_SYM_A = 7.5, DYN_SYM_NEG = -4}") == "ok");
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(7.5));
		CHECK(f.score("DYN_SYM_NEG") == doctest::Approx(-4.0));

		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "scores", "DYN_SYM_A", &score, &overridden, nullptr));
		CHECK(score == doctest::Approx(2.0));
		CHECK(overridden);

		/* A higher priority definition (override.d) keeps its score: a write is rejected, a delivery skips it */
		auto masked = f.apply("scores", "{DYN_SYM_A = 7.5, DYN_SYM_FIXED = 9}");
		CHECK(masked.find("DYN_SYM_FIXED") != std::string::npos);
		CHECK(masked.find("priority 10") != std::string::npos);
		CHECK(f.score("DYN_SYM_FIXED") == doctest::Approx(3.0));
		/* The rest of the rejected update has not been applied, the previous state is kept */
		CHECK(f.score("DYN_SYM_NEG") == doctest::Approx(-4.0));
		CHECK(f.apply_lenient("scores", "{DYN_SYM_A = 7.5, DYN_SYM_FIXED = 9}").find("ok; the score of the symbol DYN_SYM_FIXED") == 0);
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(7.5));
		CHECK(f.score("DYN_SYM_FIXED") == doctest::Approx(3.0));
		CHECK(f.score("DYN_SYM_NEG") == doctest::Approx(-1.0));

		/* An unknown symbol or a wrong value rejects the whole update */
		CHECK(f.apply("scores", "{DYN_SYM_A = 1, NO_SUCH_SYMBOL = 5}").find("unknown symbol") != std::string::npos);
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(7.5));
		CHECK(f.apply("scores", "{DYN_SYM_A = 'x'}").find("must be a number") != std::string::npos);
		CHECK(f.apply("scores", "{DYN_SYM_A = true}").find("must be a number") != std::string::npos);
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(7.5));

		CHECK(f.apply("scores", "nil") == "ok");
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(2.0));
		CHECK(f.score("DYN_SYM_NEG") == doctest::Approx(-1.0));
		auto *sym = static_cast<struct rspamd_symbol *>(g_hash_table_lookup(f.cfg->symbols, "DYN_SYM_A"));
		CHECK(sym->priority == 0);
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "scores", "DYN_SYM_A", &score, &overridden, nullptr));
		CHECK(!overridden);
		gboolean known = TRUE;

		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "scores", "NO_SUCH_SYMBOL", &score, &overridden, &known));
		CHECK(!known);
	}

	TEST_CASE("scores: the static score is what the scan reads (weight_ptr), not sym->score")
	{
		metric_fixture f;
		double score;
		gboolean overridden;

		/*
		 * A symbol that has been added by `unknown_weight` has a zero score and a weight
		 * that points to the weight of the cache item, which holds `unknown_weight`
		 */
		REQUIRE(rspamd_config_add_symbol(f.cfg, "DYN_SYM_UNK", 1.0, nullptr, nullptr, 0, 0, 1));
		auto *sym = static_cast<struct rspamd_symbol *>(g_hash_table_lookup(f.cfg->symbols, "DYN_SYM_UNK"));
		REQUIRE(sym != nullptr);
		auto *orig_weight = sym->weight_ptr;
		auto *own_weight = new double(1.0);
		sym->weight_ptr = own_weight;
		sym->score = 0.0;
		sym->priority = 0;

		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "scores", "DYN_SYM_UNK", &score, &overridden, nullptr));
		CHECK(score == doctest::Approx(1.0));
		CHECK(!overridden);

		CHECK(f.apply("scores", "{DYN_SYM_UNK = 5}") == "ok");
		CHECK(*sym->weight_ptr == doctest::Approx(5.0));
		CHECK(sym->score == doctest::Approx(5.0));
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "scores", "DYN_SYM_UNK", &score, &overridden, nullptr));
		CHECK(score == doctest::Approx(1.0));
		CHECK(overridden);

		/* The static score comes back through weight_ptr, it is not zero */
		CHECK(f.apply("scores", "nil") == "ok");
		CHECK(*sym->weight_ptr == doctest::Approx(1.0));
		CHECK(sym->score == doctest::Approx(1.0));
		CHECK(sym->priority == 0);

		sym->weight_ptr = orig_weight;
		delete own_weight;
	}

	TEST_CASE("restore keeps a value that somebody else has written in the meantime")
	{
		metric_fixture f;
		double thr;
		gboolean overridden;

		/* A symbol: a writer with a higher priority (a map, rspamd_update) */
		CHECK(f.apply("scores", "{DYN_SYM_A = 7.5, DYN_SYM_NEG = -4}") == "ok");
		auto *sym = static_cast<struct rspamd_symbol *>(g_hash_table_lookup(f.cfg->symbols, "DYN_SYM_A"));
		REQUIRE(rspamd_config_add_symbol(f.cfg, "DYN_SYM_A", 9.0, nullptr, nullptr, 0, 11, 1));
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(9.0));
		CHECK(sym->priority == 11);
		/* An equal priority writer that changes the value is not ours either */
		auto *neg = static_cast<struct rspamd_symbol *>(g_hash_table_lookup(f.cfg->symbols, "DYN_SYM_NEG"));
		REQUIRE(rspamd_config_add_symbol(f.cfg, "DYN_SYM_NEG", 2.5, nullptr, nullptr, 0, 3, 1));
		CHECK(f.score("DYN_SYM_NEG") == doctest::Approx(2.5));

		CHECK(f.apply("scores", "nil") == "ok");
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(9.0));
		CHECK(sym->priority == 11);
		CHECK(f.score("DYN_SYM_NEG") == doctest::Approx(2.5));
		CHECK(neg->priority == 3);
		/* and the saved state is forgotten, the symbol is not overridden any more */
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "scores", "DYN_SYM_A", &thr, &overridden, nullptr));
		CHECK(!overridden);
		CHECK(thr == doctest::Approx(9.0));

		/* The same for an action */
		CHECK(f.apply("actions", "{reject = 20, ['add header'] = 9}") == "ok");
		/* a higher priority writer, and an equal priority one with another value */
		add_static_action(f.cfg, "reject", 25.0, 11);
		add_static_action(f.cfg, "add header", 8.0, 3);
		CHECK(f.action("reject")->threshold == doctest::Approx(25.0));
		CHECK(f.action("add header")->threshold == doctest::Approx(8.0));
		CHECK(f.apply("actions", "nil") == "ok");
		CHECK(f.action("reject")->threshold == doctest::Approx(25.0));
		CHECK(f.action("reject")->priority == 11);
		CHECK(f.action("add header")->threshold == doctest::Approx(8.0));
		CHECK(f.action("add header")->priority == 3);
		REQUIRE(rspamd_dynconf_metric_baseline(f.cfg, "actions", "reject", &thr, &overridden, nullptr));
		CHECK(!overridden);
	}

	TEST_CASE("symbols: a symbol can be switched off at runtime")
	{
		metric_fixture f;

		REQUIRE(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_A"));
		REQUIRE(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_B"));

		CHECK(f.apply("symbols", "{DYN_SYM_A = {enabled = false}, DYN_SYM_B = {enabled = true}}") == "ok");
		CHECK(!rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_A"));
		/* `true` is what an absent override means */
		CHECK(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_B"));

		/* The other symbol goes off, the first one is back */
		CHECK(f.apply("symbols", "{DYN_SYM_B = {enabled = false}}") == "ok");
		CHECK(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_A"));
		CHECK(!rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_B"));

		/* Unknown symbols and wrong values reject the update, nothing is changed */
		CHECK(f.apply("symbols", "{DYN_SYM_A = {enabled = false}, NO_SUCH = {enabled = false}}").find("unknown symbol") != std::string::npos);
		CHECK(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_A"));
		CHECK(f.apply("symbols", "{DYN_SYM_A = {enabled = 'no'}}").find("boolean") != std::string::npos);
		CHECK(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_A"));
		CHECK(!rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_B"));

		/* The baseline reports whether a symbol is known and switched off now */
		gboolean overridden = FALSE, known = FALSE;
		double value;

		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "symbols", "DYN_SYM_B", &value, &overridden, &known));
		CHECK(known);
		CHECK(overridden);
		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "symbols", "DYN_SYM_A", &value, &overridden, &known));
		CHECK(known);
		CHECK(!overridden);
		CHECK(!rspamd_dynconf_metric_baseline(f.cfg, "symbols", "NO_SUCH", &value, &overridden, &known));
		CHECK(!known);

		CHECK(f.apply("symbols", "nil") == "ok");
		CHECK(rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_B"));

		/* A symbol that is disabled by its own definition is not enabled by a removal of an override */
		auto *sdef = static_cast<struct rspamd_symbol *>(g_hash_table_lookup(f.cfg->symbols, "DYN_SYM_A"));
		sdef->flags |= RSPAMD_SYMBOL_FLAG_DISABLED;
		CHECK(f.apply("symbols", "{DYN_SYM_A = {enabled = false}}") == "ok");
		CHECK(f.apply("symbols", "nil") == "ok");
		CHECK(!rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_A"));
	}

	TEST_CASE("the metric modules are registered once and are visible in the dump")
	{
		metric_fixture f;

		/* A second call is harmless */
		CHECK(rspamd_dynconf_register_metric_modules(f.cfg));
		CHECK(f.apply("actions", "{reject = 21}") == "ok");
		CHECK(f.apply("scores", "{DYN_SYM_A = 3}") == "ok");

		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local dump = d.dump()
			for _, m in ipairs({'actions', 'scores', 'symbols'}) do
				if not dump.modules[m] then return 'missing ' .. m end
			end
			local ov = dump.modules.actions.overrides.t
			if not ov or ov.values.reject ~= 21 then return 'no override in the dump' end
			return 'ok'
		)lua") == "ok");
	}

	/* Priorities of the definitions of actions */

	TEST_CASE("actions: the priority of a definition is stored and decides who wins")
	{
		metric_fixture f;

		CHECK(f.action("reject")->priority == 0);
		CHECK(f.action("add header")->priority == 1);
		CHECK(f.action("greylist")->priority == 10);

		/* A lower priority does not replace a higher one (the call is not an error) */
		add_static_action(f.cfg, "greylist", 2.0, 1);
		CHECK(f.action("greylist")->threshold == doctest::Approx(4.0));
		CHECK(f.action("greylist")->priority == 10);

		/* A higher one does, and its priority is stored */
		add_static_action(f.cfg, "add header", 7.0, 2);
		CHECK(f.action("add header")->threshold == doctest::Approx(7.0));
		CHECK(f.action("add header")->priority == 2);

		/* The same priority: the later definition wins */
		add_static_action(f.cfg, "add header", 7.5, 2);
		CHECK(f.action("add header")->threshold == doctest::Approx(7.5));
		add_static_action(f.cfg, "reject", 16.0, 0);
		CHECK(f.action("reject")->threshold == doctest::Approx(16.0));

		/* The `priority` attribute of an object (what Lua `set_metric_action` passes) is the same thing */
		auto *obj = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(obj, ucl_object_fromdouble(30.0), "score", 0, false);
		ucl_object_insert_key(obj, ucl_object_fromint(5), "priority", 0, false);
		REQUIRE(rspamd_config_set_action_score(f.cfg, "reject", obj));
		CHECK(f.action("reject")->threshold == doctest::Approx(30.0));
		CHECK(f.action("reject")->priority == 5);
		ucl_object_unref(obj);
		add_static_action(f.cfg, "reject", 17.0, 4);
		CHECK(f.action("reject")->threshold == doctest::Approx(30.0));

		/* Disabling an action follows the same rule */
		CHECK(!rspamd_config_maybe_disable_action(f.cfg, "greylist", 5));
		CHECK(f.action("greylist")->threshold == doctest::Approx(4.0));
		CHECK(rspamd_config_maybe_disable_action(f.cfg, "greylist", 10));
		CHECK(std::isnan(f.action("greylist")->threshold));
		CHECK(f.action("greylist")->priority == 10);
	}

	/* A file in a temporary directory that is removed with the object */
	struct temp_dir {
		std::string dir;

		temp_dir()
		{
			char tmpl[] = "/tmp/rspamd-dynconf-XXXXXX";

			REQUIRE(mkdtemp(tmpl) != nullptr);
			dir = tmpl;
		}

		~temp_dir()
		{
			for (const auto *n: {"main.conf", "local.conf", "override.conf"}) {
				(void) unlink((dir + "/" + n).c_str());
			}
			(void) rmdir(dir.c_str());
		}

		void write(const char *name, const std::string &text) const
		{
			auto *f = fopen((dir + "/" + name).c_str(), "w");

			REQUIRE(f != nullptr);
			fwrite(text.data(), 1, text.size(), f);
			fclose(f);
		}
	};

	/*
	 * Sets the actions the way the `actions` section handler of the configuration does: every key of the
	 * section with the priority that the parser has given it (the priority of the file it comes from)
	 */
	static void load_actions_section(struct rspamd_config * cfg, const std::string &dir)
	{
		auto *parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS);

		REQUIRE(ucl_parser_add_file(parser, (dir + "/main.conf").c_str()));
		auto *top = ucl_parser_get_object(parser);

		REQUIRE(top != nullptr);
		const auto *section = ucl_object_lookup(top, "actions");

		REQUIRE(section != nullptr);
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate(section, &it, true)) != nullptr) {
			if (ucl_object_type(cur) == UCL_NULL) {
				/* `action = null` disables it, with the priority of the file (see rspamd_rcl_actions_handler) */
				rspamd_config_maybe_disable_action(cfg, ucl_object_key(cur), ucl_object_get_priority(cur));
			}
			else {
				REQUIRE(rspamd_config_set_action_score(cfg, ucl_object_key(cur), cur));
			}
		}

		ucl_object_unref(top);
		ucl_parser_free(parser);
	}

	TEST_CASE("actions: the main file, local.d and override.d resolve by their priorities")
	{
		dynconf_fixture f;
		temp_dir td;

		td.write("main.conf", "actions {\n"
							  "  reject = 15;\n"
							  "  add_header = 6;\n"
							  "  greylist = 4;\n"
							  "  rewrite_subject { score = 9; }\n"
							  "  .include(try=true; priority=1; duplicate=merge) \"" +
								  td.dir + "/local.conf\"\n"
										   "  .include(try=true; priority=10) \"" +
								  td.dir + "/override.conf\"\n"
										   "}\n");
		td.write("local.conf", "reject = 20;\n"
							   "add_header = 8;\n"
							   "rewrite_subject { score = 11; }\n");
		td.write("override.conf", "reject = 30;\n");

		load_actions_section(f.cfg, td.dir);

		auto *reject = rspamd_config_get_action(f.cfg, "reject");
		auto *add_header = rspamd_config_get_action(f.cfg, "add header");
		auto *greylist = rspamd_config_get_action(f.cfg, "greylist");
		auto *rewrite = rspamd_config_get_action(f.cfg, "rewrite subject");

		REQUIRE(reject != nullptr);
		REQUIRE(add_header != nullptr);
		REQUIRE(greylist != nullptr);
		REQUIRE(rewrite != nullptr);

		/* override.d (10) beats local.d (1), which beats the main file (0) */
		CHECK(reject->threshold == doctest::Approx(30.0));
		CHECK(reject->priority == 10);
		CHECK(add_header->threshold == doctest::Approx(8.0));
		CHECK(add_header->priority == 1);
		CHECK(greylist->threshold == doctest::Approx(4.0));
		CHECK(greylist->priority == 0);
		/* the same for the object form, where the priority is that of the whole object after merging */
		CHECK(rewrite->threshold == doctest::Approx(11.0));
		CHECK(rewrite->priority == 1);
	}

	TEST_CASE("actions: override.d beats a dynamic threshold, which beats local.d and the main file")
	{
		dynconf_fixture f;
		temp_dir td;

		td.write("main.conf", "actions {\n"
							  "  reject = 15;\n"
							  "  add_header = 6;\n"
							  "  greylist = 4;\n"
							  "  .include(try=true; priority=1; duplicate=merge) \"" +
								  td.dir + "/local.conf\"\n"
										   "  .include(try=true; priority=10) \"" +
								  td.dir + "/override.conf\"\n"
										   "}\n");
		td.write("local.conf", "add_header = 8;\n");
		td.write("override.conf", "reject = 30;\n");

		load_actions_section(f.cfg, td.dir);
		REQUIRE(rspamd_symcache_add_symbol(f.cfg->cache, "DYN_SYM_A", 0, dummy_symbol_cb, nullptr,
										   SYMBOL_TYPE_NORMAL, -1) >= 0);
		REQUIRE(rspamd_dynconf_register_metric_modules(f.cfg));

		auto threshold = [&](const char *name) {
			auto *act = rspamd_config_get_action(f.cfg, name);

			REQUIRE(act != nullptr);
			return act->threshold;
		};

		auto apply = [&](const char *values, const char *opts) {
			auto code = std::string{"local d = require 'lua_dynconf'\n"
									"local ok, err, _, skipped = d.apply('t', 'actions', "} +
						values + ", 1, " + opts +
						")\n"
						"if not ok then return tostring(err) end\n"
						"if skipped then return 'ok; ' .. table.concat(skipped, '; ') end\n"
						"return 'ok'";

			return run_lua(f.L, code.c_str());
		};

		/* The dynamic threshold replaces the main file and local.d ... */
		CHECK(apply("{greylist = 3, add_header = 9}", "nil") == "ok");
		CHECK(threshold("greylist") == doctest::Approx(3.0));
		CHECK(threshold("add header") == doctest::Approx(9.0));

		/* ... but not override.d: a write says so, a delivery skips the entry and reports it */
		auto err = apply("{greylist = 3, add_header = 9, reject = 50}", "nil");
		CHECK(err.find("reject") != std::string::npos);
		CHECK(err.find("priority 10") != std::string::npos);
		CHECK(threshold("reject") == doctest::Approx(30.0));
		auto skipped = apply("{greylist = 3, add_header = 9, reject = 50}", "{lenient = true}");
		CHECK(skipped.find("ok; the threshold of the action reject is defined with the priority 10") == 0);
		CHECK(threshold("reject") == doctest::Approx(30.0));
		CHECK(threshold("greylist") == doctest::Approx(3.0));

		/* Whatever goes away gets what the files say back, with their priorities */
		CHECK(run_lua(f.L, "return tostring(require('lua_dynconf').apply('t', 'actions', nil, 1))") == "true");
		CHECK(threshold("add header") == doctest::Approx(8.0));
		CHECK(rspamd_config_get_action(f.cfg, "add header")->priority == 1);
		CHECK(threshold("greylist") == doctest::Approx(4.0));
		CHECK(rspamd_config_get_action(f.cfg, "greylist")->priority == 0);
		CHECK(threshold("reject") == doctest::Approx(30.0));
		CHECK(rspamd_config_get_action(f.cfg, "reject")->priority == 10);
	}

	TEST_CASE("actions: a null in local.d or override.d disables the action with the priority of the file")
	{
		dynconf_fixture f;
		temp_dir td;

		/* The stock files spell the standard actions with underscores: `add_header`, not `add header` */
		td.write("main.conf", "actions {\n"
							  "  reject = 15;\n"
							  "  add_header = 6;\n"
							  "  greylist = 4;\n"
							  "  .include(try=true; priority=1; duplicate=merge) \"" +
								  td.dir + "/local.conf\"\n"
										   "  .include(try=true; priority=10) \"" +
								  td.dir + "/override.conf\"\n"
										   "}\n");
		td.write("local.conf", "greylist = null;\n");
		td.write("override.conf", "add_header = null;\n");

		load_actions_section(f.cfg, td.dir);
		REQUIRE(rspamd_symcache_add_symbol(f.cfg->cache, "DYN_SYM_A", 0, dummy_symbol_cb, nullptr,
										   SYMBOL_TYPE_NORMAL, -1) >= 0);
		REQUIRE(rspamd_dynconf_register_metric_modules(f.cfg));

		auto *reject = rspamd_config_get_action(f.cfg, "reject");
		auto *add_header = rspamd_config_get_action(f.cfg, "add header");
		auto *greylist = rspamd_config_get_action(f.cfg, "greylist");

		REQUIRE(reject != nullptr);
		REQUIRE(add_header != nullptr);
		REQUIRE(greylist != nullptr);

		/* Both spellings find the action, and the priority of the file that has disabled it is stored */
		CHECK(std::isnan(add_header->threshold));
		CHECK((add_header->flags & RSPAMD_ACTION_NO_THRESHOLD) != 0);
		CHECK(add_header->priority == 10);
		CHECK(std::isnan(greylist->threshold));
		CHECK((greylist->flags & RSPAMD_ACTION_NO_THRESHOLD) != 0);
		CHECK(greylist->priority == 1);
		CHECK(reject->threshold == doctest::Approx(15.0));

		auto apply = [&](const char *values, const char *opts) {
			auto code = std::string{"local d = require 'lua_dynconf'\n"
									"local ok, err, _, skipped = d.apply('t', 'actions', "} +
						values + ", 1, " + opts +
						")\n"
						"if not ok then return tostring(err) end\n"
						"if skipped then return 'ok; ' .. table.concat(skipped, '; ') end\n"
						"return 'ok'";

			return run_lua(f.L, code.c_str());
		};

		/* override.d (10) beats a dynamic threshold, local.d (1) does not */
		CHECK(rspamd_dynconf_metric_masked(f.cfg, "actions", "add_header"));
		CHECK(rspamd_dynconf_metric_masked(f.cfg, "actions", "add header"));
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "actions", "greylist"));
		auto err = apply("{add_header = 8, greylist = 5}", "{lenient = true, strict = {'add_header'}}");
		CHECK(err.find("add header") != std::string::npos);
		CHECK(err.find("priority 10") != std::string::npos);
		CHECK(std::isnan(add_header->threshold));
		CHECK(apply("{greylist = 5}", "nil") == "ok");
		CHECK(greylist->threshold == doctest::Approx(5.0));
		CHECK((greylist->flags & RSPAMD_ACTION_NO_THRESHOLD) == 0);
		CHECK(greylist->priority == 3);
		CHECK(apply("{add_header = 8, greylist = 5}", "{lenient = true}").find("ok; the threshold of the action "
																			   "add header is defined with the priority 10") == 0);
		CHECK(std::isnan(add_header->threshold));
		CHECK(greylist->threshold == doctest::Approx(5.0));

		/* Whatever goes away gets the disabled action back */
		CHECK(run_lua(f.L, "return tostring(require('lua_dynconf').apply('t', 'actions', nil, 1))") == "true");
		CHECK(std::isnan(greylist->threshold));
		CHECK((greylist->flags & RSPAMD_ACTION_NO_THRESHOLD) != 0);
		CHECK(greylist->priority == 1);
		CHECK(std::isnan(add_header->threshold));
		CHECK(add_header->priority == 10);
	}

	TEST_CASE("the masked state: definitions of a higher priority than the dynamic one")
	{
		metric_fixture f;

		/* reject 0, add header 1, greylist 10; DYN_SYM_A 0, DYN_SYM_FIXED 10 */
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "actions", "reject"));
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "actions", "add_header"));
		CHECK(rspamd_dynconf_metric_masked(f.cfg, "actions", "greylist"));
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "scores", "DYN_SYM_A"));
		CHECK(rspamd_dynconf_metric_masked(f.cfg, "scores", "DYN_SYM_FIXED"));
		/* unknown entries and the `symbols` module are never masked */
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "actions", "no such action"));
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "scores", "NO_SUCH_SYMBOL"));
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "symbols", "DYN_SYM_A"));

		/* An entry that is overridden now is judged by its static definition, not by the dynamic priority */
		CHECK(f.apply("actions", "{reject = 20}") == "ok");
		CHECK(f.action("reject")->priority == 3);
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "actions", "reject"));
		CHECK(f.apply("scores", "{DYN_SYM_A = 7}") == "ok");
		CHECK(!rspamd_dynconf_metric_masked(f.cfg, "scores", "DYN_SYM_A"));
	}

	TEST_CASE("a write is validated even when the stored entry has the same value")
	{
		metric_fixture f;

		/* A stored entry that override.d masks: a delivery skips it ... */
		CHECK(f.apply_lenient("actions", "{greylist = 9}")
				  .find("ok; the threshold of the action greylist is defined with the priority 10") == 0);
		CHECK(f.action("greylist")->threshold == doctest::Approx(4.0));
		CHECK(f.apply_lenient("scores", "{DYN_SYM_FIXED = 9}")
				  .find("ok; the score of the symbol DYN_SYM_FIXED is defined with the priority 10") == 0);

		/* ... and a write that names it again, with the same value, is refused (nothing differs, but the
		 * subscriber is asked: no silent success) */
		auto err = f.apply("actions", "{greylist = 9}", "{lenient = true, strict = {'greylist'}}");
		CHECK(err.find("greylist") != std::string::npos);
		CHECK(err.find("priority 10") != std::string::npos);
		err = f.apply("scores", "{DYN_SYM_FIXED = 9}", "{lenient = true, strict = {'DYN_SYM_FIXED'}}");
		CHECK(err.find("DYN_SYM_FIXED") != std::string::npos);
		CHECK(err.find("priority 10") != std::string::npos);
		CHECK(f.score("DYN_SYM_FIXED") == doctest::Approx(3.0));

		/* A write that leaves the entry alone is fine, the entry is still reported */
		CHECK(f.apply("scores", "{DYN_SYM_FIXED = 9}", "{lenient = true, strict = {}}")
				  .find("ok; the score of the symbol DYN_SYM_FIXED") == 0);
	}

	TEST_CASE("a name that appears later is applied when the entry is offered again")
	{
		metric_fixture f;

		CHECK(f.apply_lenient("scores", "{DYN_SYM_A = 6, DYN_SYM_LATE = 5}") == "ok; unknown symbol DYN_SYM_LATE");
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(6.0));

		/* Nothing differs and the symbol is still unknown: skipped again, and not logged again (quiet) */
		CHECK(f.apply("scores", "{DYN_SYM_A = 6, DYN_SYM_LATE = 5}", "{lenient = true, quiet = true}") ==
			  "ok; unknown symbol DYN_SYM_LATE");

		/* The symbol is added (a map has loaded) */
		REQUIRE(rspamd_config_add_symbol(f.cfg, "DYN_SYM_LATE", 1.5, nullptr, nullptr, 0, 0, 1));
		CHECK(f.apply("scores", "{DYN_SYM_A = 6, DYN_SYM_LATE = 5}", "{lenient = true, quiet = true}") == "ok");
		CHECK(f.score("DYN_SYM_LATE") == doctest::Approx(5.0));

		/* ... and then it is restored like any other override */
		CHECK(f.apply("scores", "{DYN_SYM_A = 6}") == "ok");
		CHECK(f.score("DYN_SYM_LATE") == doctest::Approx(1.5));
	}

	/* Strict writes and lenient deliveries */

	TEST_CASE("a stale name is skipped by a delivery and refused by a write")
	{
		metric_fixture f;

		/* A delivery applies the rest and reports what it has skipped, once per name */
		CHECK(f.apply_lenient("scores", "{DYN_SYM_A = 7, NO_SUCH_SYMBOL = 5}") == "ok; unknown symbol NO_SUCH_SYMBOL");
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(7.0));
		CHECK(f.apply_lenient("actions", "{reject = 20, no_such_action = 5}") == "ok; unknown action no_such_action");
		CHECK(f.action("reject")->threshold == doctest::Approx(20.0));
		CHECK(f.apply_lenient("symbols", "{DYN_SYM_B = {enabled = false}, NO_SUCH = {enabled = false}}") ==
			  "ok; unknown symbol NO_SUCH");
		CHECK(!rspamd_symcache_get_symbol_enabled_runtime(f.cfg->cache, "DYN_SYM_B"));

		/* A write is strict about the names that it changes: the stale one stays and does not block it */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'scores', {DYN_SYM_A = 8, NO_SUCH_SYMBOL = 5}, 1,
				{lenient = true, strict = {'DYN_SYM_A'}})
			if not ok then return 'unexpected: ' .. tostring(err) end
			return 'ok'
		)lua") == "ok");
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(8.0));

		/* ... but the stale name that the write itself brings is refused */
		auto refused = run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			local ok, err = d.apply('t', 'scores', {DYN_SYM_A = 9, NO_SUCH_SYMBOL = 6}, 1,
				{lenient = true, strict = {'NO_SUCH_SYMBOL'}})
			if ok then return 'accepted' end
			return tostring(err)
		)lua");
		CHECK(refused.find("unknown symbol NO_SUCH_SYMBOL") != std::string::npos);
		CHECK(f.score("DYN_SYM_A") == doctest::Approx(8.0));

		/* The registry reports what the last update has skipped in the dump */
		CHECK(run_lua(f.L, R"lua(
			local d = require "lua_dynconf"
			assert(d.apply('t', 'scores', {DYN_SYM_A = 9, NO_SUCH_SYMBOL = 7}, 1, {lenient = true}))
			local skipped = d.dump({module = 'scores'}).modules.scores.skipped
			if not skipped or skipped[1] ~= 'unknown symbol NO_SUCH_SYMBOL' then return 'no skipped in the dump' end
			assert(d.apply('t', 'scores', {DYN_SYM_A = 9}, 1, {lenient = true}))
			if d.dump({module = 'scores'}).modules.scores.skipped ~= nil then return 'skipped is not cleared' end
			return 'ok'
		)lua") == "ok");
	}
}

#endif
