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
#include "libserver/cfg_dynamic.h"
#include "lua/lua_common.h"

#include "contrib/libev/ev.h"
#include <string>

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
		   const ucl_object_t *dyn_values, void *ud, GError **err)
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
}

#endif
