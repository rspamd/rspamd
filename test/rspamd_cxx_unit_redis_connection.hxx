/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0.
 */
#ifndef RSPAMD_CXX_UNIT_REDIS_CONNECTION_HXX
#define RSPAMD_CXX_UNIT_REDIS_CONNECTION_HXX

#include "lua/lua_common.h"
#include "libserver/redis_pool.h"
#include <memory>
#include <string>
#include <string_view>

namespace rspamd_redis_connection_test {

struct fixture {
	std::unique_ptr<lua_State, decltype(&lua_close)> state{luaL_newstate(), lua_close};
	lua_State *L = state.get();
	rspamd_redis_connection_opts opts{};

	fixture()
	{
		REQUIRE(L != nullptr);
		luaL_openlibs(L);
	}

	void load(const char *source)
	{
		REQUIRE(luaL_dostring(L, source) == 0);
	}

	void parse(rspamd_mempool_t *pool = nullptr)
	{
		rspamd_lua_redis_parse_connection(L, -1, &opts, pool);
	}

	static auto str(const char *s) -> std::string_view
	{
		return s ? s : "";
	}
};

TEST_SUITE("redis connection configuration")
{
	TEST_CASE_FIXTURE(fixture, "legacy flat connection fields and numeric database")
	{
		load("return {username='user', password='password', db=3, ssl=true, "
			 "no_ssl_verify=false, ssl_ca='ca', ssl_ca_dir='ca-dir', "
			 "ssl_cert='cert', ssl_key='key', sni='redis.example'}");
		parse();
		CHECK(str(opts.username) == "user");
		CHECK(str(opts.password) == "password");
		CHECK(str(opts.dbname) == "3");
		CHECK(opts.tls.use_tls);
		CHECK_FALSE(opts.tls.no_ssl_verify);
		CHECK(str(opts.tls.ca_file) == "ca");
		CHECK(str(opts.tls.ca_dir) == "ca-dir");
		CHECK(str(opts.tls.cert_file) == "cert");
		CHECK(str(opts.tls.key_file) == "key");
		CHECK(str(opts.tls.sni) == "redis.example");
	}

	TEST_CASE_FIXTURE(fixture, "nested connection is authoritative over request fields")
	{
		load("return {ssl=false, no_ssl_verify=true, username='outer', "
			 "password='outer', dbname='9', ssl_ca='wrong', connection={"
			 "ssl=true, no_ssl_verify=false, password='inner', db='2', ssl_ca='right'}}");
		parse();
		CHECK(opts.username == nullptr);
		CHECK(str(opts.password) == "inner");
		CHECK(str(opts.dbname) == "2");
		CHECK(opts.tls.use_tls);
		CHECK_FALSE(opts.tls.no_ssl_verify);
		CHECK(str(opts.tls.ca_file) == "right");
	}

	TEST_CASE_FIXTURE(fixture, "dbname takes precedence over db")
	{
		load("return {connection={dbname='4', db='5'}}");
		parse();
		CHECK(str(opts.dbname) == "4");
		CHECK_FALSE(opts.tls.use_tls);
	}

	TEST_CASE_FIXTURE(fixture, "missing settings do not retain earlier credentials or TLS")
	{
		load("return {password='password', ssl=true, no_ssl_verify=true}");
		parse();
		lua_settop(L, 0);
		load("return {}");
		parse();
		CHECK(opts.username == nullptr);
		CHECK(opts.password == nullptr);
		CHECK(opts.dbname == nullptr);
		CHECK_FALSE(opts.tls.use_tls);
		CHECK_FALSE(opts.tls.no_ssl_verify);
		CHECK(opts.tls.ca_file == nullptr);
	}

	TEST_CASE_FIXTURE(fixture, "borrowed generated strings remain rooted during decoding")
	{
		load("return setmetatable({}, {__index=function(_, k) "
			 "if k == 'connection' then return nil end "
			 "if k == 'ssl' then return true end "
			 "if k == 'no_ssl_verify' then return false end "
			 "return string.rep(k, 32) end})");
		parse();
		lua_gc(L, LUA_GCCOLLECT, 0);
		CHECK(str(opts.username).size() == 32 * std::string_view{"username"}.size());
		CHECK(str(opts.password).substr(0, 8) == "password");
		CHECK(str(opts.tls.ca_file).substr(0, 6) == "ssl_ca");
		CHECK(str(opts.tls.sni).size() == 96);
	}

	TEST_CASE_FIXTURE(fixture, "config pool owns strings after Lua state is cleared")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "redis_test", 0);
		load("return {connection={username='user', password='password', db='6', "
			 "ssl_ca='ca', ssl_ca_dir='ca-dir', ssl_cert='cert', ssl_key='key', sni='sni'}}");
		parse(pool);
		lua_settop(L, 0);
		lua_gc(L, LUA_GCCOLLECT, 0);
		state.reset();
		CHECK(str(opts.username) == "user");
		CHECK(str(opts.password) == "password");
		CHECK(str(opts.dbname) == "6");
		CHECK(str(opts.tls.ca_file) == "ca");
		CHECK(str(opts.tls.ca_dir) == "ca-dir");
		CHECK(str(opts.tls.cert_file) == "cert");
		CHECK(str(opts.tls.key_file) == "key");
		CHECK(str(opts.tls.sni) == "sni");
		rspamd_mempool_delete(pool);
	}

	TEST_CASE_FIXTURE(fixture, "invalid nested connection raises instead of falling back")
	{
		for (const auto *value: {"false", "'invalid'", "42"}) {
			lua_settop(L, 0);
			lua_pushcfunction(L, +[](lua_State *state) -> int {
				rspamd_redis_connection_opts connection{};
				rspamd_lua_redis_parse_connection(state, 1, &connection, nullptr);
				return 0; });
			std::string source = "return {ssl=true, connection=";
			source += value;
			source += "}";
			load(source.c_str());
			CHECK(lua_pcall(L, 1, 0, 0) != 0);
		}
	}
}

}// namespace rspamd_redis_connection_test
#endif
