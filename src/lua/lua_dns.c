/* Copyright (c) 2010-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"
#include "dns.h"

/* Public prototypes */
struct rspamd_dns_resolver *lua_check_dns_resolver (lua_State * L);
gint luaopen_dns_resolver (lua_State * L);

/* Lua bindings */
LUA_FUNCTION_DEF (dns_resolver, init);
LUA_FUNCTION_DEF (dns_resolver, resolve_a);
LUA_FUNCTION_DEF (dns_resolver, resolve_ptr);
LUA_FUNCTION_DEF (dns_resolver, resolve_txt);

static const struct luaL_reg    dns_resolverlib_f[] = {
	LUA_INTERFACE_DEF (dns_resolver, init),
	{NULL, NULL}
};

static const struct luaL_reg    dns_resolverlib_m[] = {
	LUA_INTERFACE_DEF (dns_resolver, resolve_a),
	LUA_INTERFACE_DEF (dns_resolver, resolve_ptr),
	LUA_INTERFACE_DEF (dns_resolver, resolve_txt),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

struct rspamd_dns_resolver      *
lua_check_dns_resolver (lua_State * L)
{
	void								*ud = luaL_checkudata (L, 1, "rspamd{resolver}");
	luaL_argcheck (L, ud != NULL, 1, "'resolver' expected");
	return ud ? *((struct rspamd_dns_resolver **)ud) : NULL;
}

struct lua_dns_cbdata {
	lua_State                      *L;
	struct rspamd_dns_resolver	   *resolver;
	gint							cbref;
	const gchar                    *to_resolve;
	const gchar                    *user_str;
};

static void
lua_dns_callback (struct rspamd_dns_reply *reply, gpointer arg)
{
	struct lua_dns_cbdata   	   *cd = arg;
	gint                            i = 0;
	struct rspamd_dns_resolver    **presolver;
	union rspamd_reply_element     *elt;
	GList                          *cur;

	lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->cbref);
	presolver = lua_newuserdata (cd->L, sizeof (gpointer));
	lua_setclass (cd->L, "rspamd{resolver}", -1);

	*presolver = cd->resolver;
	lua_pushstring (cd->L, cd->to_resolve);

	if (reply->code == DNS_RC_NOERROR) {
		if (reply->type == DNS_REQUEST_A) {

			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				lua_ip_push (cd->L, AF_INET, &elt->a.addr);
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);
		}
		else if (reply->type == DNS_REQUEST_AAA) {

			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				lua_ip_push (cd->L, AF_INET6, &elt->aaa.addr);
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);
		}
		else if (reply->type == DNS_REQUEST_PTR) {
			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				lua_pushstring (cd->L, elt->ptr.name);
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);

		}
		else if (reply->type == DNS_REQUEST_TXT) {
			lua_newtable (cd->L);
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				lua_pushstring (cd->L, elt->txt.data);
				lua_rawseti (cd->L, -2, ++i);
				cur = g_list_next (cur);
			}
			lua_pushnil (cd->L);

		}
		else {
			lua_pushnil (cd->L);
			lua_pushstring (cd->L, "Unknown reply type");
		}
	}
	else {
		lua_pushnil (cd->L);
		lua_pushstring (cd->L, dns_strerror (reply->code));
	}

	if (cd->user_str != NULL) {
		lua_pushstring (cd->L, cd->user_str);
	}
	else {
		lua_pushnil (cd->L);
	}

	if (lua_pcall (cd->L, 5, 0, 0) != 0) {
		msg_info ("call to dns_callback failed: %s", lua_tostring (cd->L, -1));
	}

	/* Unref function */
	luaL_unref (cd->L, LUA_REGISTRYINDEX, cd->cbref);
}

static int
lua_dns_resolver_init (lua_State *L)
{
	struct rspamd_dns_resolver					*resolver, **presolver;
	struct config_file 							*cfg, **pcfg;
	struct event_base							*base, **pbase;

	/* Check args */
	pbase = luaL_checkudata (L, 1, "rspamd{ev_base}");
	luaL_argcheck (L, pbase != NULL, 1, "'ev_base' expected");
	base = pbase ? *(pbase) : NULL;
	pcfg = luaL_checkudata (L, 2, "rspamd{config}");
	luaL_argcheck (L, pcfg != NULL, 2, "'config' expected");
	cfg = pcfg ? *(pcfg) : NULL;

	if (base != NULL && cfg != NULL) {
		resolver = dns_resolver_init (base, cfg);
		if (resolver) {
			presolver = lua_newuserdata (L, sizeof (gpointer));
			lua_setclass (L, "rspamd{resolver}", -1);
			*presolver = resolver;
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_dns_resolver_resolve_common (lua_State *L, struct rspamd_dns_resolver *resolver, enum rspamd_request_type type)
{
	struct rspamd_async_session					*session, **psession;
	memory_pool_t								*pool, **ppool;
	const gchar									*to_resolve;
	struct in_addr								 ina;
	struct lua_dns_cbdata						*cbdata;

	/* Check arguments */
	psession = luaL_checkudata (L, 2, "rspamd{session}");
	luaL_argcheck (L, psession != NULL, 2, "'session' expected");
	session = psession ? *(psession) : NULL;
	ppool = luaL_checkudata (L, 3, "rspamd{mempool}");
	luaL_argcheck (L, ppool != NULL, 3, "'mempool' expected");
	pool = ppool ? *(ppool) : NULL;
	to_resolve = luaL_checkstring (L, 4);

	if (pool != NULL && session != NULL && to_resolve != NULL && lua_isfunction (L, 5)) {
		if (type == DNS_REQUEST_PTR) {
			if (inet_aton (to_resolve, &ina) == 0) {
				msg_err ("wrong resolve string to PTR request: %s", to_resolve);
				lua_pushnil (L);
				return 1;
			}
		}
		cbdata = memory_pool_alloc (pool, sizeof (struct lua_dns_cbdata));
		cbdata->L = L;
		cbdata->resolver = resolver;
		cbdata->to_resolve = memory_pool_strdup (pool, to_resolve);
		lua_pushvalue (L, 5);
		cbdata->cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		if (lua_gettop (L) > 5) {
			cbdata->user_str = lua_tostring (L, 6);
		}
		else {
			cbdata->user_str = NULL;
		}

		if (type == DNS_REQUEST_PTR) {
			make_dns_request (resolver, session, pool, lua_dns_callback, cbdata, type, &ina);
		}
		else {
			make_dns_request (resolver, session, pool, lua_dns_callback, cbdata, type, to_resolve);
		}
		lua_pushboolean (L, TRUE);
	}
	else {
		msg_err ("invalid arguments to lua_resolve");
		lua_pushnil (L);
	}

	return 1;

}

static int
lua_dns_resolver_resolve_a (lua_State *L)
{
	struct rspamd_dns_resolver					*dns_resolver = lua_check_dns_resolver (L);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L, dns_resolver, DNS_REQUEST_A);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_dns_resolver_resolve_ptr (lua_State *L)
{
	struct rspamd_dns_resolver					*dns_resolver = lua_check_dns_resolver (L);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L, dns_resolver, DNS_REQUEST_PTR);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_dns_resolver_resolve_txt (lua_State *L)
{
	struct rspamd_dns_resolver					*dns_resolver = lua_check_dns_resolver (L);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L, dns_resolver, DNS_REQUEST_TXT);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

gint
luaopen_dns_resolver (lua_State * L)
{
	luaL_newmetatable (L, "rspamd{resolver}");
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);
	lua_settable (L, -3);

	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{resolver}");
	lua_rawset (L, -3);

	luaL_register (L, NULL, dns_resolverlib_m);
	luaL_register (L, "rspamd_resolver", dns_resolverlib_f);

	lua_pop (L, 1);                      /* remove metatable from stack */
	return 1;	
}
