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
LUA_FUNCTION_DEF (dns_resolver, resolve_mx);
LUA_FUNCTION_DEF (dns_resolver, resolve);

static const struct luaL_reg    dns_resolverlib_f[] = {
	LUA_INTERFACE_DEF (dns_resolver, init),
	{NULL, NULL}
};

static const struct luaL_reg    dns_resolverlib_m[] = {
	LUA_INTERFACE_DEF (dns_resolver, resolve_a),
	LUA_INTERFACE_DEF (dns_resolver, resolve_ptr),
	LUA_INTERFACE_DEF (dns_resolver, resolve_txt),
	LUA_INTERFACE_DEF (dns_resolver, resolve_mx),
	LUA_INTERFACE_DEF (dns_resolver, resolve),
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

static int
lua_dns_get_type (lua_State *L, int argno)
{
	int type;

	lua_pushvalue (L, argno);
	lua_gettable (L, lua_upvalueindex (1));

	type = lua_tonumber (L, -1);
	lua_pop (L, 1);
	if (type == 0) {
		rspamd_lua_typerror (L, argno, "dns_request_type");
	}
	return type;
}

static void
lua_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct lua_dns_cbdata   	   *cd = arg;
	gint                            i = 0;
	struct rspamd_dns_resolver    **presolver;
	struct rdns_reply_entry        *elt;
	rspamd_inet_addr_t               addr;

	lua_rawgeti (cd->L, LUA_REGISTRYINDEX, cd->cbref);
	presolver = lua_newuserdata (cd->L, sizeof (gpointer));
	lua_setclass (cd->L, "rspamd{resolver}", -1);

	*presolver = cd->resolver;
	lua_pushstring (cd->L, cd->to_resolve);

	/*
	 * XXX: rework to handle different request types
	 */
	if (reply->code == RDNS_RC_NOERROR) {
		lua_newtable (cd->L);
		LL_FOREACH (reply->entries, elt) {
			switch (elt->type) {
			case RDNS_REQUEST_A:
				addr.af = AF_INET;
				addr.slen = sizeof (addr.addr.s4);
				memcpy (&addr.addr.s4.sin_addr, &elt->content.a.addr,
						sizeof (addr.addr.s4.sin_addr));
				lua_ip_push (cd->L, &addr);
				lua_rawseti (cd->L, -2, ++i);
				break;
			case RDNS_REQUEST_AAAA:
				addr.af = AF_INET6;
				addr.slen = sizeof (addr.addr.s6);
				memcpy (&addr.addr.s6.sin6_addr, &elt->content.aaa.addr,
						sizeof (addr.addr.s6.sin6_addr));
				lua_ip_push (cd->L, &addr);
				lua_rawseti (cd->L, -2, ++i);
				break;
			case RDNS_REQUEST_PTR:
				lua_pushstring (cd->L, elt->content.ptr.name);
				lua_rawseti (cd->L, -2, ++i);
				break;
			case RDNS_REQUEST_TXT:
			case RDNS_REQUEST_SPF:
				lua_pushstring (cd->L, elt->content.txt.data);
				lua_rawseti (cd->L, -2, ++i);
				break;
			case RDNS_REQUEST_MX:
				/* mx['name'], mx['priority'] */
				lua_newtable (cd->L);
				lua_set_table_index (cd->L, "name", elt->content.mx.name);
				lua_pushstring (cd->L, "priority");
				lua_pushnumber (cd->L, elt->content.mx.priority);
				lua_settable (cd->L, -3);

				lua_rawseti (cd->L, -2, ++i);
				break;
			}
		}
		lua_pushnil (cd->L);
	}
	else {
		lua_pushnil (cd->L);
		lua_pushstring (cd->L, rdns_strerror (reply->code));
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
		resolver = dns_resolver_init (rspamd_main->logger, base, cfg);
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
lua_dns_resolver_resolve_common (lua_State *L, struct rspamd_dns_resolver *resolver,
		enum rdns_request_type type, int first)
{
	struct rspamd_async_session					*session, **psession;
	rspamd_mempool_t								*pool, **ppool;
	const gchar									*to_resolve;
	struct lua_dns_cbdata						*cbdata;

	/* Check arguments */
	psession = luaL_checkudata (L, first, "rspamd{session}");
	luaL_argcheck (L, psession != NULL, first, "'session' expected");
	session = psession ? *(psession) : NULL;
	ppool = luaL_checkudata (L, first + 1, "rspamd{mempool}");
	luaL_argcheck (L, ppool != NULL, first + 1, "'mempool' expected");
	pool = ppool ? *(ppool) : NULL;
	to_resolve = luaL_checkstring (L, first + 2);

	if (pool != NULL && session != NULL && to_resolve != NULL && lua_isfunction (L, first + 3)) {
		cbdata = rspamd_mempool_alloc (pool, sizeof (struct lua_dns_cbdata));
		cbdata->L = L;
		cbdata->resolver = resolver;
		if (type != RDNS_REQUEST_PTR) {
			cbdata->to_resolve = rspamd_mempool_strdup (pool, to_resolve);
		}
		else {
			char *ptr_str;
			ptr_str = rdns_generate_ptr_from_str (to_resolve);
			if (ptr_str == NULL) {
				msg_err ("wrong resolve string to PTR request: %s", to_resolve);
				lua_pushnil (L);
				return 1;
			}
			cbdata->to_resolve = rspamd_mempool_strdup (pool, ptr_str);
			free (ptr_str);
		}
		lua_pushvalue (L, first + 3);
		cbdata->cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		if (lua_gettop (L) > first + 3) {
			cbdata->user_str = lua_tostring (L, first + 4);
		}
		else {
			cbdata->user_str = NULL;
		}
		make_dns_request (resolver, session, pool, lua_dns_callback, cbdata, type, to_resolve);
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
		return lua_dns_resolver_resolve_common (L, dns_resolver, RDNS_REQUEST_A, 2);
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
		return lua_dns_resolver_resolve_common (L, dns_resolver, RDNS_REQUEST_PTR, 2);
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
		return lua_dns_resolver_resolve_common (L, dns_resolver, RDNS_REQUEST_TXT, 2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_dns_resolver_resolve_mx (lua_State *L)
{
	struct rspamd_dns_resolver					*dns_resolver = lua_check_dns_resolver (L);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L, dns_resolver, RDNS_REQUEST_MX, 2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_dns_resolver_resolve (lua_State *L)
{
	struct rspamd_dns_resolver					*dns_resolver = lua_check_dns_resolver (L);
	int type;

	type = lua_dns_get_type (L, 2);

	if (dns_resolver && type != 0) {
		return lua_dns_resolver_resolve_common (L, dns_resolver, type, 3);
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

	{
		LUA_ENUM(L, RDNS_REQUEST_A, RDNS_REQUEST_A);
		LUA_ENUM(L, RDNS_REQUEST_PTR, RDNS_REQUEST_PTR);
		LUA_ENUM(L, RDNS_REQUEST_MX, RDNS_REQUEST_MX);
		LUA_ENUM(L, RDNS_REQUEST_TXT, RDNS_REQUEST_TXT);
		LUA_ENUM(L, RDNS_REQUEST_SRV, RDNS_REQUEST_SRV);
		LUA_ENUM(L, RDNS_REQUEST_SPF, RDNS_REQUEST_SRV);
		LUA_ENUM(L, RDNS_REQUEST_AAA, RDNS_REQUEST_SRV);
	}

	luaL_register (L, NULL, dns_resolverlib_m);
	luaL_register (L, "rspamd_resolver", dns_resolverlib_f);

	lua_pop (L, 1);                      /* remove metatable from stack */
	return 1;	
}
