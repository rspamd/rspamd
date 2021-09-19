/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "lua_common.h"
#include "lua_thread_pool.h"
#include "utlist.h"


/***
 * @module rspamd_resolver
 * This module allows to resolve DNS names from LUA code. All resolving is executed
 * asynchronously. Here is an example of name resolution:
 * @example
local function symbol_callback(task)
	local host = 'example.com'

	local function dns_cb(resolver, to_resolve, results, err, _, authenticated)
		if not results then
			rspamd_logger.infox('DNS resolving of %1 failed: %2', host, err)
			return
		end
		for _,r in ipairs(results) do
			-- r is of type rspamd{ip} here, but it can be converted to string
			rspamd_logger.infox('Resolved %1 to %2', host, tostring(r))
		end
	end

	task:get_resolver():resolve_a({task = task, name = host, callback = dns_cb})
end
 */

static const gchar *M = "rspamd lua dns resolver";

/* Lua bindings */
LUA_FUNCTION_DEF (dns_resolver, init);
LUA_FUNCTION_DEF (dns_resolver, resolve_a);
LUA_FUNCTION_DEF (dns_resolver, resolve_ptr);
LUA_FUNCTION_DEF (dns_resolver, resolve_txt);
LUA_FUNCTION_DEF (dns_resolver, resolve_mx);
LUA_FUNCTION_DEF (dns_resolver, resolve_ns);
LUA_FUNCTION_DEF (dns_resolver, resolve);
LUA_FUNCTION_DEF (dns_resolver, idna_convert_utf8);

void lua_push_dns_reply (lua_State *L, const struct rdns_reply *reply);

static const struct luaL_reg dns_resolverlib_f[] = {
	LUA_INTERFACE_DEF (dns_resolver, init),
	{NULL, NULL}
};

static const struct luaL_reg dns_resolverlib_m[] = {
	LUA_INTERFACE_DEF (dns_resolver, resolve_a),
	LUA_INTERFACE_DEF (dns_resolver, resolve_ptr),
	LUA_INTERFACE_DEF (dns_resolver, resolve_txt),
	LUA_INTERFACE_DEF (dns_resolver, resolve_mx),
	LUA_INTERFACE_DEF (dns_resolver, resolve_ns),
	LUA_INTERFACE_DEF (dns_resolver, resolve),
	LUA_INTERFACE_DEF (dns_resolver, idna_convert_utf8),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

struct rspamd_dns_resolver *
lua_check_dns_resolver (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{resolver}");
	luaL_argcheck (L, ud != NULL, pos, "'resolver' expected");
	return ud ? *((struct rspamd_dns_resolver **)ud) : NULL;
}

struct lua_dns_cbdata {
	struct rspamd_task *task;
	rspamd_mempool_t *pool;
	struct rspamd_dns_resolver *resolver;
	gint cbref;
	gchar *to_resolve;
	gchar *user_str;
	struct rspamd_symcache_item *item;
	struct rspamd_async_session *s;
};

static int
lua_dns_get_type (lua_State *L, int argno)
{
	int type = RDNS_REQUEST_A;
	const gchar *strtype;

	if (lua_type (L, argno) != LUA_TSTRING) {
		lua_pushvalue (L, argno);
		lua_gettable (L, lua_upvalueindex (1));

		type = lua_tonumber (L, -1);
		lua_pop (L, 1);
		if (type == 0) {
			rspamd_lua_typerror (L, argno, "dns_request_type");
		}
	}
	else {
		strtype = lua_tostring (L, argno);

		if (g_ascii_strcasecmp (strtype, "a") == 0) {
			type = RDNS_REQUEST_A;
		}
		else if (g_ascii_strcasecmp (strtype, "aaaa") == 0) {
			type = RDNS_REQUEST_AAAA;
		}
		else if (g_ascii_strcasecmp (strtype, "mx") == 0) {
			type = RDNS_REQUEST_MX;
		}
		else if (g_ascii_strcasecmp (strtype, "txt") == 0) {
			type = RDNS_REQUEST_TXT;
		}
		else if (g_ascii_strcasecmp (strtype, "ptr") == 0) {
			type = RDNS_REQUEST_PTR;
		}
		else if (g_ascii_strcasecmp (strtype, "soa") == 0) {
			type = RDNS_REQUEST_SOA;
		}
		else {
			msg_err ("bad DNS type: %s", strtype);
		}
	}

	return type;
}

static void
lua_dns_resolver_callback (struct rdns_reply *reply, gpointer arg)
{
	struct lua_dns_cbdata *cd = arg;
	struct rspamd_dns_resolver **presolver;
	lua_State *L;
	struct lua_callback_state cbs;
	rspamd_mempool_t *pool;
	gint err_idx;

	pool = cd->pool;
	lua_thread_pool_prepare_callback (cd->resolver->cfg->lua_thread_pool, &cbs);
	L = cbs.L;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cd->cbref);

	presolver = lua_newuserdata (L, sizeof (gpointer));
	rspamd_lua_setclass (L, "rspamd{resolver}", -1);

	*presolver = cd->resolver;
	lua_pushstring (L, cd->to_resolve);

	lua_push_dns_reply (L, reply);

	/*
	 * 1 - resolver
	 * 2 - to_resolve
	 * 3 - entries | nil
	 * 4 - error | nil
	 * 5 - user_str
	 * 6 - reply->authenticated
	 * 7 - server
	 */
	if (reply->code != RDNS_RC_NOERROR) {
		lua_pushnil (L);
		lua_pushstring (L, rdns_strerror (reply->code));
	}
	if (cd->user_str != NULL) {
		lua_pushstring (L, cd->user_str);
	}
	else {
		lua_pushnil (L);
	}

	lua_pushboolean (L, reply->authenticated);

	const gchar *servname = rdns_request_get_server (reply->request);

	if (servname) {
		lua_pushstring (L, servname);
	}
	else {
		lua_pushnil (L);
	}

	if (cd->item) {
		/* We also need to restore the item in case there are some chains */
		rspamd_symcache_set_cur_item (cd->task, cd->item);
	}

	if (lua_pcall (L, 7, 0, err_idx) != 0) {
		msg_err_pool_check ("call to dns callback failed: %s",
				lua_tostring (L, -1));
	}

	lua_settop (L, err_idx - 1);

	/* Unref function */
	luaL_unref (L, LUA_REGISTRYINDEX, cd->cbref);
	lua_thread_pool_restore_callback (&cbs);

	if (cd->item) {
		rspamd_symcache_item_async_dec_check (cd->task, cd->item, M);
	}

	if (!cd->pool) {
		g_free (cd->to_resolve);
		g_free (cd->user_str);
		g_free (cd);
	}
}

void
lua_push_dns_reply (lua_State *L, const struct rdns_reply *reply)
{
	gint i = 0, naddrs = 0;
	struct rdns_reply_entry *elt;
	rspamd_inet_addr_t *addr;

	if (reply->code == RDNS_RC_NOERROR) {
		LL_FOREACH (reply->entries, elt) {
			naddrs ++;
		}

		lua_createtable (L, naddrs, 0);

		LL_FOREACH (reply->entries, elt)
		{
			switch (elt->type) {
			case RDNS_REQUEST_A:
				addr = rspamd_inet_address_new (AF_INET, &elt->content.a.addr);
				rspamd_lua_ip_push (L, addr);
				rspamd_inet_address_free (addr);
				lua_rawseti (L, -2, ++i);
				break;
			case RDNS_REQUEST_AAAA:
				addr = rspamd_inet_address_new (AF_INET6, &elt->content.aaa.addr);
				rspamd_lua_ip_push (L, addr);
				rspamd_inet_address_free (addr);
				lua_rawseti (L, -2, ++i);
				break;
			case RDNS_REQUEST_NS:
				lua_pushstring (L, elt->content.ns.name);
				lua_rawseti (L, -2, ++i);
				break;
			case RDNS_REQUEST_PTR:
				lua_pushstring (L, elt->content.ptr.name);
				lua_rawseti (L, -2, ++i);
				break;
			case RDNS_REQUEST_TXT:
			case RDNS_REQUEST_SPF:
				lua_pushstring (L, elt->content.txt.data);
				lua_rawseti (L, -2, ++i);
				break;
			case RDNS_REQUEST_MX:
				/* mx['name'], mx['priority'] */
				lua_createtable (L, 0, 2);
				rspamd_lua_table_set (L, "name", elt->content.mx.name);
				lua_pushstring (L, "priority");
				lua_pushinteger (L, elt->content.mx.priority);
				lua_settable (L, -3);

				lua_rawseti (L, -2, ++i);
				break;
			case RDNS_REQUEST_SOA:
				lua_createtable (L, 0, 7);
				rspamd_lua_table_set (L, "ns", elt->content.soa.mname);
				rspamd_lua_table_set (L, "contact", elt->content.soa.admin);
				lua_pushstring (L, "serial");
				lua_pushinteger (L, elt->content.soa.serial);
				lua_settable (L, -3);
				lua_pushstring (L, "refresh");
				lua_pushinteger (L, elt->content.soa.refresh);
				lua_settable (L, -3);
				lua_pushstring (L, "retry");
				lua_pushinteger (L, elt->content.soa.retry);
				lua_settable (L, -3);
				lua_pushstring (L, "expiry");
				lua_pushinteger (L, elt->content.soa.expire);
				lua_settable (L, -3);
				/* Negative TTL */
				lua_pushstring (L, "nx");
				lua_pushinteger (L, elt->content.soa.minimum);
				lua_settable (L, -3);

				lua_rawseti (L, -2, ++i);
				break;
			default:
				continue;
			}
		}
		lua_pushnil (L);
	}
}

/***
 * @function rspamd_resolver.init(ev_base, config)
 * @param {event_base} ev_base event base used for asynchronous events
 * @param {rspamd_config} config rspamd configuration parameters
 * @return {rspamd_resolver} new resolver object associated with the specified base
 */
static int
lua_dns_resolver_init (lua_State *L)
{
	struct rspamd_dns_resolver *resolver, **presolver;
	struct rspamd_config *cfg, **pcfg;
	struct ev_loop *base, **pbase;

	/* Check args */
	pbase = rspamd_lua_check_udata (L, 1, "rspamd{ev_base}");
	luaL_argcheck (L, pbase != NULL, 1, "'ev_base' expected");
	base = pbase ? *(pbase) : NULL;
	pcfg = rspamd_lua_check_udata (L, 2, "rspamd{config}");
	luaL_argcheck (L, pcfg != NULL,	 2, "'config' expected");
	cfg = pcfg ? *(pcfg) : NULL;

	if (base != NULL && cfg != NULL) {
		resolver = rspamd_dns_resolver_init (NULL, base, cfg);
		if (resolver) {
			presolver = lua_newuserdata (L, sizeof (gpointer));
			rspamd_lua_setclass (L, "rspamd{resolver}", -1);
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
lua_dns_resolver_resolve_common (lua_State *L,
	struct rspamd_dns_resolver *resolver,
	enum rdns_request_type type,
	int first)
{
	LUA_TRACE_POINT;
	struct rspamd_async_session *session = NULL;
	rspamd_mempool_t *pool = NULL;
	const gchar *to_resolve = NULL, *user_str = NULL;
	struct lua_dns_cbdata *cbdata;
	gint cbref = -1, ret;
	struct rspamd_task *task = NULL;
	GError *err = NULL;
	gboolean forced = FALSE;
	struct rspamd_symcache_item *item = NULL;

	/* Check arguments */
	if (!rspamd_lua_parse_table_arguments (L, first, &err,
			RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
			"session=U{session};mempool=U{mempool};*name=S;*callback=F;"
			"option=S;task=U{task};forced=B",
			&session, &pool, &to_resolve, &cbref, &user_str, &task, &forced)) {

		if (err) {
			ret = luaL_error (L, "invalid arguments: %s", err->message);
			g_error_free (err);

			return ret;
		}

		return luaL_error (L, "invalid arguments");
	}

	if (task) {
		pool = task->task_pool;
		session = task->s;
		item = rspamd_symcache_get_cur_item (task);
	}

	if (to_resolve != NULL) {
		if (pool != NULL) {
			cbdata = rspamd_mempool_alloc0 (pool, sizeof (struct lua_dns_cbdata));
			cbdata->user_str = rspamd_mempool_strdup (pool, user_str);

			if (type != RDNS_REQUEST_PTR) {
				cbdata->to_resolve = rspamd_mempool_strdup (pool, to_resolve);
			}
			else {
				char *ptr_str;

				ptr_str = rdns_generate_ptr_from_str (to_resolve);

				if (ptr_str == NULL) {
					msg_err_task_check ("wrong resolve string to PTR request: %s",
							to_resolve);
					goto err;
				}

				cbdata->to_resolve = rspamd_mempool_strdup (pool, ptr_str);
				to_resolve = cbdata->to_resolve;
				free (ptr_str);
			}
		}
		else {
			cbdata = g_malloc0 (sizeof (struct lua_dns_cbdata));
			cbdata->user_str = user_str ? g_strdup (user_str) : NULL;

			if (type != RDNS_REQUEST_PTR) {
				cbdata->to_resolve = g_strdup (to_resolve);
			}
			else {
				char *ptr_str;

				ptr_str = rdns_generate_ptr_from_str (to_resolve);

				if (ptr_str == NULL) {
					msg_err_task_check ("wrong resolve string to PTR request: %s",
							to_resolve);
					goto err;
				}

				cbdata->to_resolve = g_strdup (ptr_str);
				free (ptr_str);
			}
		}

		cbdata->resolver = resolver;
		cbdata->cbref = cbref;
		cbdata->task = task;
		cbdata->pool = pool;

		if (task == NULL) {
			if (rspamd_dns_resolver_request (resolver,
					session,
					pool,
					lua_dns_resolver_callback,
					cbdata,
					type,
					to_resolve)) {

				lua_pushboolean (L, TRUE);

				if (session) {
					cbdata->s = session;
				}
			}
			else {
				goto err;
			}
		}
		else {
			/* Fail-safety as this function can, in theory, call
			 * lua_dns_resolver_callback without switching to the event loop
			 */
			if (item) {
				rspamd_symcache_item_async_inc (task, item, M);
			}

			if (forced) {
				ret = rspamd_dns_resolver_request_task_forced (task,
						lua_dns_resolver_callback,
						cbdata,
						type,
						to_resolve);
			} else {
				ret = rspamd_dns_resolver_request_task (task,
						lua_dns_resolver_callback,
						cbdata,
						type,
						to_resolve);
			}

			if (ret) {
				cbdata->s = session;

				if (item) {
					cbdata->item = item;
					rspamd_symcache_item_async_inc (task, item, M);
				}
				/* callback was set up */
				lua_pushboolean (L, TRUE);
			}
			else {
				if (item) {
					rspamd_symcache_item_async_dec_check (task, item, M);
				}

				goto err;
			}

			if (item) {
				rspamd_symcache_item_async_dec_check (task, item, M);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments to lua_resolve");
	}

	return 1;

err:
	/* Callback is not called in this case */
	if (cbdata->cbref != -1) {
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cbref);
	}

	if (!pool) {
		/* Free resources */
		g_free (cbdata->to_resolve);
		g_free (cbdata->user_str);
		g_free (cbdata);
	}

	lua_pushnil (L);

	return 1;
}

/***
 * @method resolver:resolve_a(table)
 * Resolve A record for a specified host.
 * Table elements:
 * * `task` - task element (preferred, required to track dependencies) -or-
 * * `session` - asynchronous session normally associated with rspamd task (`task:get_session()`)
 * * `mempool` - pool memory pool for storing intermediate data
 * * `name` - host name to resolve
 * * `callback` - callback callback function to be called upon name resolution is finished; must be of type `function (resolver, to_resolve, results, err)`
 * * `forced` - true if needed to override notmal limit for DNS requests
 * @return {boolean} `true` if DNS request has been scheduled
 */
static int
lua_dns_resolver_resolve_a (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L,
				   dns_resolver,
				   RDNS_REQUEST_A,
				   2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method resolver:resolve_ptr(table)
 * Resolve PTR record for a specified host.
 * Table elements:
 * * `task` - task element (preferred, required to track dependencies) -or-
 * * `session` - asynchronous session normally associated with rspamd task (`task:get_session()`)
 * * `mempool` - pool memory pool for storing intermediate data
 * * `name` - host name to resolve
 * * `callback` - callback callback function to be called upon name resolution is finished; must be of type `function (resolver, to_resolve, results, err)`
 * * `forced` - true if needed to override notmal limit for DNS requests
 * @return {boolean} `true` if DNS request has been scheduled
 */
static int
lua_dns_resolver_resolve_ptr (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L,
				   dns_resolver,
				   RDNS_REQUEST_PTR,
				   2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method resolver:resolve_txt(table)
 * Resolve TXT record for a specified host.
 * Table elements:
 * * `task` - task element (preferred, required to track dependencies) -or-
 * * `session` - asynchronous session normally associated with rspamd task (`task:get_session()`)
 * * `mempool` - pool memory pool for storing intermediate data
 * * `name` - host name to resolve
 * * `callback` - callback callback function to be called upon name resolution is finished; must be of type `function (resolver, to_resolve, results, err)`
 * * `forced` - true if needed to override notmal limit for DNS requests
 * @return {boolean} `true` if DNS request has been scheduled
 */
static int
lua_dns_resolver_resolve_txt (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L,
				   dns_resolver,
				   RDNS_REQUEST_TXT,
				   2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method resolver:resolve_mx(table)
 * Resolve MX record for a specified host.
 * Table elements:
 * * `task` - task element (preferred, required to track dependencies) -or-
 * * `session` - asynchronous session normally associated with rspamd task (`task:get_session()`)
 * * `mempool` - pool memory pool for storing intermediate data
 * * `name` - host name to resolve
 * * `callback` - callback callback function to be called upon name resolution is finished; must be of type `function (resolver, to_resolve, results, err)`
 * * `forced` - true if needed to override notmal limit for DNS requests
 * @return {boolean} `true` if DNS request has been scheduled
 */
static int
lua_dns_resolver_resolve_mx (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L,
				   dns_resolver,
				   RDNS_REQUEST_MX,
				   2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/***
 * @method resolver:resolve_ns(table)
 * Resolve NS records for a specified host.
 * Table elements:
 * * `task` - task element (preferred, required to track dependencies) -or-
 * * `session` - asynchronous session normally associated with rspamd task (`task:get_session()`)
 * * `mempool` - pool memory pool for storing intermediate data
 * * `name` - host name to resolve
 * * `callback` - callback callback function to be called upon name resolution is finished; must be of type `function (resolver, to_resolve, results, err)`
 * * `forced` - true if needed to override notmal limit for DNS requests
 * @return {boolean} `true` if DNS request has been scheduled
 */
static int
lua_dns_resolver_resolve_ns (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);

	if (dns_resolver) {
		return lua_dns_resolver_resolve_common (L,
				   dns_resolver,
				   RDNS_REQUEST_NS,
				   2);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/* XXX: broken currently */
static int
lua_dns_resolver_resolve (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);
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

/***
 * @method resolver:idna_convert_utf8(hostname[, pool])
 * Converts domain name from IDN (in utf8 format) to punycode
 * @return {string} new name converted
 */
static int
lua_dns_resolver_idna_convert_utf8 (lua_State *L)
{
	struct rspamd_dns_resolver *dns_resolver = lua_check_dns_resolver (L, 1);
	gsize hlen;
	guint conv_len = 0;
	const gchar *hname = luaL_checklstring (L, 2, &hlen);
	gchar *converted;
	rspamd_mempool_t *pool = rspamd_lua_check_udata_maybe (L, 3, "rspamd{mempool}");


	if (dns_resolver && hname) {
		if (!rspamd_str_has_8bit (hname, hlen)) {
			/* No 8 bit, no reasons to call idna */
			lua_pushlstring (L, hname, hlen);
		}
		else {
			converted = rspamd_dns_resolver_idna_convert_utf8 (dns_resolver, pool,
					hname, hlen, &conv_len);

			if (converted == NULL) {
				lua_pushnil (L);
			}
			else {
				lua_pushlstring (L, converted, conv_len);

				if (pool == NULL) {
					g_free (converted);
				}
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_load_dns_resolver (lua_State *L)
{
	lua_newtable (L);
	luaL_register (L, NULL, dns_resolverlib_f);

	return 1;
}

void
luaopen_dns_resolver (lua_State * L)
{

	rspamd_lua_new_class (L, "rspamd{resolver}", dns_resolverlib_m);
	{
		LUA_ENUM (L, DNS_A,	 RDNS_REQUEST_A);
		LUA_ENUM (L, DNS_PTR, RDNS_REQUEST_PTR);
		LUA_ENUM (L, DNS_MX,	RDNS_REQUEST_MX);
		LUA_ENUM (L, DNS_TXT, RDNS_REQUEST_TXT);
		LUA_ENUM (L, DNS_SRV, RDNS_REQUEST_SRV);
		LUA_ENUM (L, DNS_SPF, RDNS_REQUEST_SPF);
		LUA_ENUM (L, DNS_AAAA, RDNS_REQUEST_AAAA);
		LUA_ENUM (L, DNS_SOA, RDNS_REQUEST_SOA);
	}

	lua_pop (L, 1);

	rspamd_lua_add_preload (L, "rspamd_resolver", lua_load_dns_resolver);
}
