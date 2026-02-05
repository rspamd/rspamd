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
/*
 * Rspamd fuzzy storage server: ratelimits
 */

#include "config.h"

#include "fuzzy_storage_internal.h"

#include "maps/map_helpers.h"
#include "rspamd_control.h"
#include "lua/lua_common.h"
#include "contrib/uthash/utlist.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

enum rspamd_ratelimit_check_result
rspamd_fuzzy_check_ratelimit_bucket(struct rspamd_fuzzy_storage_ctx *ctx,
									rspamd_inet_addr_t *addr,
									ev_tstamp timestamp,
									struct rspamd_leaky_bucket_elt *elt,
									enum rspamd_ratelimit_check_policy policy,
									double max_burst, double max_rate)
{
	gboolean ratelimited = FALSE, new_ratelimit = FALSE;

	/* Nothing to check */
	if (isnan(max_burst) || isnan(max_rate)) {
		return ratelimit_pass;
	}

	if (isnan(elt->cur)) {
		/* There is an issue with the previous logic: the TTL is updated each time
		 * we see that new bucket. Hence, we need to check the `last` and act accordingly
		 */
		if (elt->last < timestamp && timestamp - elt->last >= ctx->leaky_bucket_ttl) {
			/*
			 * We reset bucket to it's 90% capacity to allow some requests
			 * This should cope with the issue when we block an IP network for some burst and never unblock it
			 */
			elt->cur = max_burst * 0.9;
			elt->last = timestamp;
		}
		else {
			ratelimited = TRUE;
		}
	}
	else {
		/* Update bucket: leak some elements */
		if (elt->last < timestamp) {
			elt->cur -= max_rate * (timestamp - elt->last);
			elt->last = timestamp;

			if (elt->cur < 0) {
				elt->cur = 0;
			}
		}
		else {
			elt->last = timestamp;
		}

		/* Check the bucket */
		if (elt->cur >= max_burst) {

			if (policy == ratelimit_policy_permanent) {
				elt->cur = NAN;
			}
			new_ratelimit = TRUE;
			ratelimited = TRUE;
		}
		else {
			elt->cur++; /* Allow one more request */
		}
	}

	/* Note: Caller is responsible for calling the ratelimit handlers with
	 * proper context (new vs existing, bucket info, session info, etc.)
	 */

	if (new_ratelimit) {
		return ratelimit_new;
	}

	return ratelimited ? ratelimit_existing : ratelimit_pass;
}

gboolean
rspamd_fuzzy_check_ratelimit(struct rspamd_fuzzy_storage_ctx *ctx,
							 rspamd_inet_addr_t *addr,
							 struct rspamd_worker *worker,
							 ev_tstamp timestamp)
{
	rspamd_inet_addr_t *masked;
	struct rspamd_leaky_bucket_elt *elt;

	if (!addr) {
		return TRUE;
	}

	if (ctx->ratelimit_whitelist != NULL) {
		if (rspamd_match_radix_map_addr(ctx->ratelimit_whitelist,
										addr) != NULL) {
			return TRUE;
		}
	}

	/* Skip ratelimit for local addresses */
	if (rspamd_inet_address_is_local(addr)) {
		return TRUE;
	}

	masked = rspamd_inet_address_copy(addr, NULL);

	if (rspamd_inet_address_get_af(masked) == AF_INET) {
		rspamd_inet_address_apply_mask(masked,
									   MIN(ctx->leaky_bucket_mask, 32));
	}
	else {
		/* Must be at least /64 */
		rspamd_inet_address_apply_mask(masked,
									   MIN(MAX(ctx->leaky_bucket_mask * 4, 64), 128));
	}

	elt = rspamd_lru_hash_lookup(ctx->ratelimit_buckets, masked,
								 (time_t) timestamp);

	if (elt) {
		enum rspamd_ratelimit_check_result res = rspamd_fuzzy_check_ratelimit_bucket(ctx, addr,
																					 timestamp, elt,
																					 ratelimit_policy_permanent,
																					 ctx->leaky_bucket_burst,
																					 ctx->leaky_bucket_rate);

		if (res == ratelimit_new) {
			msg_info("ratelimiting %s (%s), %.1f max elts",
					 rspamd_inet_address_to_string(addr),
					 rspamd_inet_address_to_string(masked),
					 ctx->leaky_bucket_burst);

			struct rspamd_srv_command srv_cmd;

			srv_cmd.type = RSPAMD_SRV_FUZZY_BLOCKED;
			srv_cmd.cmd.fuzzy_blocked.af = rspamd_inet_address_get_af(masked);

			if (srv_cmd.cmd.fuzzy_blocked.af == AF_INET || srv_cmd.cmd.fuzzy_blocked.af == AF_INET6) {
				socklen_t slen;
				struct sockaddr *sa = rspamd_inet_address_get_sa(masked, &slen);

				if (slen <= sizeof(srv_cmd.cmd.fuzzy_blocked.addr)) {
					memcpy(&srv_cmd.cmd.fuzzy_blocked.addr, sa, slen);
					msg_debug("propagating blocked address to other workers");
					rspamd_srv_send_command(worker, ctx->event_loop, &srv_cmd, -1, NULL, NULL);
				}
				else {
					msg_err("bad address length: %d, expected to be %d",
							(int) slen, (int) sizeof(srv_cmd.cmd.fuzzy_blocked.addr));
				}
			}

			if (ctx->lua_blacklist_handlers) {
				struct rspamd_ratelimit_callback_ctx cb_ctx = {
					.addr = addr,
					.reason = "ratelimit",
					.type = RATELIMIT_EVENT_NEW,
					.bucket = elt,
					.max_burst = ctx->leaky_bucket_burst,
					.max_rate = ctx->leaky_bucket_rate,
					.session = NULL,
				};
				rspamd_fuzzy_call_ratelimit_handlers(ctx, &cb_ctx);
			}
		}
		else if (res == ratelimit_existing) {
			if (ctx->lua_blacklist_handlers) {
				struct rspamd_ratelimit_callback_ctx cb_ctx = {
					.addr = addr,
					.reason = "ratelimit",
					.type = RATELIMIT_EVENT_EXISTING,
					.bucket = elt,
					.max_burst = ctx->leaky_bucket_burst,
					.max_rate = ctx->leaky_bucket_rate,
					.session = NULL,
				};
				rspamd_fuzzy_call_ratelimit_handlers(ctx, &cb_ctx);
			}
		}

		rspamd_inet_address_free(masked);

		return res == ratelimit_pass;
	}
	else {
		/* New bucket */
		elt = g_malloc(sizeof(*elt));
		elt->addr = masked; /* transfer ownership */
		elt->cur = 1;
		elt->last = timestamp;

		rspamd_lru_hash_insert(ctx->ratelimit_buckets,
							   masked,
							   elt,
							   timestamp,
							   ctx->leaky_bucket_ttl);
	}

	return TRUE;
}

static void
rspamd_fuzzy_bucket_info_tolua(lua_State *L,
							   const struct rspamd_ratelimit_callback_ctx *cb_ctx)
{
	if (!cb_ctx->bucket) {
		lua_pushnil(L);
		return;
	}

	lua_createtable(L, 0, 6);

	/* bucket_level - current fill level (nil if permanently blocked) */
	if (isnan(cb_ctx->bucket->cur)) {
		lua_pushnil(L);
		lua_setfield(L, -2, "bucket_level");
		lua_pushboolean(L, TRUE);
		lua_setfield(L, -2, "is_permanent");
	}
	else {
		lua_pushnumber(L, cb_ctx->bucket->cur);
		lua_setfield(L, -2, "bucket_level");
		lua_pushboolean(L, FALSE);
		lua_setfield(L, -2, "is_permanent");
	}

	/* max_burst */
	if (!isnan(cb_ctx->max_burst)) {
		lua_pushnumber(L, cb_ctx->max_burst);
		lua_setfield(L, -2, "max_burst");
	}

	/* max_rate */
	if (!isnan(cb_ctx->max_rate)) {
		lua_pushnumber(L, cb_ctx->max_rate);
		lua_setfield(L, -2, "max_rate");
	}

	/* exceeded_by - how much over the limit */
	if (!isnan(cb_ctx->bucket->cur) && !isnan(cb_ctx->max_burst) &&
		cb_ctx->bucket->cur > cb_ctx->max_burst) {
		lua_pushnumber(L, cb_ctx->bucket->cur - cb_ctx->max_burst);
		lua_setfield(L, -2, "exceeded_by");
	}

	/* last_seen */
	lua_pushnumber(L, cb_ctx->bucket->last);
	lua_setfield(L, -2, "last_seen");
}

static void
rspamd_fuzzy_ratelimit_extensions_tolua(lua_State *L,
										const struct rspamd_ratelimit_callback_ctx *cb_ctx)
{
	struct rspamd_fuzzy_cmd_extension *ext;
	rspamd_inet_addr_t *addr;

	lua_createtable(L, 0, 2);

	if (!cb_ctx->session || !cb_ctx->session->extensions) {
		return;
	}

	LL_FOREACH(cb_ctx->session->extensions, ext)
	{
		switch (ext->ext) {
		case RSPAMD_FUZZY_EXT_SOURCE_DOMAIN:
			lua_pushlstring(L, (const char *) ext->payload, ext->length);
			lua_setfield(L, -2, "domain");
			break;
		case RSPAMD_FUZZY_EXT_SOURCE_IP4:
			addr = rspamd_inet_address_new(AF_INET, ext->payload);
			rspamd_lua_ip_push(L, addr);
			rspamd_inet_address_free(addr);
			lua_setfield(L, -2, "source_ip");
			break;
		case RSPAMD_FUZZY_EXT_SOURCE_IP6:
			addr = rspamd_inet_address_new(AF_INET6, ext->payload);
			rspamd_lua_ip_push(L, addr);
			rspamd_inet_address_free(addr);
			lua_setfield(L, -2, "source_ip");
			break;
		}
	}
}

void rspamd_fuzzy_call_ratelimit_handlers(struct rspamd_fuzzy_storage_ctx *ctx,
										  const struct rspamd_ratelimit_callback_ctx *cb_ctx)
{
	if (ctx->lua_blacklist_handlers == NULL) {
		return;
	}

	struct rspamd_lua_fuzzy_script *cur;
	LL_FOREACH(ctx->lua_blacklist_handlers, cur)
	{
		lua_State *L = ctx->cfg->lua_state;
		int err_idx, ret;
		const int nargs = 6;

		lua_pushcfunction(L, &rspamd_lua_traceback);
		err_idx = lua_gettop(L);
		lua_checkstack(L, err_idx + nargs + 2);
		lua_rawgeti(L, LUA_REGISTRYINDEX, cur->cbref);

		/* Arg 1: client IP */
		rspamd_lua_ip_push(L, cb_ctx->addr);

		/* Arg 2: block reason */
		lua_pushstring(L, cb_ctx->reason);

		/* Arg 3: event type */
		switch (cb_ctx->type) {
		case RATELIMIT_EVENT_NEW:
			lua_pushliteral(L, "new");
			break;
		case RATELIMIT_EVENT_EXISTING:
			lua_pushliteral(L, "existing");
			break;
		case RATELIMIT_EVENT_BLACKLIST:
			lua_pushliteral(L, "blacklist");
			break;
		}

		/* Arg 4: ratelimit_info table (or nil) */
		rspamd_fuzzy_bucket_info_tolua(L, cb_ctx);

		/* Arg 5: digest (or nil) */
		if (cb_ctx->session) {
			(void) lua_new_text(L, (const char *) cb_ctx->session->cmd.basic.digest,
								sizeof(cb_ctx->session->cmd.basic.digest), FALSE);
		}
		else {
			lua_pushnil(L);
		}

		/* Arg 6: extensions table */
		rspamd_fuzzy_ratelimit_extensions_tolua(L, cb_ctx);

		if ((ret = lua_pcall(L, nargs, 0, err_idx)) != 0) {
			msg_err("call to lua_blacklist_cbref "
					"script failed (%d): %s",
					ret, lua_tostring(L, -1));
		}

		lua_settop(L, 0);
	}
}

void rspamd_fuzzy_maybe_call_blacklisted(struct rspamd_fuzzy_storage_ctx *ctx,
										 rspamd_inet_addr_t *addr,
										 const char *reason)
{
	if (ctx->lua_blacklist_handlers == NULL) {
		return;
	}

	struct rspamd_ratelimit_callback_ctx cb_ctx = {
		.addr = addr,
		.reason = reason,
		.type = g_strcmp0(reason, "blacklisted") == 0 ? RATELIMIT_EVENT_BLACKLIST : RATELIMIT_EVENT_EXISTING,
		.bucket = NULL,
		.max_burst = NAN,
		.max_rate = NAN,
		.session = NULL,
	};
	rspamd_fuzzy_call_ratelimit_handlers(ctx, &cb_ctx);
}

gboolean
rspamd_fuzzy_check_client(struct rspamd_fuzzy_storage_ctx *ctx,
						  rspamd_inet_addr_t *addr)
{
	if (ctx->blocked_ips != NULL) {
		if (rspamd_match_radix_map_addr(ctx->blocked_ips,
										addr) != NULL) {

			rspamd_fuzzy_maybe_call_blacklisted(ctx, addr, "blacklisted");
			return FALSE;
		}
	}

	return TRUE;
}

void fuzzy_rl_bucket_free(gpointer p)
{
	struct rspamd_leaky_bucket_elt *elt = (struct rspamd_leaky_bucket_elt *) p;

	rspamd_inet_address_free(elt->addr);
	g_free(elt);
}

ucl_object_t *
rspamd_leaky_bucket_to_ucl(struct rspamd_leaky_bucket_elt *p_elt)
{
	ucl_object_t *res;

	res = ucl_object_typed_new(UCL_OBJECT);

	ucl_object_insert_key(res, ucl_object_fromdouble(p_elt->cur), "cur", 0, false);
	ucl_object_insert_key(res, ucl_object_fromdouble(p_elt->last), "last", 0, false);

	return res;
}

void rspamd_fuzzy_maybe_load_ratelimits(struct rspamd_fuzzy_storage_ctx *ctx)
{
	char path[PATH_MAX];

	rspamd_snprintf(path, sizeof(path), "%s" G_DIR_SEPARATOR_S "fuzzy_ratelimits.ucl",
					RSPAMD_DBDIR);

	if (access(path, R_OK) != -1) {
		struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
		if (ucl_parser_add_file(parser, path)) {
			ucl_object_t *obj = ucl_parser_get_object(parser);
			int loaded = 0;

			if (ucl_object_type(obj) == UCL_ARRAY) {
				ucl_object_iter_t it = NULL;
				const ucl_object_t *cur;

				while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
					const ucl_object_t *ip, *value, *last;
					const char *ip_str;
					double limit_val, last_val;

					ip = ucl_object_find_key(cur, "ip");
					value = ucl_object_find_key(cur, "value");
					last = ucl_object_find_key(cur, "last");

					if (ip == NULL || value == NULL || last == NULL) {
						msg_err("invalid ratelimit object");
						continue;
					}

					ip_str = ucl_object_tostring(ip);
					limit_val = ucl_object_todouble(value);
					last_val = ucl_object_todouble(last);

					if (ip_str == NULL || isnan(last_val)) {
						msg_err("invalid ratelimit object");
						continue;
					}

					rspamd_inet_addr_t *addr;
					if (rspamd_parse_inet_address(&addr, ip_str, strlen(ip_str),
												  RSPAMD_INET_ADDRESS_PARSE_NO_UNIX | RSPAMD_INET_ADDRESS_PARSE_NO_PORT)) {
						struct rspamd_leaky_bucket_elt *elt = g_malloc(sizeof(*elt));

						elt->cur = limit_val;
						elt->last = last_val;
						elt->addr = addr;
						rspamd_lru_hash_insert(ctx->ratelimit_buckets, addr, elt, elt->last, ctx->leaky_bucket_ttl);
						loaded++;
					}
					else {
						msg_err("invalid ratelimit ip: %s", ip_str);
						continue;
					}
				}

				msg_info("loaded %d ratelimit objects", loaded);
			}

			ucl_object_unref(obj);
		}

		ucl_parser_free(parser);
	}
}

void rspamd_fuzzy_maybe_save_ratelimits(struct rspamd_fuzzy_storage_ctx *ctx)
{
	char path[PATH_MAX];

	rspamd_snprintf(path, sizeof(path), "%s" G_DIR_SEPARATOR_S "fuzzy_ratelimits.ucl.new",
					RSPAMD_DBDIR);
	FILE *f = fopen(path, "w");

	if (f != NULL) {
		ucl_object_t *top = ucl_object_typed_new(UCL_ARRAY);
		int it = 0;
		gpointer k, v;

		ucl_object_reserve(top, rspamd_lru_hash_size(ctx->ratelimit_buckets));

		while ((it = rspamd_lru_hash_foreach(ctx->ratelimit_buckets, it, &k, &v)) != -1) {
			ucl_object_t *cur = ucl_object_typed_new(UCL_OBJECT);
			struct rspamd_leaky_bucket_elt *elt = (struct rspamd_leaky_bucket_elt *) v;

			ucl_object_insert_key(cur, ucl_object_fromdouble(elt->cur), "value", 0, false);
			ucl_object_insert_key(cur, ucl_object_fromdouble(elt->last), "last", 0, false);
			ucl_object_insert_key(cur, ucl_object_fromstring(rspamd_inet_address_to_string(elt->addr)), "ip", 0, false);
			ucl_array_append(top, cur);
		}

		if (ucl_object_emit_full(top, UCL_EMIT_JSON_COMPACT, ucl_object_emit_file_funcs(f), NULL)) {
			char npath[PATH_MAX];

			fflush(f);
			rspamd_snprintf(npath, sizeof(npath), "%s" G_DIR_SEPARATOR_S "fuzzy_ratelimits.ucl",
							RSPAMD_DBDIR);

			if (rename(path, npath) == -1) {
				msg_warn("cannot rename %s to %s: %s", path, npath, strerror(errno));
			}
			else {
				msg_info("saved %d ratelimits in %s", rspamd_lru_hash_size(ctx->ratelimit_buckets), npath);
			}
		}
		else {
			msg_warn("cannot serialize ratelimit buckets to %s: %s", path, strerror(errno));
		}

		fclose(f);
		ucl_object_unref(top);
	}
	else {
		msg_warn("cannot save ratelimit buckets to %s: %s", path, strerror(errno));
	}
}
