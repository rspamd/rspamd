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
 * Rspamd fuzzy storage server: keys and dynamic keymaps
 */

#include "config.h"

#include "fuzzy_storage_internal.h"

#include "cfg_rcl.h"
#include "libcryptobox/cryptobox.h"
#include "libcryptobox/keypair.h"
#include "libserver/maps/map.h"
#include "lua/lua_common.h"
#include "unix-std.h"

#include <math.h>
#include <string.h>
#include <time.h>

char *
ucl_keymap_read_cb(char *chunk, int len,
				   struct map_cb_data *data, gboolean final)
{
	struct fuzzy_keymap_ucl_buf *jb, *pd;

	pd = data->prev_data;

	g_assert(pd != NULL);

	if (data->cur_data == NULL) {
		jb = g_malloc0(sizeof(*jb));
		jb->ctx = pd->ctx;
		data->cur_data = jb;
	}
	else {
		jb = data->cur_data;
	}

	if (jb->buf == NULL) {
		/* Allocate memory for buffer */
		jb->buf = rspamd_fstring_sized_new(MAX(len, 4096));
	}

	jb->buf = rspamd_fstring_append(jb->buf, chunk, len);

	return NULL;
}

void ucl_keymap_fin_cb(struct map_cb_data *data, void **target)
{
	struct fuzzy_keymap_ucl_buf *jb;
	ucl_object_t *top;
	struct ucl_parser *parser;
	struct rspamd_config *cfg;

	/* Now parse ucl */
	if (data->cur_data) {
		jb = data->cur_data;
		cfg = jb->ctx->cfg;
	}
	else {
		msg_err("no cur data in the map! might be a bug");
		return;
	}

	if (jb->buf->len == 0) {
		msg_err_config("no data read");

		return;
	}

	parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);

	if (!ucl_parser_add_chunk(parser, jb->buf->str, jb->buf->len)) {
		msg_err_config("cannot load ucl data: parse error %s",
					   ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return;
	}

	top = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	if (ucl_object_type(top) != UCL_ARRAY) {
		ucl_object_unref(top);
		msg_err_config("loaded ucl is not an array");
		return;
	}

	if (target) {
		*target = data->cur_data;
	}

	if (data->prev_data) {
		jb = data->prev_data;
		/* Clean prev data */
		if (jb->buf) {
			rspamd_fstring_free(jb->buf);
		}

		/* Clean the existing keys */
		struct fuzzy_key *key;
		kh_foreach_value(jb->ctx->dynamic_keys, key, {
			REF_RELEASE(key);
		});
		kh_clear(rspamd_fuzzy_keys_hash, jb->ctx->dynamic_keys);

		/* Insert new keys */
		const ucl_object_t *cur;
		ucl_object_iter_t it = NULL;
		int success = 0;

		while ((cur = ucl_object_iterate(top, &it, true)) != NULL) {
			struct fuzzy_key *nk;

			nk = fuzzy_add_keypair_from_ucl(cfg, cur, jb->ctx->dynamic_keys);

			if (nk == NULL) {
				msg_warn_config("cannot add dynamic keypair");
			}
			success++;
		}

		msg_info_config("loaded %d dynamic keypairs", success);

		g_free(jb);
	}

	ucl_object_unref(top);
}

void ucl_keymap_dtor_cb(struct map_cb_data *data)
{
	struct fuzzy_keymap_ucl_buf *jb;

	if (data->cur_data) {
		jb = data->cur_data;
		/* Clean prev data */
		if (jb->buf) {
			rspamd_fstring_free(jb->buf);
		}

		struct fuzzy_key *key;
		kh_foreach_value(jb->ctx->dynamic_keys, key, {
			REF_RELEASE(key);
		});
		/* Clear hash content but don't destroy - mempool destructor will handle it */
		kh_clear(rspamd_fuzzy_keys_hash, jb->ctx->dynamic_keys);

		g_free(jb);
	}
}

void fuzzy_key_stat_dtor(gpointer p)
{
	struct fuzzy_key_stat *st = p;

	if (st->last_ips) {
		rspamd_lru_hash_destroy(st->last_ips);
	}

	if (st->keypair) {
		rspamd_keypair_unref(st->keypair);
	}

	g_free(st);
}

void fuzzy_key_stat_unref(gpointer p)
{
	struct fuzzy_key_stat *st = p;

	REF_RELEASE(st);
}

void fuzzy_key_dtor(gpointer p)
{
	struct fuzzy_key *key = p;

	if (key) {
		if (key->key) {
			rspamd_keypair_unref(key->key);
		}

		if (key->stat) {
			REF_RELEASE(key->stat);
		}

		if (key->flags_stat) {
			kh_destroy(fuzzy_key_flag_stat, key->flags_stat);
		}

		if (key->forbidden_ids) {
			kh_destroy(fuzzy_key_ids_set, key->forbidden_ids);
		}

		if (key->rl_bucket) {
			/* TODO: save bucket stats */
			g_free(key->rl_bucket);
		}

		if (key->name) {
			g_free(key->name);
		}

		if (key->extensions) {
			ucl_object_unref(key->extensions);
		}

		g_free(key);
	}
}

void fuzzy_hash_table_dtor(khash_t(rspamd_fuzzy_keys_hash) * hash)
{
	struct fuzzy_key *key;
	kh_foreach_value(hash, key, {
		REF_RELEASE(key);
	});
	kh_destroy(rspamd_fuzzy_keys_hash, hash);
}

gboolean
fuzzy_parse_ids(rspamd_mempool_t *pool,
				const ucl_object_t *obj,
				gpointer ud,
				struct rspamd_rcl_section *section,
				GError **err)
{
	struct rspamd_rcl_struct_parser *pd = (struct rspamd_rcl_struct_parser *) ud;
	khash_t(fuzzy_key_ids_set) * target;

	target = *(khash_t(fuzzy_key_ids_set) **) ((char *) pd->user_struct + pd->offset);

	if (ucl_object_type(obj) == UCL_ARRAY) {
		const ucl_object_t *cur;
		ucl_object_iter_t it = NULL;
		uint64_t id;

		while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
			if (ucl_object_toint_safe(cur, &id)) {
				int r;

				kh_put(fuzzy_key_ids_set, target, id, &r);
			}
			else {
				return FALSE;
			}
		}

		return TRUE;
	}
	else if (ucl_object_type(obj) == UCL_INT) {
		int r;
		kh_put(fuzzy_key_ids_set, target, ucl_object_toint(obj), &r);

		return TRUE;
	}

	return FALSE;
}

struct fuzzy_key *
fuzzy_add_keypair_from_ucl(struct rspamd_config *cfg,
						   const ucl_object_t *obj,
						   khash_t(rspamd_fuzzy_keys_hash) * target)
{
	struct rspamd_cryptobox_keypair *kp = rspamd_keypair_from_ucl(obj);

	if (kp == NULL) {
		return NULL;
	}

	if (rspamd_keypair_type(kp) != RSPAMD_KEYPAIR_KEX) {
		rspamd_keypair_unref(kp);
		return NULL;
	}

	struct fuzzy_key *key = g_malloc0(sizeof(*key));
	REF_INIT_RETAIN(key, fuzzy_key_dtor);
	key->key = kp;
	struct fuzzy_key_stat *keystat = g_malloc0(sizeof(*keystat));
	REF_INIT_RETAIN(keystat, fuzzy_key_stat_dtor);
	/* Hash of ip -> fuzzy_key_stat */
	keystat->last_ips = rspamd_lru_hash_new_full(1024,
												 (GDestroyNotify) rspamd_inet_address_free,
												 fuzzy_key_stat_unref,
												 rspamd_inet_address_hash, rspamd_inet_address_equal);
	key->stat = keystat;
	key->flags_stat = kh_init(fuzzy_key_flag_stat);
	key->burst = NAN;
	key->rate = NAN;
	key->expire = NAN;
	key->rl_bucket = NULL;
	/* Allow read by default */
	key->flags = FUZZY_KEY_READ;
	/* Preallocate some space for flags */
	kh_resize(fuzzy_key_flag_stat, key->flags_stat, 8);
	const unsigned char *pk = rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_PK,
													   NULL);
	keystat->keypair = rspamd_keypair_ref(kp);
	/* We map entries by pubkey in binary form for faster lookup */
	khiter_t k;
	int r;

	k = kh_put(rspamd_fuzzy_keys_hash, target, pk, &r);

	if (r == 0) {
		msg_err("duplicate keypair found: pk=%*bs",
				32, pk);
		REF_RELEASE(key);

		return NULL;
	}
	else if (r == -1) {
		msg_err("hash insertion error: pk=%*bs",
				32, pk);
		REF_RELEASE(key);

		return NULL;
	}

	kh_val(target, k) = key;

	const ucl_object_t *extensions = rspamd_keypair_get_extensions(kp);

	if (extensions) {
		key->extensions = ucl_object_ref(extensions);
		lua_State *L = RSPAMD_LUA_CFG_STATE(cfg);
		const ucl_object_t *forbidden_ids = ucl_object_lookup(extensions, "forbidden_ids");

		if (forbidden_ids && ucl_object_type(forbidden_ids) == UCL_ARRAY) {
			key->forbidden_ids = kh_init(fuzzy_key_ids_set);
			const ucl_object_t *cur;
			ucl_object_iter_t it = NULL;

			while ((cur = ucl_object_iterate(forbidden_ids, &it, true)) != NULL) {
				if (ucl_object_type(cur) == UCL_INT || ucl_object_type(cur) == UCL_FLOAT) {
					int id = ucl_object_toint(cur);
					int ids_r;

					kh_put(fuzzy_key_ids_set, key->forbidden_ids, id, &ids_r);
				}
			}
		}

		const ucl_object_t *ratelimit = ucl_object_lookup(extensions, "ratelimit");

		static int ratelimit_lua_id = -1;

		if (ratelimit_lua_id == -1) {
			/* Load ratelimit parsing function */
			if (!rspamd_lua_require_function(L, "plugins/ratelimit", "parse_limit")) {
				msg_err_config("cannot load ratelimit parser from ratelimit plugin");
			}
			else {
				ratelimit_lua_id = luaL_ref(L, LUA_REGISTRYINDEX);
			}
		}

		if (ratelimit && ratelimit_lua_id != -1) {
			lua_rawgeti(L, LUA_REGISTRYINDEX, ratelimit_lua_id);
			lua_pushstring(L, "fuzzy_key_ratelimit");
			ucl_object_push_lua(L, ratelimit, false);

			if (lua_pcall(L, 2, 1, 0) != 0) {
				msg_err_config("cannot call ratelimit parser from ratelimit plugin");
			}
			else {
				if (lua_type(L, -1) == LUA_TTABLE) {
					/* The returned table is in form { rate = xx, burst = yy } */
					lua_getfield(L, -1, "rate");
					key->rate = lua_tonumber(L, -1);
					lua_pop(L, 1);

					lua_getfield(L, -1, "burst");
					key->burst = lua_tonumber(L, -1);
					lua_pop(L, 1);

					key->rl_bucket = g_malloc0(sizeof(*key->rl_bucket));
				}
			}

			lua_settop(L, 0);
		}

		const ucl_object_t *expire = ucl_object_lookup(extensions, "expire");
		if (expire && ucl_object_type(expire) == UCL_STRING) {
			struct tm tm;

			/* DD-MM-YYYY */
			char *end = strptime(ucl_object_tostring(expire), "%d-%m-%Y", &tm);

			if (end != NULL && *end != '\0') {
				msg_err_config("cannot parse expire date: %s", ucl_object_tostring(expire));
			}
			else {
				key->expire = mktime(&tm);
			}
		}

		const ucl_object_t *name = ucl_object_lookup(extensions, "name");
		if (name && ucl_object_type(name) == UCL_STRING) {
			key->name = g_strdup(ucl_object_tostring(name));
		}

		/* Check permissions */
		const ucl_object_t *read_only = ucl_object_lookup(extensions, "read_only");
		if (read_only && ucl_object_type(read_only) == UCL_BOOLEAN) {
			if (ucl_object_toboolean(read_only)) {
				key->flags &= ~(FUZZY_KEY_WRITE | FUZZY_KEY_DELETE);
			}
			else {
				key->flags |= (FUZZY_KEY_WRITE | FUZZY_KEY_DELETE);
			}
		}

		const ucl_object_t *allowed_ops = ucl_object_lookup(extensions, "allowed_ops");
		if (allowed_ops && ucl_object_type(allowed_ops) == UCL_ARRAY) {
			const ucl_object_t *cur;
			ucl_object_iter_t it = NULL;
			/* Reset to only allowed */
			key->flags = 0;

			while ((cur = ucl_object_iterate(allowed_ops, &it, true)) != NULL) {
				if (ucl_object_type(cur) == UCL_STRING) {
					const char *op = ucl_object_tostring(cur);

					if (g_ascii_strcasecmp(op, "read") == 0) {
						key->flags |= FUZZY_KEY_READ;
					}
					else if (g_ascii_strcasecmp(op, "write") == 0) {
						key->flags |= FUZZY_KEY_WRITE;
					}
					else if (g_ascii_strcasecmp(op, "delete") == 0) {
						key->flags |= FUZZY_KEY_DELETE;
					}
					else {
						msg_warn_config("invalid operation: %s", op);
					}
				}
			}
		}
	}

	msg_debug("loaded keypair %*bs; expire=%f; rate=%f; burst=%f; name=%s",
			  (int) crypto_box_publickeybytes(), pk,
			  key->expire, key->rate, key->burst, key->name);

	return key;
}

gboolean
fuzzy_parse_keypair(rspamd_mempool_t *pool,
					const ucl_object_t *obj,
					gpointer ud,
					struct rspamd_rcl_section *section,
					GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	struct rspamd_fuzzy_storage_ctx *ctx;
	struct fuzzy_key *key;
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;
	gboolean ret;

	ctx = pd->user_struct;
	pd->offset = G_STRUCT_OFFSET(struct rspamd_fuzzy_storage_ctx, default_keypair);

	/*
	 * Single key
	 */
	if (ucl_object_type(obj) == UCL_STRING || ucl_object_type(obj) == UCL_OBJECT) {
		ret = rspamd_rcl_parse_struct_keypair(pool, obj, pd, section, err);

		if (!ret) {
			return ret;
		}

		key = fuzzy_add_keypair_from_ucl(ctx->cfg, obj, ctx->keys);

		if (key == NULL) {
			return FALSE;
		}

		/* Use the last one ? */
		ctx->default_key = key;
	}
	else if (ucl_object_type(obj) == UCL_ARRAY) {
		while ((cur = ucl_object_iterate(obj, &it, true)) != NULL) {
			if (!fuzzy_parse_keypair(pool, cur, pd, section, err)) {
				msg_err_pool("cannot parse keypair");
			}
		}
	}

	return TRUE;
}
