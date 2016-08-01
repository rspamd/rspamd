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
/***MODULE:spf
 * rspamd module that checks spf records of incoming email
 *
 * Allowed options:
 * - symbol_allow (string): symbol to insert (default: 'R_SPF_ALLOW')
 * - symbol_fail (string): symbol to insert (default: 'R_SPF_FAIL')
 * - symbol_softfail (string): symbol to insert (default: 'R_SPF_SOFTFAIL')
 * - whitelist (map): map of whitelisted networks
 */

#include "config.h"
#include "libmime/message.h"
#include "libserver/spf.h"
#include "libutil/hash.h"
#include "libutil/map.h"
#include "rspamd.h"
#include "addr.h"

#define DEFAULT_SYMBOL_FAIL "R_SPF_FAIL"
#define DEFAULT_SYMBOL_SOFTFAIL "R_SPF_SOFTFAIL"
#define DEFAULT_SYMBOL_NEUTRAL "R_SPF_NEUTRAL"
#define DEFAULT_SYMBOL_ALLOW "R_SPF_ALLOW"
#define DEFAULT_SYMBOL_DNSFAIL "R_SPF_DNSFAIL"
#define DEFAULT_CACHE_SIZE 2048
#define DEFAULT_CACHE_MAXAGE 86400

struct spf_ctx {
	struct module_ctx ctx;
	const gchar *symbol_fail;
	const gchar *symbol_softfail;
	const gchar *symbol_neutral;
	const gchar *symbol_allow;
	const gchar *symbol_dnsfail;

	rspamd_mempool_t *spf_pool;
	radix_compressed_t *whitelist_ip;
	rspamd_lru_hash_t *spf_hash;
};

static struct spf_ctx *spf_module_ctx = NULL;

static void spf_symbol_callback (struct rspamd_task *task, void *unused);

/* Initialization */
gint spf_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint spf_module_config (struct rspamd_config *cfg);
gint spf_module_reconfig (struct rspamd_config *cfg);

module_t spf_module = {
	"spf",
	spf_module_init,
	spf_module_config,
	spf_module_reconfig,
	NULL,
	RSPAMD_MODULE_VER
};

gint
spf_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	spf_module_ctx = g_malloc (sizeof (struct spf_ctx));

	spf_module_ctx->spf_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);

	*ctx = (struct module_ctx *)spf_module_ctx;

	rspamd_rcl_add_doc_by_path (cfg,
			NULL,
			"SPF check plugin",
			"spf",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);

	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Map of IP addresses that should be excluded from SPF checks (in addition to `local_networks`)",
			"whitelist",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Symbol that is added if SPF check is successful",
			"symbol_allow",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Symbol that is added if SPF policy is set to 'deny'",
			"symbol_fail",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Symbol that is added if SPF policy is set to 'undefined'",
			"symbol_softfail",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Symbol that is added if SPF policy is set to 'neutral'",
			"symbol_neutral",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Symbol that is added if SPF policy is failed due to DNS failure",
			"symbol_dnsfail",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Size of SPF parsed records cache",
			"spf_cache_size",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);

	return 0;
}


gint
spf_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value;
	gint res = TRUE, cb_id;
	guint cache_size;

	if (!rspamd_config_is_module_enabled (cfg, "spf")) {
		return TRUE;
	}

	spf_module_ctx->whitelist_ip = radix_create_compressed ();

	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "symbol_fail")) != NULL) {
		spf_module_ctx->symbol_fail = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_fail = DEFAULT_SYMBOL_FAIL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "symbol_softfail")) != NULL) {
		spf_module_ctx->symbol_softfail = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_softfail = DEFAULT_SYMBOL_SOFTFAIL;
	}
	if ((value =
			rspamd_config_get_module_opt (cfg, "spf", "symbol_neutral")) != NULL) {
		spf_module_ctx->symbol_neutral = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_neutral = DEFAULT_SYMBOL_NEUTRAL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "symbol_allow")) != NULL) {
		spf_module_ctx->symbol_allow = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_allow = DEFAULT_SYMBOL_ALLOW;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "symbol_dnsfail")) != NULL) {
		spf_module_ctx->symbol_dnsfail = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_dnsfail = DEFAULT_SYMBOL_DNSFAIL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "spf_cache_size")) != NULL) {
		cache_size = ucl_obj_toint (value);
	}
	else {
		cache_size = DEFAULT_CACHE_SIZE;
	}

	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "whitelist")) != NULL) {

		rspamd_config_radix_from_ucl (cfg, value, "SPF whitelist",
				&spf_module_ctx->whitelist_ip, NULL);
	}

	cb_id = rspamd_symbols_cache_add_symbol (cfg->cache,
		spf_module_ctx->symbol_fail,
		0,
		spf_symbol_callback,
		NULL,
		SYMBOL_TYPE_NORMAL|SYMBOL_TYPE_FINE|SYMBOL_TYPE_EMPTY, -1);
	rspamd_symbols_cache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_softfail, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symbols_cache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_neutral, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symbols_cache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_allow, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symbols_cache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_dnsfail, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);

	spf_module_ctx->spf_hash = rspamd_lru_hash_new (
			cache_size,
			NULL,
			(GDestroyNotify)spf_record_unref);

	msg_info_config ("init internal spf module");

	return res;
}

gint
spf_module_reconfig (struct rspamd_config *cfg)
{
	struct module_ctx saved_ctx;

	saved_ctx = spf_module_ctx->ctx;
	rspamd_mempool_delete (spf_module_ctx->spf_pool);
	radix_destroy_compressed (spf_module_ctx->whitelist_ip);
	memset (spf_module_ctx, 0, sizeof (*spf_module_ctx));
	spf_module_ctx->ctx = saved_ctx;
	spf_module_ctx->spf_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);

	return spf_module_config (cfg);
}

static gboolean
spf_check_element (struct spf_resolved *rec, struct spf_addr *addr,
		struct rspamd_task *task)
{
	gboolean res = FALSE;
	const guint8 *s, *d;
	gchar *spf_result;
	guint af, mask, bmask, addrlen;
	const gchar *spf_message, *spf_symbol;
	GList *opts = NULL;

	if (task->from_addr == NULL) {
		return FALSE;
	}

	if (addr->flags & RSPAMD_SPF_FLAG_TEMPFAIL) {
		/* Ignore failed addresses */
		return FALSE;
	}

	af = rspamd_inet_address_get_af (task->from_addr);
	/* Basic comparing algorithm */
	if (((addr->flags & RSPAMD_SPF_FLAG_IPV6) && af == AF_INET6) ||
		((addr->flags & RSPAMD_SPF_FLAG_IPV4) && af == AF_INET)) {
		d = rspamd_inet_address_get_hash_key (task->from_addr, &addrlen);

		if (af == AF_INET6) {
			s = (const guint8 *)addr->addr6;
			mask = addr->m.dual.mask_v6;
		}
		else {
			s = (const guint8 *)addr->addr4;
			mask = addr->m.dual.mask_v4;
		}

		/* Compare the first bytes */
		bmask = mask / CHAR_BIT;
		if (bmask > addrlen) {
			msg_info_task ("bad mask length: %d", mask);
		}
		else if (memcmp (s, d, bmask) == 0) {

			if (bmask * CHAR_BIT != mask) {
				/* Compare the remaining bits */
				s += bmask;
				d += bmask;
				mask = (0xff << (CHAR_BIT - (mask - bmask * 8))) & 0xff;
				if ((*s & mask) == (*d & mask)) {
					res = TRUE;
				}
			}
			else {
				res = TRUE;
			}
		}
	}
	else {
		if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
			res = TRUE;
		}
		else {
			res = FALSE;
		}
	}

	if (res) {
		spf_result = rspamd_mempool_strdup (task->task_pool, addr->spf_string);
		opts = g_list_prepend (opts, spf_result);

		switch (addr->mech) {
		case SPF_FAIL:
			spf_symbol = spf_module_ctx->symbol_fail;
			spf_message = "(SPF): spf fail";
			if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
				if (rec->failed) {
					msg_info_task ("do not apply SPF failed policy, as we have "
							"some addresses unresolved");
					spf_symbol = spf_module_ctx->symbol_dnsfail;
					spf_message = "(SPF): spf DNS fail";
				}
			}
			break;
		case SPF_SOFT_FAIL:
			spf_symbol = spf_module_ctx->symbol_softfail;
			spf_message = "(SPF): spf softfail";

			if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
				if (rec->failed) {
					msg_info_task ("do not apply SPF failed policy, as we have "
							"some addresses unresolved");
					spf_symbol = spf_module_ctx->symbol_dnsfail;
					spf_message = "(SPF): spf DNS fail";
				}
			}
			break;
		case SPF_NEUTRAL:
			spf_symbol = spf_module_ctx->symbol_neutral;
			spf_message = "(SPF): spf neutral";
			break;
		default:
			spf_symbol = spf_module_ctx->symbol_allow;
			spf_message = "(SPF): spf allow";
			break;
		}

		rspamd_task_insert_result (task,
				spf_symbol,
				1,
				opts);
		task->messages = g_list_prepend (task->messages, (gpointer)spf_message);
		return TRUE;
	}

	return FALSE;
}

static void
spf_check_list (struct spf_resolved *rec, struct rspamd_task *task)
{
	guint i;
	struct spf_addr *addr;

	for (i = 0; i < rec->elts->len; i ++) {
		addr = &g_array_index (rec->elts, struct spf_addr, i);
		if (spf_check_element (rec, addr, task)) {
			break;
		}
	}
}

static void
spf_plugin_callback (struct spf_resolved *record, struct rspamd_task *task,
		gpointer ud)
{
	struct spf_resolved *l;
	struct rspamd_async_watcher *w = ud;

	if (record && record->elts->len > 0 && record->domain) {

		if ((l = rspamd_lru_hash_lookup (spf_module_ctx->spf_hash,
					record->domain, task->tv.tv_sec)) == NULL) {

			l = spf_record_ref (record);

			if (!record->failed) {
				rspamd_lru_hash_insert (spf_module_ctx->spf_hash,
						record->domain, l,
						task->tv.tv_sec, record->ttl);
			}

		}
		spf_record_ref (l);
		spf_check_list (l, task);
		spf_record_unref (l);
	}

	rspamd_session_watcher_pop (task->s, w);
}


static void
spf_symbol_callback (struct rspamd_task *task, void *unused)
{
	const gchar *domain;
	struct spf_resolved *l;
	struct rspamd_async_watcher *w;

	if (radix_find_compressed_addr (spf_module_ctx->whitelist_ip,
			task->from_addr) != RADIX_NO_VALUE) {
		return;
	}

	if (task->user != NULL || rspamd_inet_address_is_local (task->from_addr)) {
		msg_info_task ("skip SPF checks for local networks and authorized users");
		return;
	}

	domain = rspamd_spf_get_domain (task);

	if (domain) {
		if ((l =
			rspamd_lru_hash_lookup (spf_module_ctx->spf_hash, domain,
			task->tv.tv_sec)) != NULL) {
			spf_record_ref (l);
			spf_check_list (l, task);
			spf_record_unref (l);
		}
		else {
			w = rspamd_session_get_watcher (task->s);
			if (!rspamd_spf_resolve (task, spf_plugin_callback, w)) {
				msg_info_task ("cannot make spf request for [%s]",
						task->message_id);
			}
			else {
				rspamd_session_watcher_push (task->s);
			}
		}
	}
}
