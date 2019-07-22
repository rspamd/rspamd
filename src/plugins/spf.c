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
 * - symbol_na (string): symbol to insert (default: 'R_SPF_NA')
 * - symbol_dnsfail (string): symbol to insert (default: 'R_SPF_DNSFAIL')
 * - symbol_permfail (string): symbol to insert (default: 'R_SPF_PERMFAIL')
 * - whitelist (map): map of whitelisted networks
 */


#include "config.h"
#include "libmime/message.h"
#include "libserver/spf.h"
#include "libutil/hash.h"
#include "libutil/map.h"
#include "libutil/map_helpers.h"
#include "rspamd.h"
#include "libserver/mempool_vars_internal.h"

#define DEFAULT_SYMBOL_FAIL "R_SPF_FAIL"
#define DEFAULT_SYMBOL_SOFTFAIL "R_SPF_SOFTFAIL"
#define DEFAULT_SYMBOL_NEUTRAL "R_SPF_NEUTRAL"
#define DEFAULT_SYMBOL_ALLOW "R_SPF_ALLOW"
#define DEFAULT_SYMBOL_DNSFAIL "R_SPF_DNSFAIL"
#define DEFAULT_SYMBOL_PERMFAIL "R_SPF_PERMFAIL"
#define DEFAULT_SYMBOL_NA "R_SPF_NA"
#define DEFAULT_CACHE_SIZE 2048

static const gchar *M = "rspamd spf plugin";

struct spf_ctx {
	struct module_ctx ctx;
	const gchar *symbol_fail;
	const gchar *symbol_softfail;
	const gchar *symbol_neutral;
	const gchar *symbol_allow;
	const gchar *symbol_dnsfail;
	const gchar *symbol_na;
	const gchar *symbol_permfail;

	struct rspamd_radix_map_helper *whitelist_ip;
	rspamd_lru_hash_t *spf_hash;

	gboolean check_local;
	gboolean check_authed;
};

static void spf_symbol_callback (struct rspamd_task *task,
								 struct rspamd_symcache_item *item,
								 void *unused);

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
		RSPAMD_MODULE_VER,
		(guint)-1,
};

static inline struct spf_ctx *
spf_get_context (struct rspamd_config *cfg)
{
	return (struct spf_ctx *)g_ptr_array_index (cfg->c_modules,
			spf_module.ctx_offset);
}


gint
spf_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	struct spf_ctx *spf_module_ctx;

	spf_module_ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (*spf_module_ctx));
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
			"Symbol that is added if no SPF policy is found",
			"symbol_na",
			UCL_STRING,
			NULL,
			0,
			NULL,
			0);
	rspamd_rcl_add_doc_by_path (cfg,
			"spf",
			"Symbol that is added if SPF policy is invalid",
			"symbol_permfail",
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
	struct spf_ctx *spf_module_ctx = spf_get_context (cfg);

	if (!rspamd_config_is_module_enabled (cfg, "spf")) {
		return TRUE;
	}

	spf_module_ctx->whitelist_ip = NULL;

	value = rspamd_config_get_module_opt (cfg, "spf", "check_local");

	if (value == NULL) {
		rspamd_config_get_module_opt (cfg, "options", "check_local");
	}

	if (value != NULL) {
		spf_module_ctx->check_local = ucl_obj_toboolean (value);
	}
	else {
		spf_module_ctx->check_local = FALSE;
	}

	value = rspamd_config_get_module_opt (cfg, "spf", "check_authed");

	if (value == NULL) {
		rspamd_config_get_module_opt (cfg, "options", "check_authed");
	}

	if (value != NULL) {
		spf_module_ctx->check_authed = ucl_obj_toboolean (value);
	}
	else {
		spf_module_ctx->check_authed = FALSE;
	}
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
		rspamd_config_get_module_opt (cfg, "spf", "symbol_na")) != NULL) {
		spf_module_ctx->symbol_na = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_na = DEFAULT_SYMBOL_NA;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "symbol_permfail")) != NULL) {
		spf_module_ctx->symbol_permfail = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_permfail = DEFAULT_SYMBOL_PERMFAIL;
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

	cb_id = rspamd_symcache_add_symbol (cfg->cache,
			"SPF_CHECK",
			0,
			spf_symbol_callback,
			NULL,
			SYMBOL_TYPE_CALLBACK | SYMBOL_TYPE_FINE | SYMBOL_TYPE_EMPTY, -1);
	rspamd_config_add_symbol (cfg,
			"SPF_CHECK",
			0.0,
			"SPF check callback",
			"policies",
			RSPAMD_SYMBOL_FLAG_IGNORE,
			1,
			1);
	rspamd_config_add_symbol_group (cfg, "SPF_CHECK", "spf");

	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_fail, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_softfail, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_permfail, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_na, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_neutral, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_allow, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);
	rspamd_symcache_add_symbol (cfg->cache,
			spf_module_ctx->symbol_dnsfail, 0,
			NULL, NULL,
			SYMBOL_TYPE_VIRTUAL,
			cb_id);

	if (cache_size > 0) {
		spf_module_ctx->spf_hash = rspamd_lru_hash_new (
				cache_size,
				NULL,
				(GDestroyNotify) spf_record_unref);
		rspamd_mempool_add_destructor (cfg->cfg_pool,
				(rspamd_mempool_destruct_t)rspamd_lru_hash_destroy,
				spf_module_ctx->spf_hash);
	}

	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_map_helper_destroy_radix,
			spf_module_ctx->whitelist_ip);

	msg_info_config ("init internal spf module");

	return res;
}

gint
spf_module_reconfig (struct rspamd_config *cfg)
{
	return spf_module_config (cfg);
}

static gboolean
spf_check_element (struct spf_resolved *rec, struct spf_addr *addr,
		struct rspamd_task *task, gboolean cached)
{
	gboolean res = FALSE;
	const guint8 *s, *d;
	gchar *spf_result;
	guint af, mask, bmask, addrlen;
	const gchar *spf_message, *spf_symbol;
	struct spf_ctx *spf_module_ctx = spf_get_context (task->cfg);

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
		if (mask > addrlen * CHAR_BIT) {
			msg_info_task ("bad mask length: %d", mask);
		}
		else if (memcmp (s, d, bmask) == 0) {
			if (bmask * CHAR_BIT < mask) {
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
		spf_result = rspamd_mempool_alloc (task->task_pool,
				strlen (addr->spf_string) + 5);

		switch (addr->mech) {
		case SPF_FAIL:
			spf_symbol = spf_module_ctx->symbol_fail;
			spf_result[0] = '-';
			spf_message = "(SPF): spf fail";
			if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
				if (rec->perm_failed) {
					msg_info_task ("do not apply SPF failed policy, as we have "
							"some addresses unresolved");
					spf_symbol = spf_module_ctx->symbol_permfail;
				}
				else if (rec->temp_failed) {
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
			spf_result[0] = '~';

			if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
				if (rec->perm_failed) {
					msg_info_task ("do not apply SPF failed policy, as we have "
							"some addresses unresolved");
					spf_symbol = spf_module_ctx->symbol_permfail;
				}
				else if (rec->temp_failed) {
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
			spf_result[0] = '?';
			break;
		default:
			spf_symbol = spf_module_ctx->symbol_allow;
			spf_message = "(SPF): spf allow";
			spf_result[0] = '+';
			break;
		}

		gint r = rspamd_strlcpy (spf_result + 1, addr->spf_string,
				strlen (addr->spf_string) + 1);

		if (cached) {
			rspamd_strlcpy (spf_result + r + 1, ":c", 3);
		}

		rspamd_task_insert_result (task,
				spf_symbol,
				1,
				spf_result);
		ucl_object_insert_key (task->messages,
				ucl_object_fromstring (spf_message), "spf", 0,
				false);

		return TRUE;
	}

	return FALSE;
}

static void
spf_check_list (struct spf_resolved *rec, struct rspamd_task *task, gboolean cached)
{
	guint i;
	struct spf_addr *addr;
	struct spf_ctx *spf_module_ctx = spf_get_context (task->cfg);

	if (cached) {
		msg_info_task ("use cached record for %s (0x%xuL) in LRU cache for %d seconds, "
					   "%d/%d elements in the cache",
				rec->domain,
				rec->digest,
				rec->ttl,
				rspamd_lru_hash_size (spf_module_ctx->spf_hash),
				rspamd_lru_hash_capacity (spf_module_ctx->spf_hash));
	}

	for (i = 0; i < rec->elts->len; i ++) {
		addr = &g_array_index (rec->elts, struct spf_addr, i);
		if (spf_check_element (rec, addr, task, cached)) {
			break;
		}
	}
}

static void
spf_plugin_callback (struct spf_resolved *record, struct rspamd_task *task,
		gpointer ud)
{
	struct spf_resolved *l = NULL;
	struct rspamd_symcache_item *item = (struct rspamd_symcache_item *)ud;
	struct spf_ctx *spf_module_ctx = spf_get_context (task->cfg);

	if (record && record->na) {
		rspamd_task_insert_result (task,
				spf_module_ctx->symbol_na,
				1,
				NULL);
	}
	else if (record && record->elts->len == 0 && record->temp_failed) {
		rspamd_task_insert_result (task,
				spf_module_ctx->symbol_dnsfail,
				1,
				NULL);
	}
	else if (record && record->elts->len == 0 && record->perm_failed) {
		rspamd_task_insert_result (task,
				spf_module_ctx->symbol_permfail,
				1,
				NULL);
	}
	else if (record && record->elts->len == 0) {
		rspamd_task_insert_result (task,
				spf_module_ctx->symbol_permfail,
				1,
				NULL);
	}
	else if (record && record->domain) {

		spf_record_ref (record);

		if (!spf_module_ctx->spf_hash ||
			(l = rspamd_lru_hash_lookup (spf_module_ctx->spf_hash,
					record->domain, task->task_timestamp)) == NULL) {
			l = record;

			if (record->ttl > 0 &&
					!record->temp_failed &&
					!record->perm_failed &&
					!record->na) {

				if (spf_module_ctx->spf_hash) {
					rspamd_lru_hash_insert (spf_module_ctx->spf_hash,
							record->domain, spf_record_ref (l),
							task->task_timestamp, record->ttl);

					msg_info_task ("stored record for %s (0x%xuL) in LRU cache for %d seconds, "
								   "%d/%d elements in the cache",
							record->domain,
							record->digest,
							record->ttl,
							rspamd_lru_hash_size (spf_module_ctx->spf_hash),
							rspamd_lru_hash_capacity (spf_module_ctx->spf_hash));
				}
			}

		}

		spf_record_ref (l);
		spf_check_list (l, task, FALSE);
		spf_record_unref (l);

		spf_record_unref (record);
	}

	rspamd_symcache_item_async_dec_check (task, item, M);
}


static void
spf_symbol_callback (struct rspamd_task *task,
					 struct rspamd_symcache_item *item,
					 void *unused)
{
	const gchar *domain;
	struct spf_resolved *l;
	gint *dmarc_checks;
	struct spf_ctx *spf_module_ctx = spf_get_context (task->cfg);

	/* Allow dmarc */
	dmarc_checks = rspamd_mempool_get_variable (task->task_pool,
			RSPAMD_MEMPOOL_DMARC_CHECKS);

	if (dmarc_checks) {
		(*dmarc_checks) ++;
	}
	else {
		dmarc_checks = rspamd_mempool_alloc (task->task_pool,
				sizeof (*dmarc_checks));
		*dmarc_checks = 1;
		rspamd_mempool_set_variable (task->task_pool,
				RSPAMD_MEMPOOL_DMARC_CHECKS,
				dmarc_checks, NULL);
	}

	if (rspamd_match_radix_map_addr (spf_module_ctx->whitelist_ip,
			task->from_addr) != NULL) {
		rspamd_symcache_finalize_item (task, item);
		return;
	}

	if ((!spf_module_ctx->check_authed && task->user != NULL)
			|| (!spf_module_ctx->check_local &&
					rspamd_inet_address_is_local (task->from_addr, TRUE))) {
		msg_info_task ("skip SPF checks for local networks and authorized users");
		rspamd_symcache_finalize_item (task, item);

		return;
	}

	domain = rspamd_spf_get_domain (task);
	rspamd_symcache_item_async_inc (task, item, M);

	if (domain) {
		if (spf_module_ctx->spf_hash &&
				(l = rspamd_lru_hash_lookup (spf_module_ctx->spf_hash, domain,
					task->task_timestamp)) != NULL) {
			spf_record_ref (l);
			spf_check_list (l, task, TRUE);
			spf_record_unref (l);
		}
		else {

			if (!rspamd_spf_resolve (task, spf_plugin_callback, item)) {
				msg_info_task ("cannot make spf request for %s", domain);
				rspamd_task_insert_result (task,
						spf_module_ctx->symbol_dnsfail,
						1,
						"(SPF): spf DNS fail");
			}
			else {
				rspamd_symcache_item_async_inc (task, item, M);
			}
		}
	}

	rspamd_symcache_item_async_dec_check (task, item, M);
}
