/* Copyright (c) 2010-2011, Vsevolod Stakhov
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


/***MODULE:dkim
 * rspamd module that checks dkim records of incoming email
 *
 * Allowed options:
 * - symbol_allow (string): symbol to insert in case of allow (default: 'R_DKIM_ALLOW')
 * - symbol_reject (string): symbol to insert (default: 'R_DKIM_REJECT')
 * - symbol_rempfail (string): symbol to insert in case of temporary fail (default: 'R_DKIM_TEMPFAIL')
 * - whitelist (map): map of whitelisted networks
 * - domains (map): map of domains to check
 * - strict_multiplier (number): multiplier for strict domains
 * - time_jitter (number): jitter in seconds to allow time diff while checking
 * - trusted_only (flag): check signatures only for domains in 'domains' map
 * - skip_mutli (flag): skip messages with multiply dkim signatures
 */

#include "config.h"
#include "libmime/message.h"
#include "libserver/dkim.h"
#include "libutil/hash.h"
#include "libutil/map.h"
#include "main.h"
#include "utlist.h"

#define DEFAULT_SYMBOL_REJECT "R_DKIM_REJECT"
#define DEFAULT_SYMBOL_TEMPFAIL "R_DKIM_TEMPFAIL"
#define DEFAULT_SYMBOL_ALLOW "R_DKIM_ALLOW"
#define DEFAULT_CACHE_SIZE 2048
#define DEFAULT_CACHE_MAXAGE 86400
#define DEFAULT_TIME_JITTER 60

struct dkim_ctx {
	struct module_ctx ctx;
	const gchar *symbol_reject;
	const gchar *symbol_tempfail;
	const gchar *symbol_allow;

	rspamd_mempool_t *dkim_pool;
	radix_compressed_t *whitelist_ip;
	GHashTable *dkim_domains;
	guint strict_multiplier;
	guint time_jitter;
	rspamd_lru_hash_t *dkim_hash;
	gboolean trusted_only;
	gboolean skip_multi;
};

struct dkim_check_result {
	rspamd_dkim_context_t *ctx;
	rspamd_dkim_key_t *key;
	struct rspamd_task *task;
	gint res;
	gint mult_allow, mult_deny;
	struct rspamd_async_watcher *w;
	struct dkim_check_result *next, *prev, *first;
};

static struct dkim_ctx *dkim_module_ctx = NULL;

static void dkim_symbol_callback (struct rspamd_task *task, void *unused);

/* Initialization */
gint dkim_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint dkim_module_config (struct rspamd_config *cfg);
gint dkim_module_reconfig (struct rspamd_config *cfg);

module_t dkim_module = {
	"dkim",
	dkim_module_init,
	dkim_module_config,
	dkim_module_reconfig,
	NULL
};

gint
dkim_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	dkim_module_ctx = g_malloc0 (sizeof (struct dkim_ctx));

	dkim_module_ctx->dkim_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	*ctx = (struct module_ctx *)dkim_module_ctx;

	return 0;
}

gint
dkim_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value;
	gint res = TRUE, cb_id;
	guint cache_size, cache_expire;
	gboolean got_trusted = FALSE;

	dkim_module_ctx->whitelist_ip = radix_create_compressed ();

	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "symbol_reject")) != NULL) {
		dkim_module_ctx->symbol_reject = ucl_obj_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_reject = DEFAULT_SYMBOL_REJECT;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"symbol_tempfail")) != NULL) {
		dkim_module_ctx->symbol_tempfail = ucl_obj_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_tempfail = DEFAULT_SYMBOL_TEMPFAIL;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "symbol_allow")) != NULL) {
		dkim_module_ctx->symbol_allow = ucl_obj_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_allow = DEFAULT_SYMBOL_ALLOW;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"dkim_cache_size")) != NULL) {
		cache_size = ucl_obj_toint (value);
	}
	else {
		cache_size = DEFAULT_CACHE_SIZE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"dkim_cache_expire")) != NULL) {
		cache_expire = ucl_obj_todouble (value);
	}
	else {
		cache_expire = DEFAULT_CACHE_MAXAGE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "time_jitter")) != NULL) {
		dkim_module_ctx->time_jitter = ucl_obj_todouble (value);
	}
	else {
		dkim_module_ctx->time_jitter = DEFAULT_TIME_JITTER;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "whitelist")) != NULL) {
		if (!rspamd_map_add (cfg, ucl_obj_tostring (value),
			"DKIM whitelist", rspamd_radix_read, rspamd_radix_fin,
			(void **)&dkim_module_ctx->whitelist_ip)) {
			radix_add_generic_iplist (ucl_obj_tostring (value),
				&dkim_module_ctx->whitelist_ip);
		}
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "domains")) != NULL) {
		if (!rspamd_map_add (cfg, ucl_obj_tostring (value),
			"DKIM domains", rspamd_kv_list_read, rspamd_kv_list_fin,
			(void **)&dkim_module_ctx->dkim_domains)) {
			msg_warn ("cannot load dkim domains list from %s",
				ucl_obj_tostring (value));
		}
		else {
			got_trusted = TRUE;
		}
	}
	if (!got_trusted && (value =
			rspamd_config_get_module_opt (cfg, "dkim", "trusted_domains")) != NULL) {
		if (!rspamd_map_add (cfg, ucl_obj_tostring (value),
				"DKIM domains", rspamd_kv_list_read, rspamd_kv_list_fin,
				(void **)&dkim_module_ctx->dkim_domains)) {
			msg_warn ("cannot load dkim domains list from %s",
					ucl_obj_tostring (value));
		}
		else {
			got_trusted = TRUE;
		}
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim",
		"strict_multiplier")) != NULL) {
		dkim_module_ctx->strict_multiplier = ucl_obj_toint (value);
	}
	else {
		dkim_module_ctx->strict_multiplier = 1;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "trusted_only")) != NULL) {
		dkim_module_ctx->trusted_only = ucl_obj_toboolean (value);
	}
	else {
		dkim_module_ctx->trusted_only = FALSE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "dkim", "skip_multi")) != NULL) {
		dkim_module_ctx->skip_multi = ucl_obj_toboolean (value);
	}
	else {
		dkim_module_ctx->skip_multi = FALSE;
	}

	if (dkim_module_ctx->trusted_only && !got_trusted) {
		msg_err (
			"trusted_only option is set and no trusted domains are defined; disabling dkim module completely as it is useless in this case");
	}
	else {
		cb_id = rspamd_symbols_cache_add_symbol_normal (cfg->cache,
			dkim_module_ctx->symbol_reject,
			1,
			dkim_symbol_callback,
			NULL);
		rspamd_symbols_cache_add_symbol_virtual (cfg->cache,
			dkim_module_ctx->symbol_tempfail,
			1,
			cb_id);
		rspamd_symbols_cache_add_symbol_virtual (cfg->cache,
			dkim_module_ctx->symbol_allow,
			1,
			cb_id);

		dkim_module_ctx->dkim_hash = rspamd_lru_hash_new (
				cache_size,
				cache_expire,
				g_free,
				(GDestroyNotify)rspamd_dkim_key_free);


#ifndef HAVE_OPENSSL
		msg_warn (
			"openssl is not found so dkim rsa check is disabled, only check body hash, it is NOT safe to trust these results");
#endif
	}

	return res;
}

gint
dkim_module_reconfig (struct rspamd_config *cfg)
{
	struct module_ctx saved_ctx;

	saved_ctx = dkim_module_ctx->ctx;
	rspamd_mempool_delete (dkim_module_ctx->dkim_pool);
	radix_destroy_compressed (dkim_module_ctx->whitelist_ip);
	if (dkim_module_ctx->dkim_domains) {
		g_hash_table_destroy (dkim_module_ctx->dkim_domains);
	}

	memset (dkim_module_ctx, 0, sizeof (*dkim_module_ctx));
	dkim_module_ctx->ctx = saved_ctx;
	dkim_module_ctx->dkim_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	return dkim_module_config (cfg);
}

/*
 * Parse strict value for domain in format: 'reject_multiplier:deny_multiplier'
 */
static gboolean
dkim_module_parse_strict (const gchar *value, gint *allow, gint *deny)
{
	const gchar *colon;
	gulong val;

	colon = strchr (value, ':');
	if (colon) {
		if (rspamd_strtoul (value, colon - value, &val)) {
			*deny = val;
			colon++;
			if (rspamd_strtoul (colon, strlen (colon), &val)) {
				*allow = val;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static void
dkim_module_check (struct dkim_check_result *res)
{
	gboolean all_done = TRUE, got_allow = FALSE;
	const gchar *strict_value;
	struct dkim_check_result *first, *cur, *sel = NULL;

	first = res->first;

	DL_FOREACH (first, cur) {
		if (cur->ctx == NULL) {
			continue;
		}

		if (cur->key != NULL && cur->res == -1) {
			msg_debug ("check dkim signature for %s domain from %s",
					cur->ctx->domain,
					cur->ctx->dns_key);
			cur->res = rspamd_dkim_check (cur->ctx, cur->key, cur->task);

			if (dkim_module_ctx->dkim_domains != NULL) {
				/* Perform strict check */
				if ((strict_value =
						g_hash_table_lookup (dkim_module_ctx->dkim_domains,
								cur->ctx->domain)) != NULL) {
					if (!dkim_module_parse_strict (strict_value, &cur->mult_allow,
							&cur->mult_deny)) {
						cur->mult_allow = dkim_module_ctx->strict_multiplier;
						cur->mult_deny = dkim_module_ctx->strict_multiplier;
					}
				}
			}
		}

		if (cur->res == -1 || cur->key == NULL) {
			/* Still need a key */
			all_done = FALSE;
		}
	}

	if (all_done) {
		DL_FOREACH (first, cur) {
			if (cur->ctx == NULL) {
				continue;
			}

			if (cur->res == DKIM_CONTINUE) {
				rspamd_task_insert_result (cur->task,
						dkim_module_ctx->symbol_allow,
						cur->mult_allow * 1.0,
						g_list_prepend (NULL,
								rspamd_mempool_strdup (cur->task->task_pool,
										cur->ctx->domain)));
				got_allow = TRUE;
				sel = NULL;
			}
			else if (!got_allow) {
				if (sel == NULL) {
					sel = cur;
				}
				else if (sel->res == DKIM_TRYAGAIN && cur->res != DKIM_TRYAGAIN) {
					sel = cur;
				}
			}
		}
	}

	if (sel != NULL) {
		if (sel->res == DKIM_REJECT) {
			rspamd_task_insert_result (sel->task,
					dkim_module_ctx->symbol_reject,
					sel->mult_deny * 1.0,
					g_list_prepend (NULL,
							rspamd_mempool_strdup (sel->task->task_pool,
									sel->ctx->domain)));
		}
		else {
			rspamd_task_insert_result (sel->task,
					dkim_module_ctx->symbol_tempfail,
					1.0,
					g_list_prepend (NULL,
							rspamd_mempool_strdup (sel->task->task_pool,
									sel->ctx->domain)));
		}
	}

	if (all_done && res != NULL) {
		rspamd_session_watcher_pop (res->task->s, res->w);
	}
}

static void
dkim_module_key_handler (rspamd_dkim_key_t *key,
	gsize keylen,
	rspamd_dkim_context_t *ctx,
	gpointer ud,
	GError *err)
{
	struct dkim_check_result *res = ud;

	if (key != NULL) {
		/* Add new key to the lru cache */
		rspamd_lru_hash_insert (dkim_module_ctx->dkim_hash,
			g_strdup (ctx->dns_key),
			key, res->task->time_real, key->ttl);
		res->key = key;
	}
	else {
		/* Insert tempfail symbol */
		msg_info ("cannot get key for domain %s", ctx->dns_key);
		if (err != NULL) {
			res->res = DKIM_TRYAGAIN;
		}
	}

	if (err) {
		g_error_free (err);
	}

	dkim_module_check (res);
}

static void
dkim_symbol_callback (struct rspamd_task *task, void *unused)
{
	GList *hlist;
	rspamd_dkim_context_t *ctx;
	rspamd_dkim_key_t *key;
	GError *err = NULL;
	struct raw_header *rh;
	struct dkim_check_result *res = NULL, *cur;
	/* First check if a message has its signature */

	hlist = rspamd_message_get_header (task,
			DKIM_SIGNHEADER,
			FALSE);
	if (hlist != NULL) {
		/* Check whitelist */
		msg_debug ("dkim signature found");
		if (radix_find_compressed_addr (dkim_module_ctx->whitelist_ip,
				task->from_addr) == RADIX_NO_VALUE) {
			/* Parse signature */
			msg_debug ("create dkim signature");

			while (hlist != NULL) {
				rh = (struct raw_header *)hlist->data;

				if (res == NULL) {
					res = rspamd_mempool_alloc0 (task->task_pool, sizeof (*res));
					res->prev = res;
					res->w = rspamd_session_get_watcher (task->s);
					cur = res;
				}
				else {
					cur = rspamd_mempool_alloc0 (task->task_pool, sizeof (*res));
				}

				cur->first = res;
				cur->res = -1;
				cur->task = task;
				cur->mult_allow = 1.0;
				cur->mult_deny = 1.0;

				ctx = rspamd_create_dkim_context (rh->decoded,
						task->task_pool,
						dkim_module_ctx->time_jitter,
						&err);
				if (ctx == NULL) {
					if (err != NULL) {
						msg_info ("<%s> cannot parse DKIM context: %s",
								task->message_id, err->message);
						g_error_free (err);
					}
					else {
						msg_info ("<%s> cannot parse DKIM context: unknown error",
								task->message_id);
					}

					hlist = g_list_next (hlist);
					continue;
				}
				else {
					/* Get key */

					cur->ctx = ctx;

					if (dkim_module_ctx->trusted_only &&
							(dkim_module_ctx->dkim_domains == NULL ||
									g_hash_table_lookup (dkim_module_ctx->dkim_domains,
											ctx->domain) == NULL)) {
						msg_debug ("skip dkim check for %s domain", ctx->domain);
						hlist = g_list_next (hlist);

						continue;
					}

					key = rspamd_lru_hash_lookup (dkim_module_ctx->dkim_hash,
							ctx->dns_key,
							task->tv.tv_sec);
					if (key != NULL) {
						debug_task ("found key for %s in cache", ctx->dns_key);
						cur->key = key;
					}
					else {
						debug_task ("request key for %s from DNS", ctx->dns_key);
						task->dns_requests++;
						rspamd_get_dkim_key (ctx,
								task->resolver,
								task->s,
								dkim_module_key_handler,
								cur);
					}
				}

				if (res != cur) {
					DL_APPEND (res, cur);
				}

				hlist = g_list_next (hlist);
			}
		}
	}

	if (res != NULL) {
		rspamd_session_watcher_push (task->s);
		dkim_module_check (res);
	}
}
