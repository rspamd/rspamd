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
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "expressions.h"
#include "util.h"
#include "view.h"
#include "map.h"
#include "dkim.h"
#include "hash.h"

#define DEFAULT_SYMBOL_REJECT "R_DKIM_REJECT"
#define DEFAULT_SYMBOL_TEMPFAIL "R_DKIM_TEMPFAIL"
#define DEFAULT_SYMBOL_ALLOW "R_DKIM_ALLOW"
#define DEFAULT_CACHE_SIZE 2048
#define DEFAULT_CACHE_MAXAGE 86400
#define DEFAULT_TIME_JITTER 60

struct dkim_ctx {
	gint                            (*filter) (struct rspamd_task * task);
	const gchar                    *symbol_reject;
	const gchar                    *symbol_tempfail;
	const gchar                    *symbol_allow;

	rspamd_mempool_t                   *dkim_pool;
	radix_tree_t                    *whitelist_ip;
	GHashTable						*dkim_domains;
	guint							 strict_multiplier;
	guint							 time_jitter;
	rspamd_lru_hash_t               *dkim_hash;
	gboolean						 trusted_only;
	gboolean						 skip_multi;
};

static struct dkim_ctx        *dkim_module_ctx = NULL;

static void                   dkim_symbol_callback (struct rspamd_task *task, void *unused);

/* Initialization */
gint dkim_module_init (struct config_file *cfg, struct module_ctx **ctx);
gint dkim_module_config (struct config_file *cfg);
gint dkim_module_reconfig (struct config_file *cfg);

module_t dkim_module = {
	"dkim",
	dkim_module_init,
	dkim_module_config,
	dkim_module_reconfig
};

gint
dkim_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	dkim_module_ctx = g_malloc0 (sizeof (struct dkim_ctx));

	dkim_module_ctx->dkim_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	*ctx = (struct module_ctx *)dkim_module_ctx;

	return 0;
}

gint
dkim_module_config (struct config_file *cfg)
{
	const ucl_object_t             *value;
	gint                            res = TRUE;
	guint                           cache_size, cache_expire;
	gboolean						got_trusted = FALSE;

	dkim_module_ctx->whitelist_ip = radix_tree_create ();

	if ((value = get_module_opt (cfg, "dkim", "symbol_reject")) != NULL) {
		dkim_module_ctx->symbol_reject = ucl_obj_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_reject = DEFAULT_SYMBOL_REJECT;
	}
	if ((value = get_module_opt (cfg, "dkim", "symbol_tempfail")) != NULL) {
		dkim_module_ctx->symbol_tempfail = ucl_obj_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_tempfail = DEFAULT_SYMBOL_TEMPFAIL;
	}
	if ((value = get_module_opt (cfg, "dkim", "symbol_allow")) != NULL) {
		dkim_module_ctx->symbol_allow = ucl_obj_tostring (value);
	}
	else {
		dkim_module_ctx->symbol_allow = DEFAULT_SYMBOL_ALLOW;
	}
	if ((value = get_module_opt (cfg, "dkim", "dkim_cache_size")) != NULL) {
		cache_size = ucl_obj_toint (value);
	}
	else {
		cache_size = DEFAULT_CACHE_SIZE;
	}
	if ((value = get_module_opt (cfg, "dkim", "dkim_cache_expire")) != NULL) {
		cache_expire = ucl_obj_todouble (value);
	}
	else {
		cache_expire = DEFAULT_CACHE_MAXAGE;
	}
	if ((value = get_module_opt (cfg, "dkim", "time_jitter")) != NULL) {
		dkim_module_ctx->time_jitter = ucl_obj_todouble (value);
	}
	else {
		dkim_module_ctx->time_jitter = DEFAULT_TIME_JITTER;
	}
	if ((value = get_module_opt (cfg, "dkim", "whitelist")) != NULL) {
		if (! add_map (cfg, ucl_obj_tostring (value),
				"DKIM whitelist", read_radix_list, fin_radix_list,
				(void **)&dkim_module_ctx->whitelist_ip)) {
			msg_warn ("cannot load whitelist from %s", ucl_obj_tostring (value));
		}
	}
	if ((value = get_module_opt (cfg, "dkim", "domains")) != NULL) {
		if (! add_map (cfg, ucl_obj_tostring (value),
				"DKIM domains", read_kv_list, fin_kv_list,
				(void **)&dkim_module_ctx->dkim_domains)) {
			msg_warn ("cannot load dkim domains list from %s", ucl_obj_tostring (value));
		}
		else {
			got_trusted = TRUE;
		}
	}
	if ((value = get_module_opt (cfg, "dkim", "strict_multiplier")) != NULL) {
		dkim_module_ctx->strict_multiplier = ucl_obj_toint (value);
	}
	else {
		dkim_module_ctx->strict_multiplier = 1;
	}
	if ((value = get_module_opt (cfg, "dkim", "trusted_only")) != NULL) {
		dkim_module_ctx->trusted_only = ucl_obj_toboolean (value);
	}
	else {
		dkim_module_ctx->trusted_only = FALSE;
	}
	if ((value = get_module_opt (cfg, "dkim", "skip_multi")) != NULL) {
		dkim_module_ctx->skip_multi = ucl_obj_toboolean (value);
	}
	else {
		dkim_module_ctx->skip_multi = FALSE;
	}

	if (dkim_module_ctx->trusted_only && !got_trusted) {
		msg_err ("trusted_only option is set and no trusted domains are defined; disabling dkim module completely as it is useless in this case");
	}
	else {
		register_symbol (&cfg->cache, dkim_module_ctx->symbol_reject, 1, dkim_symbol_callback, NULL);
		register_virtual_symbol (&cfg->cache, dkim_module_ctx->symbol_tempfail, 1);
		register_virtual_symbol (&cfg->cache, dkim_module_ctx->symbol_allow, 1);

		dkim_module_ctx->dkim_hash = rspamd_lru_hash_new (rspamd_strcase_hash, rspamd_strcase_equal,
				cache_size, cache_expire, g_free, (GDestroyNotify)rspamd_dkim_key_free);


#ifndef HAVE_OPENSSL
		msg_warn ("openssl is not found so dkim rsa check is disabled, only check body hash, it is NOT safe to trust these results");
#endif
	}

	return res;
}

gint
dkim_module_reconfig (struct config_file *cfg)
{
	rspamd_mempool_delete (dkim_module_ctx->dkim_pool);
	radix_tree_free (dkim_module_ctx->whitelist_ip);
	if (dkim_module_ctx->dkim_domains) {
		g_hash_table_destroy (dkim_module_ctx->dkim_domains);
	}
	dkim_module_ctx->dkim_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	return dkim_module_config (cfg);
}

/*
 * Parse strict value for domain in format: 'reject_multiplier:deny_multiplier'
 */
static gboolean
dkim_module_parse_strict (const gchar *value, gint *allow, gint *deny)
{
	const gchar							*colon;
	gulong								 val;

	colon = strchr (value, ':');
	if (colon) {
		if (rspamd_strtoul (value, colon - value, &val)) {
			*deny = val;
			colon ++;
			if (rspamd_strtoul (colon, strlen (colon), &val)) {
				*allow = val;
				return TRUE;
			}
		}
	}
	return FALSE;
}

static void
dkim_module_check (struct rspamd_task *task, rspamd_dkim_context_t *ctx, rspamd_dkim_key_t *key)
{
	gint								 res, score_allow = 1, score_deny = 1;
	const gchar							*strict_value;

	msg_debug ("check dkim signature for %s domain from %s", ctx->domain, ctx->dns_key);
	res = rspamd_dkim_check (ctx, key, task);

	if (dkim_module_ctx->dkim_domains != NULL) {
		/* Perform strict check */
		if ((strict_value = g_hash_table_lookup (dkim_module_ctx->dkim_domains, ctx->domain)) != NULL) {
			if (!dkim_module_parse_strict (strict_value, &score_allow, &score_deny)) {
				score_allow = dkim_module_ctx->strict_multiplier;
				score_deny = dkim_module_ctx->strict_multiplier;
				msg_debug ("no specific score found for %s domain, using %d for it", ctx->domain, score_deny);
			}
			else {
				msg_debug ("specific score found for %s domain: using %d for deny and %d for allow",
						ctx->dns_key, score_deny, score_allow);
			}
		}
	}

	if (res == DKIM_REJECT) {
		insert_result (task, dkim_module_ctx->symbol_reject, score_deny, NULL);
	}
	else if (res == DKIM_TRYAGAIN) {
		insert_result (task, dkim_module_ctx->symbol_tempfail, 1, NULL);
	}
	else if (res == DKIM_CONTINUE) {
		insert_result (task, dkim_module_ctx->symbol_allow, score_allow, NULL);
	}
}

static void
dkim_module_key_handler (rspamd_dkim_key_t *key, gsize keylen, rspamd_dkim_context_t *ctx, gpointer ud, GError *err)
{
	struct rspamd_task					*task = ud;


	if (key != NULL) {
		/* Add new key to the lru cache */
		rspamd_lru_hash_insert (dkim_module_ctx->dkim_hash, g_strdup (ctx->dns_key),
				key, task->tv.tv_sec, key->ttl);
		dkim_module_check (task, ctx, key);
	}
	else {
		/* Insert tempfail symbol */
		msg_info ("cannot get key for domain %s", ctx->dns_key);
		if (err != NULL) {
			insert_result (task, dkim_module_ctx->symbol_tempfail, 1,
					g_list_prepend (NULL, rspamd_mempool_strdup (task->task_pool, err->message)));

		}
		else {
			insert_result (task, dkim_module_ctx->symbol_tempfail, 1, NULL);
		}
	}

	if (err) {
		g_error_free (err);
	}
}

static void
dkim_symbol_callback (struct rspamd_task *task, void *unused)
{
	GList								*hlist;
	rspamd_dkim_context_t				*ctx;
	rspamd_dkim_key_t					*key;
	GError								*err = NULL;
	/* First check if a message has its signature */

	hlist = message_get_header (task->task_pool, task->message, DKIM_SIGNHEADER, FALSE);
	if (hlist != NULL) {
		/* Check whitelist */
		msg_debug ("dkim signature found");
#ifdef HAVE_INET_PTON
		if (!task->from_addr.has_addr ||
				radix32tree_find (dkim_module_ctx->whitelist_ip, ntohl (task->from_addr.d.in4.s_addr)) == RADIX_NO_VALUE) {
#else
		if (radix32tree_find (dkim_module_ctx->whitelist_ip, ntohl (task->from_addr.s_addr)) == RADIX_NO_VALUE) {
#endif
			/* Parse signature */
			msg_debug ("create dkim signature");
			/*
			 * Check only last signature as there is no way to check embeded signatures after
			 * resend or something like this
			 */
			if (dkim_module_ctx->skip_multi) {
				if (hlist->next != NULL) {
					msg_info ("<%s> skip dkim check as it has several dkim signatures", task->message_id);
					return;
				}
			}
			hlist = g_list_last (hlist);
			ctx = rspamd_create_dkim_context (hlist->data, task->task_pool, dkim_module_ctx->time_jitter, &err);
			if (ctx == NULL) {
				msg_info ("cannot parse DKIM context: %s", err->message);
				g_error_free (err);
			}
			else {
				/* Get key */
				if (dkim_module_ctx->trusted_only && (dkim_module_ctx->dkim_domains == NULL ||
						g_hash_table_lookup (dkim_module_ctx->dkim_domains, ctx->domain) == NULL)) {
					msg_debug ("skip dkim check for %s domain", ctx->domain);
					return;
				}
				key = rspamd_lru_hash_lookup (dkim_module_ctx->dkim_hash, ctx->dns_key, task->tv.tv_sec);
				if (key != NULL) {
					debug_task ("found key for %s in cache", ctx->dns_key);
					dkim_module_check (task, ctx, key);
				}
				else {
					debug_task ("request key for %s from DNS", ctx->dns_key);
					task->dns_requests ++;
					rspamd_get_dkim_key (ctx, task->resolver, task->s, dkim_module_key_handler, task);
				}
			}
		}
	}
}
