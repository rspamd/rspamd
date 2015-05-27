/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#include "main.h"

#define DEFAULT_SYMBOL_FAIL "R_SPF_FAIL"
#define DEFAULT_SYMBOL_SOFTFAIL "R_SPF_SOFTFAIL"
#define DEFAULT_SYMBOL_NEUTRAL "R_SPF_NEUTRAL"
#define DEFAULT_SYMBOL_ALLOW "R_SPF_ALLOW"
#define DEFAULT_CACHE_SIZE 2048
#define DEFAULT_CACHE_MAXAGE 86400

struct spf_ctx {
	struct module_ctx ctx;
	const gchar *symbol_fail;
	const gchar *symbol_softfail;
	const gchar *symbol_neutral;
	const gchar *symbol_allow;

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
	NULL
};

gint
spf_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	spf_module_ctx = g_malloc (sizeof (struct spf_ctx));

	spf_module_ctx->spf_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	*ctx = (struct module_ctx *)spf_module_ctx;

	return 0;
}


gint
spf_module_config (struct rspamd_config *cfg)
{
	const ucl_object_t *value;
	gint res = TRUE;
	guint cache_size, cache_expire;

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
		rspamd_config_get_module_opt (cfg, "spf", "spf_cache_size")) != NULL) {
		cache_size = ucl_obj_toint (value);
	}
	else {
		cache_size = DEFAULT_CACHE_SIZE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf",
		"spf_cache_expire")) != NULL) {
		cache_expire = ucl_obj_toint (value);
	}
	else {
		cache_expire = DEFAULT_CACHE_MAXAGE;
	}
	if ((value =
		rspamd_config_get_module_opt (cfg, "spf", "whitelist")) != NULL) {
		if (!rspamd_map_add (cfg, ucl_obj_tostring (value),
			"SPF whitelist", rspamd_radix_read, rspamd_radix_fin,
			(void **)&spf_module_ctx->whitelist_ip)) {
			radix_add_generic_iplist (ucl_obj_tostring (value),
				&spf_module_ctx->whitelist_ip);
		}
	}

	register_symbol (cfg->cache,
		spf_module_ctx->symbol_fail,
		1,
		spf_symbol_callback,
		NULL);
	register_virtual_symbol (cfg->cache, spf_module_ctx->symbol_softfail, 1);
	register_virtual_symbol (cfg->cache, spf_module_ctx->symbol_neutral,  1);
	register_virtual_symbol (cfg->cache, spf_module_ctx->symbol_allow,	   1);

	spf_module_ctx->spf_hash = rspamd_lru_hash_new (
			cache_size,
			cache_expire,
			NULL,
			(GDestroyNotify)spf_record_unref);

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
	spf_module_ctx->spf_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	return spf_module_config (cfg);
}

static gboolean
spf_check_element (struct spf_addr *addr, struct rspamd_task *task)
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

	af = rspamd_inet_address_get_af (task->from_addr);
	/* Basic comparing algorithm */
	if (((addr->flags & RSPAMD_SPF_FLAG_IPV6) && af == AF_INET6) ||
		((addr->flags & RSPAMD_SPF_FLAG_IPV4) && af == AF_INET)) {
		d = rspamd_inet_address_get_radix_key (task->from_addr, &addrlen);

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
			msg_info ("bad mask length: %d", mask);
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
			break;
		case SPF_SOFT_FAIL:
			spf_symbol = spf_module_ctx->symbol_softfail;
			spf_message = "(SPF): spf softfail";
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
		if (spf_check_element (addr, task)) {
			break;
		}
	}
}

static void
spf_plugin_callback (struct spf_resolved *record, struct rspamd_task *task)
{
	struct spf_resolved *l;

	if (record && record->elts->len > 0 && record->domain) {

		if ((l =
			rspamd_lru_hash_lookup (spf_module_ctx->spf_hash,
			record->domain, task->tv.tv_sec)) == NULL) {

			l = spf_record_ref (record);
			rspamd_lru_hash_insert (spf_module_ctx->spf_hash,
				record->domain, l,
				task->tv.tv_sec, record->ttl);

		}
		spf_record_ref (l);
		spf_check_list (l, task);
		spf_record_unref (l);
	}
}


static void
spf_symbol_callback (struct rspamd_task *task, void *unused)
{
	const gchar *domain;
	struct spf_resolved *l;

	if (radix_find_compressed_addr (spf_module_ctx->whitelist_ip,
			task->from_addr) == RADIX_NO_VALUE) {
		domain = get_spf_domain (task);
		if (domain) {
			if ((l =
				rspamd_lru_hash_lookup (spf_module_ctx->spf_hash, domain,
				task->tv.tv_sec)) != NULL) {
				spf_record_ref (l);
				spf_check_list (l, task);
				spf_record_unref (l);
			}
			else if (!resolve_spf (task, spf_plugin_callback)) {
				msg_info ("cannot make spf request for [%s]", task->message_id);
			}
		}
	}
}
