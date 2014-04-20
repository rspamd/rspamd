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
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "expressions.h"
#include "util.h"
#include "view.h"
#include "map.h"
#include "spf.h"
#include "hash.h"

#define DEFAULT_SYMBOL_FAIL "R_SPF_FAIL"
#define DEFAULT_SYMBOL_SOFTFAIL "R_SPF_SOFTFAIL"
#define DEFAULT_SYMBOL_ALLOW "R_SPF_ALLOW"
#define DEFAULT_CACHE_SIZE 2048
#define DEFAULT_CACHE_MAXAGE 86400

struct spf_ctx {
	gint                            (*filter) (struct worker_task * task);
	const gchar                    *symbol_fail;
	const gchar                    *symbol_softfail;
	const gchar                    *symbol_allow;

	rspamd_mempool_t                   *spf_pool;
	radix_tree_t                    *whitelist_ip;
	rspamd_lru_hash_t               *spf_hash;
};

static struct spf_ctx        *spf_module_ctx = NULL;

static void                   spf_symbol_callback (struct worker_task *task, void *unused);
static GList *                spf_record_copy (GList *addrs);
static void                   spf_record_destroy (gpointer list);

/* Initialization */
gint spf_module_init (struct config_file *cfg, struct module_ctx **ctx);
gint spf_module_config (struct config_file *cfg);
gint spf_module_reconfig (struct config_file *cfg);

module_t spf_module = {
	"spf",
	spf_module_init,
	spf_module_config,
	spf_module_reconfig
};

gint
spf_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	spf_module_ctx = g_malloc (sizeof (struct spf_ctx));

	spf_module_ctx->spf_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	*ctx = (struct module_ctx *)spf_module_ctx;

	return 0;
}


gint
spf_module_config (struct config_file *cfg)
{
	const ucl_object_t             *value;
	gint                            res = TRUE;
	guint                           cache_size, cache_expire;

	spf_module_ctx->whitelist_ip = radix_tree_create ();
	
	if ((value = get_module_opt (cfg, "spf", "symbol_fail")) != NULL) {
		spf_module_ctx->symbol_fail = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_fail = DEFAULT_SYMBOL_FAIL;
	}
	if ((value = get_module_opt (cfg, "spf", "symbol_softfail")) != NULL) {
		spf_module_ctx->symbol_softfail = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_softfail = DEFAULT_SYMBOL_SOFTFAIL;
	}
	if ((value = get_module_opt (cfg, "spf", "symbol_allow")) != NULL) {
		spf_module_ctx->symbol_allow = ucl_obj_tostring (value);
	}
	else {
		spf_module_ctx->symbol_allow = DEFAULT_SYMBOL_ALLOW;
	}
	if ((value = get_module_opt (cfg, "spf", "spf_cache_size")) != NULL) {
		cache_size = ucl_obj_toint (value);
	}
	else {
		cache_size = DEFAULT_CACHE_SIZE;
	}
	if ((value = get_module_opt (cfg, "spf", "spf_cache_expire")) != NULL) {
		cache_expire = ucl_obj_toint (value);
	}
	else {
		cache_expire = DEFAULT_CACHE_MAXAGE;
	}
	if ((value = get_module_opt (cfg, "spf", "whitelist")) != NULL) {
		if (! add_map (cfg, ucl_obj_tostring (value),
				"SPF whitelist", read_radix_list, fin_radix_list,
				(void **)&spf_module_ctx->whitelist_ip)) {
			msg_warn ("cannot load whitelist from %s", value);
		}
	}

	register_symbol (&cfg->cache, spf_module_ctx->symbol_fail, 1, spf_symbol_callback, NULL);
	register_virtual_symbol (&cfg->cache, spf_module_ctx->symbol_softfail, 1);
	register_virtual_symbol (&cfg->cache, spf_module_ctx->symbol_allow, 1);

	spf_module_ctx->spf_hash = rspamd_lru_hash_new (rspamd_strcase_hash, rspamd_strcase_equal,
			cache_size, cache_expire, g_free, spf_record_destroy);

	return res;
}

gint
spf_module_reconfig (struct config_file *cfg)
{
	rspamd_mempool_delete (spf_module_ctx->spf_pool);
	radix_tree_free (spf_module_ctx->whitelist_ip);
	spf_module_ctx->spf_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());

	return spf_module_config (cfg);
}

static gboolean
spf_check_element (struct spf_addr *addr, struct worker_task *task)
{
	gboolean                        res = FALSE;
#ifdef HAVE_INET_PTON
	guint8                         *s, *d, t;
	guint                           nbits, addrlen;
	struct in_addr					in4s, in4d;
	struct in6_addr                 in6s, in6d;

	/* Basic comparing algorithm */
	if (addr->data.normal.ipv6 == task->from_addr.ipv6) {
		if (addr->data.normal.ipv6) {
			addrlen = sizeof (struct in6_addr);
			memcpy (&in6s, &addr->data.normal.d.in6, sizeof (struct in6_addr));
			memcpy (&in6d, &task->from_addr.d.in6, sizeof (struct in6_addr));
			s = (guint8 *)&in6s;
			d = (guint8 *)&in6d;
		}
		else {
			addrlen = sizeof (struct in_addr);
			memcpy (&in4s, &addr->data.normal.d.in4, sizeof (struct in_addr));
			memcpy (&in4d, &task->from_addr.d.in4, sizeof (struct in_addr));
			s = (guint8 *)&in4s;
			d = (guint8 *)&in4d;
		}
		/* Move pointers to the less significant byte */
		t = 0x1;
		s += addrlen - 1;
		d += addrlen - 1;
		/* TODO: improve this cycle by masking by words */
		for (nbits = 0; nbits < addrlen * CHAR_BIT - addr->data.normal.mask; nbits ++) {
			/* Skip bits from the beginning as we know that data is in network byte order */
			if (nbits != 0 && nbits % 8 == 0) {
				/* Move pointer to the next byte */
				s --;
				d --;
				t = 0x1;
			}
			*s |= t;
			*d |= t;
			t <<= 1;
		}
		if (addr->data.normal.ipv6) {
			res = memcmp (&in6d, &in6s, sizeof (struct in6_addr)) == 0;
		}
		else {
			res = memcmp (&in4d, &in4s, sizeof (struct in_addr)) == 0;
		}
	}
	else {
		if (addr->data.normal.addr_any) {
			res = TRUE;
		}
		else {
			res = FALSE;
		}
	}
#else
	guint32                         s, m;

	if (addr->data.normal.mask == 0) {
		m = 0;
	}
	else {
		m = htonl (G_MAXUINT32 << (32 - addr->data.normal.mask));
	}
	s = task->from_addr.s_addr;
	res = (s & m) == (addr->data.normal.d.in4.s_addr & m);
#endif

	if (res) {
		switch (addr->mech) {
		case SPF_FAIL:
			insert_result (task, spf_module_ctx->symbol_fail, 1, g_list_prepend (NULL, addr->spf_string));
			task->messages = g_list_prepend (task->messages, "(SPF): spf fail");
			break;
		case SPF_SOFT_FAIL:
		case SPF_NEUTRAL:
			insert_result (task, spf_module_ctx->symbol_softfail, 1, g_list_prepend (NULL, addr->spf_string));
			task->messages = g_list_prepend (task->messages, "(SPF): spf softfail");
			break;
		default:
			insert_result (task, spf_module_ctx->symbol_allow, 1, g_list_prepend (NULL, addr->spf_string));
			task->messages = g_list_prepend (task->messages, "(SPF): spf allow");
			break;
		}
		return TRUE;
	}

	return FALSE;
}

static gboolean
spf_check_list (GList *list, struct worker_task *task)
{
	GList                           *cur;
	struct spf_addr                 *addr;

	cur = list;

	while (cur) {
		addr = cur->data;
		if (addr->is_list) {
			/* Recursive call */
			if (spf_check_list (addr->data.list, task)) {
				return TRUE;
			}
		}
		else {
			if (spf_check_element (addr, task)) {
				return TRUE;
			}
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

static void 
spf_plugin_callback (struct spf_record *record, struct worker_task *task)
{
	GList                           *l;

	if (record && record->addrs && record->sender_domain) {

		if ((l = rspamd_lru_hash_lookup (spf_module_ctx->spf_hash, record->sender_domain, task->tv.tv_sec)) == NULL) {
			l = spf_record_copy (record->addrs);
			rspamd_lru_hash_insert (spf_module_ctx->spf_hash, g_strdup (record->sender_domain),
				l, task->tv.tv_sec, record->ttl);
		}
		spf_check_list (l, task);
	}
}


static void 
spf_symbol_callback (struct worker_task *task, void *unused)
{
	gchar                           *domain;
	GList                           *l;

#ifdef HAVE_INET_PTON
	if (task->from_addr.has_addr) {
		if (TRUE) {
#else
	if (task->from_addr.s_addr != INADDR_NONE && task->from_addr.s_addr != INADDR_ANY) {
		if (radix32tree_find (spf_module_ctx->whitelist_ip, ntohl (task->from_addr.s_addr)) == RADIX_NO_VALUE) {
#endif
			domain = get_spf_domain (task);
			if (domain) {
				if ((l = rspamd_lru_hash_lookup (spf_module_ctx->spf_hash, domain, task->tv.tv_sec)) != NULL) {
					spf_check_list (l, task);
				}
				else if (!resolve_spf (task, spf_plugin_callback)) {
					msg_info ("cannot make spf request for [%s]", task->message_id);
				}
			}
		}
#ifndef HAVE_INET_PTON
		else {
			msg_info ("ip %s is whitelisted for spf checks", inet_ntoa (task->from_addr));
		}
#endif
	}
}

/*
 * Make a deep copy of list, note copy is REVERSED
 */
static GList *
spf_record_copy (GList *addrs)
{
	GList                           *cur, *newl = NULL;
	struct spf_addr                 *addr, *newa;

	cur = addrs;

	while (cur) {
		addr = cur->data;
		newa = g_malloc (sizeof (struct spf_addr));
		memcpy (newa, addr, sizeof (struct spf_addr));
		if (addr->is_list) {
			/* Recursive call */
			newa->data.list = spf_record_copy (addr->data.list);
		}
		else {
			if (addr->spf_string) {
				newa->spf_string = g_strdup (addr->spf_string);
			}
		}
		newl = g_list_prepend (newl, newa);
		cur = g_list_next (cur);
	}

	return newl;
}

/*
 * Destroy allocated spf list
 */


static void
spf_record_destroy (gpointer list)
{
	GList                           *cur = list;
	struct spf_addr                 *addr;

	while (cur) {
		addr = cur->data;
		if (addr->is_list) {
			spf_record_destroy (addr->data.list);
		}
		else {
			if (addr->spf_string) {
				g_free (addr->spf_string);
			}
		}
		g_free (addr);
		cur = g_list_next (cur);
	}

	g_list_free (list);
}
