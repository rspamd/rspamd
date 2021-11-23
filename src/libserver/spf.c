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

#include "config.h"
#include "dns.h"
#include "spf.h"
#include "rspamd.h"
#include "message.h"
#include "utlist.h"
#include "libserver/mempool_vars_internal.h"
#include "contrib/librdns/rdns.h"
#include "contrib/mumhash/mum.h"

#define SPF_VER1_STR "v=spf1"
#define SPF_VER2_STR "spf2."
#define SPF_SCOPE_PRA "pra"
#define SPF_SCOPE_MFROM "mfrom"
#define SPF_ALL "all"
#define SPF_A "a"
#define SPF_IP4 "ip4"
#define SPF_IP4_ALT "ipv4"
#define SPF_IP6 "ip6"
#define SPF_IP6_ALT "ipv6"
#define SPF_PTR "ptr"
#define SPF_MX "mx"
#define SPF_EXISTS "exists"
#define SPF_INCLUDE "include"
#define SPF_REDIRECT "redirect"
#define SPF_EXP "exp"

struct spf_resolved_element {
	GPtrArray *elts;
	gchar *cur_domain;
	gboolean redirected; /* Ingnore level, it's redirected */
};

struct spf_record {
	gint nested;
	gint dns_requests;
	gint requests_inflight;

	guint ttl;
	GPtrArray *resolved;
	/* Array of struct spf_resolved_element */
	const gchar *sender;
	const gchar *sender_domain;
	const gchar *top_record;
	gchar *local_part;
	struct rspamd_task *task;
	spf_cb_t callback;
	gpointer cbdata;
	gboolean done;
};

struct rspamd_spf_library_ctx {
	guint max_dns_nesting;
	guint max_dns_requests;
	guint min_cache_ttl;
	gboolean disable_ipv6;
	rspamd_lru_hash_t *spf_hash;
};

struct rspamd_spf_library_ctx *spf_lib_ctx = NULL;

/**
 * BNF for SPF record:
 *
 * spf_mech ::= +|-|~|?
 *
 * spf_body ::= spf=v1 <spf_command> [<spf_command>]
 * spf_command ::= [spf_mech]all|a|<ip4>|<ip6>|ptr|mx|<exists>|<include>|<redirect>
 *
 * spf_domain ::= [:domain][/mask]
 * spf_ip4 ::= ip[/mask]
 * ip4 ::= ip4:<spf_ip4>
 * mx ::= mx<spf_domain>
 * a ::= a<spf_domain>
 * ptr ::= ptr[:domain]
 * exists ::= exists:domain
 * include ::= include:domain
 * redirect ::= redirect:domain
 * exp ::= exp:domain
 *
 */

#undef SPF_DEBUG

#define msg_err_spf(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "spf", rec->task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_spf(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "spf", rec->task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_spf(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "spf", rec->task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_spf(...)  rspamd_conditional_debug_fast (NULL, rec->task->from_addr, \
        rspamd_spf_log_id, "spf", rec->task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_spf_flatten(...)  rspamd_conditional_debug_fast_num_id (NULL, NULL, \
        rspamd_spf_log_id, "spf", (flat)->digest, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(spf)

struct spf_dns_cb {
	struct spf_record *rec;
	struct spf_addr *addr;
	struct spf_resolved_element *resolved;
	const gchar *ptr_host;
	spf_action_t cur_action;
	gboolean in_include;
};

#define CHECK_REC(rec)                                          \
    do {                                                        \
        if (spf_lib_ctx->max_dns_nesting > 0 &&                 \
            (rec)->nested > spf_lib_ctx->max_dns_nesting) {     \
            msg_warn_spf ("spf nesting limit: %d > %d is reached, domain: %s", \
                (rec)->nested,  spf_lib_ctx->max_dns_nesting,   \
                (rec)->sender_domain);                          \
            return FALSE;                                       \
        }                                                       \
        if (spf_lib_ctx->max_dns_requests > 0 &&                \
            (rec)->dns_requests > spf_lib_ctx->max_dns_requests) {     \
            msg_warn_spf ("spf dns requests limit: %d > %d is reached, domain: %s", \
                (rec)->dns_requests,  spf_lib_ctx->max_dns_requests, \
                (rec)->sender_domain);                          \
            return FALSE;                                       \
        }                                                       \
    } while (0)                                                 \

RSPAMD_CONSTRUCTOR(rspamd_spf_lib_ctx_ctor) {
	spf_lib_ctx = g_malloc0 (sizeof (*spf_lib_ctx));
	spf_lib_ctx->max_dns_nesting = SPF_MAX_NESTING;
	spf_lib_ctx->max_dns_requests = SPF_MAX_DNS_REQUESTS;
	spf_lib_ctx->min_cache_ttl = SPF_MIN_CACHE_TTL;
	spf_lib_ctx->disable_ipv6 = FALSE;
}

RSPAMD_DESTRUCTOR(rspamd_spf_lib_ctx_dtor) {
	if (spf_lib_ctx->spf_hash) {
		rspamd_lru_hash_destroy (spf_lib_ctx->spf_hash);
	}
	g_free (spf_lib_ctx);
	spf_lib_ctx = NULL;
}

static void
spf_record_cached_unref_dtor (gpointer p)
{
	struct spf_resolved *flat = (struct spf_resolved *)p;

	_spf_record_unref (flat, "LRU cache");
}

void
spf_library_config (const ucl_object_t *obj)
{
	const ucl_object_t *value;
	gint64 ival;
	bool bval;

	if (obj == NULL) {
		/* No specific config */
		return;
	}

	if ((value = ucl_object_find_key (obj, "min_cache_ttl")) != NULL) {
		if (ucl_object_toint_safe (value, &ival) && ival >= 0) {
			spf_lib_ctx->min_cache_ttl = ival;
		}
	}

	if ((value = ucl_object_find_key (obj, "max_dns_nesting")) != NULL) {
		if (ucl_object_toint_safe (value, &ival) && ival >= 0) {
			spf_lib_ctx->max_dns_nesting = ival;
		}
	}

	if ((value = ucl_object_find_key (obj, "max_dns_requests")) != NULL) {
		if (ucl_object_toint_safe (value, &ival) && ival >= 0) {
			spf_lib_ctx->max_dns_requests = ival;
		}
	}
	if ((value = ucl_object_find_key (obj, "disable_ipv6")) != NULL) {
		if (ucl_object_toboolean_safe (value, &bval)) {
			spf_lib_ctx->disable_ipv6 = bval;
		}
	}

	if ((value = ucl_object_find_key (obj, "disable_ipv6")) != NULL) {
		if (ucl_object_toboolean_safe (value, &bval)) {
			spf_lib_ctx->disable_ipv6 = bval;
		}
	}

	if (spf_lib_ctx->spf_hash) {
		rspamd_lru_hash_destroy (spf_lib_ctx->spf_hash);
		spf_lib_ctx->spf_hash = NULL;
	}

	if ((value = ucl_object_find_key (obj, "spf_cache_size")) != NULL) {
		if (ucl_object_toint_safe (value, &ival) && ival > 0) {
			spf_lib_ctx->spf_hash = rspamd_lru_hash_new (
					ival,
					g_free,
					spf_record_cached_unref_dtor);
		}
	}
	else {
		/* Preserve compatibility */
		spf_lib_ctx->spf_hash = rspamd_lru_hash_new (
				2048,
				g_free,
				spf_record_cached_unref_dtor);
	}
}

static gboolean start_spf_parse (struct spf_record *rec,
		struct spf_resolved_element *resolved, gchar *begin);

/* Determine spf mech */
static spf_mech_t
check_spf_mech (const gchar *elt, gboolean *need_shift)
{
	g_assert (elt != NULL);

	*need_shift = TRUE;

	switch (*elt) {
		case '-':
			return SPF_FAIL;
		case '~':
			return SPF_SOFT_FAIL;
		case '+':
			return SPF_PASS;
		case '?':
			return SPF_NEUTRAL;
		default:
			*need_shift = FALSE;
			return SPF_PASS;
	}
}

static const gchar *
rspamd_spf_dns_action_to_str (spf_action_t act)
{
	const char *ret = "unknown";

	switch (act) {
	case SPF_RESOLVE_MX:
		ret = "MX";
		break;
	case SPF_RESOLVE_A:
		ret = "A";
		break;
	case SPF_RESOLVE_PTR:
		ret = "PTR";
		break;
	case SPF_RESOLVE_AAA:
		ret = "AAAA";
		break;
	case SPF_RESOLVE_REDIRECT:
		ret = "REDIRECT";
		break;
	case SPF_RESOLVE_INCLUDE:
		ret = "INCLUDE";
		break;
	case SPF_RESOLVE_EXISTS:
		ret = "EXISTS";
		break;
	case SPF_RESOLVE_EXP:
		ret = "EXP";
		break;
	}

	return ret;
}

static struct spf_addr *
rspamd_spf_new_addr (struct spf_record *rec,
		struct spf_resolved_element *resolved, const gchar *elt)
{
	gboolean need_shift = FALSE;
	struct spf_addr *naddr;

	naddr = g_malloc0 (sizeof (*naddr));
	naddr->mech = check_spf_mech (elt, &need_shift);

	if (need_shift) {
		naddr->spf_string = g_strdup (elt + 1);
	}
	else {
		naddr->spf_string = g_strdup (elt);
	}

	g_ptr_array_add (resolved->elts, naddr);
	naddr->prev = naddr;
	naddr->next = NULL;

	return naddr;
}

static void
rspamd_spf_free_addr (gpointer a)
{
	struct spf_addr *addr = a, *tmp, *cur;

	if (addr) {
		g_free (addr->spf_string);
		DL_FOREACH_SAFE (addr, cur, tmp) {
			g_free (cur);
		}
	}
}

static struct spf_resolved_element *
rspamd_spf_new_addr_list (struct spf_record *rec, const gchar *domain)
{
	struct spf_resolved_element *resolved;

	resolved = g_malloc0 (sizeof (*resolved));
	resolved->redirected = FALSE;
	resolved->cur_domain = g_strdup (domain);
	resolved->elts = g_ptr_array_new_full (8, rspamd_spf_free_addr);

	g_ptr_array_add (rec->resolved, resolved);

	return g_ptr_array_index (rec->resolved, rec->resolved->len - 1);
}

/*
 * Destructor for spf record
 */
static void
spf_record_destructor (gpointer r)
{
	struct spf_record *rec = r;
	struct spf_resolved_element *elt;
	guint i;

	if (rec) {
		for (i = 0; i < rec->resolved->len; i++) {
			elt = g_ptr_array_index (rec->resolved, i);
			g_ptr_array_free (elt->elts, TRUE);
			g_free (elt->cur_domain);
			g_free (elt);
		}

		g_ptr_array_free (rec->resolved, TRUE);
	}
}

static void
rspamd_flatten_record_dtor (struct spf_resolved *r)
{
	struct spf_addr *addr;
	guint i;

	for (i = 0; i < r->elts->len; i++) {
		addr = &g_array_index (r->elts, struct spf_addr, i);
		g_free (addr->spf_string);
	}

	g_free (r->top_record);
	g_free (r->domain);
	g_array_free (r->elts, TRUE);
	g_free (r);
}

static void
rspamd_spf_process_reference (struct spf_resolved *target,
		struct spf_addr *addr, struct spf_record *rec, gboolean top)
{
	struct spf_resolved_element *elt, *relt;
	struct spf_addr *cur = NULL, taddr, *cur_addr;
	guint i;

	if (addr) {
		g_assert (addr->m.idx < rec->resolved->len);

		elt = g_ptr_array_index (rec->resolved, addr->m.idx);
	}
	else {
		elt = g_ptr_array_index (rec->resolved, 0);
	}

	if (rec->ttl < target->ttl) {
		msg_debug_spf ("reducing ttl from %d to %d after subrecord processing %s",
				target->ttl, rec->ttl, rec->sender_domain);
		target->ttl = rec->ttl;
	}

	if (elt->redirected) {
		g_assert (elt->elts->len > 0);

		for (i = 0; i < elt->elts->len; i++) {
			cur = g_ptr_array_index (elt->elts, i);
			if (cur->flags & RSPAMD_SPF_FLAG_REDIRECT) {
				break;
			}
		}

		g_assert (cur != NULL);
		if (!(cur->flags & (RSPAMD_SPF_FLAG_PARSED|RSPAMD_SPF_FLAG_RESOLVED))) {
			/* Unresolved redirect */
			msg_info_spf ("redirect to %s cannot be resolved", cur->spf_string);
		}
		else {
			g_assert (cur->flags & RSPAMD_SPF_FLAG_REFERENCE);
			g_assert (cur->m.idx < rec->resolved->len);
			relt = g_ptr_array_index (rec->resolved, cur->m.idx);
			msg_debug_spf ("domain %s is redirected to %s", elt->cur_domain,
					relt->cur_domain);
		}
	}

	for (i = 0; i < elt->elts->len; i++) {
		cur = g_ptr_array_index (elt->elts, i);

		if (cur->flags & RSPAMD_SPF_FLAG_TEMPFAIL) {
			target->flags |= RSPAMD_SPF_RESOLVED_TEMP_FAILED;
			continue;
		}
		if (cur->flags & RSPAMD_SPF_FLAG_PERMFAIL) {
			if (cur->flags & RSPAMD_SPF_FLAG_REDIRECT) {
				target->flags |= RSPAMD_SPF_RESOLVED_PERM_FAILED;
			}
			continue;
		}
		if (cur->flags & RSPAMD_SPF_FLAG_NA) {
			target->flags |= RSPAMD_SPF_RESOLVED_NA;
			continue;
		}
		if (cur->flags & RSPAMD_SPF_FLAG_INVALID) {
			/* Ignore invalid elements */
			continue;
		}
		if ((cur->flags & (RSPAMD_SPF_FLAG_PARSED|RSPAMD_SPF_FLAG_RESOLVED)) !=
				(RSPAMD_SPF_FLAG_RESOLVED|RSPAMD_SPF_FLAG_PARSED)) {
			/* Ignore unparsed addrs */
			continue;
		}
		if (cur->flags & RSPAMD_SPF_FLAG_REFERENCE) {
			/* Process reference */
			if (cur->flags & RSPAMD_SPF_FLAG_REDIRECT) {
				/* Stop on redirected domain */
				rspamd_spf_process_reference (target, cur, rec, top);
				break;
			}
			else {
				rspamd_spf_process_reference (target, cur, rec, FALSE);
			}
		}
		else {
			if ((cur->flags & RSPAMD_SPF_FLAG_ANY) && !top) {
				/* Ignore wide policies in includes */
				continue;
			}

			DL_FOREACH (cur, cur_addr) {
				memcpy (&taddr, cur_addr, sizeof (taddr));
				taddr.spf_string = g_strdup (cur_addr->spf_string);
				g_array_append_val (target->elts, taddr);
			}
		}
	}
}

/*
 * Parse record and flatten it to a simple structure
 */
static struct spf_resolved *
rspamd_spf_record_flatten (struct spf_record *rec)
{
	struct spf_resolved *res;

	g_assert (rec != NULL);

	res = g_malloc0 (sizeof (*res));
	res->domain = g_strdup (rec->sender_domain);
	res->ttl = rec->ttl;
	/* Not precise but okay */
	res->timestamp = rec->task->task_timestamp;
	res->digest = mum_hash_init (0xa4aa40bbeec59e2bULL);
	res->top_record = g_strdup (rec->top_record);
	REF_INIT_RETAIN (res, rspamd_flatten_record_dtor);

	if (rec->resolved) {
		res->elts = g_array_sized_new (FALSE, FALSE, sizeof (struct spf_addr),
				rec->resolved->len);

		if (rec->resolved->len > 0) {
			rspamd_spf_process_reference (res, NULL, rec, TRUE);
		}
	}
	else {
		res->elts = g_array_new (FALSE, FALSE, sizeof (struct spf_addr));
	}

	return res;
}

static gint
rspamd_spf_elts_cmp (gconstpointer a, gconstpointer b)
{
	struct spf_addr *addr_a, *addr_b;

	addr_a = (struct spf_addr *)a;
	addr_b = (struct spf_addr *)b;

	if (addr_a->flags == addr_b->flags) {
		if (addr_a->flags & RSPAMD_SPF_FLAG_ANY) {
			return 0;
		}
		else if (addr_a->flags & RSPAMD_SPF_FLAG_IPV4) {
			return (addr_a->m.dual.mask_v4 - addr_b->m.dual.mask_v4) ||
				memcmp (addr_a->addr4, addr_b->addr4, sizeof (addr_a->addr4));
		}
		else if (addr_a->flags & RSPAMD_SPF_FLAG_IPV6) {
			return (addr_a->m.dual.mask_v6 - addr_b->m.dual.mask_v6) ||
			 memcmp (addr_a->addr6, addr_b->addr6, sizeof (addr_a->addr6));
		}
		else {
			return 0;
		}
	}
	else {
		if (addr_a->flags & RSPAMD_SPF_FLAG_ANY) {
			return 1;
		}
		else if (addr_b->flags & RSPAMD_SPF_FLAG_ANY) {
			return -1;
		}
		else if (addr_a->flags & RSPAMD_SPF_FLAG_IPV4) {
			return -1;
		}

		return 1;
	}
}

static void
rspamd_spf_record_postprocess (struct spf_resolved *rec, struct rspamd_task *task)
{
	g_array_sort (rec->elts, rspamd_spf_elts_cmp);

	for (guint i = 0; i < rec->elts->len; i ++) {
		struct spf_addr *cur_addr = &g_array_index (rec->elts, struct spf_addr, i);

		if (cur_addr->flags & RSPAMD_SPF_FLAG_IPV6) {
			guint64 t[3];

			/*
			 * Fill hash entry for ipv6 addr with 2 int64 from ipv6 address,
			 * the remaining int64 has mech + mask
			 */
			memcpy (t, cur_addr->addr6, sizeof (guint64) * 2);
			t[2] = ((guint64) (cur_addr->mech)) << 48u;
			t[2] |= cur_addr->m.dual.mask_v6;

			for (guint j = 0; j < G_N_ELEMENTS (t); j++) {
				rec->digest = mum_hash_step (rec->digest, t[j]);
			}
		}
		else if (cur_addr->flags & RSPAMD_SPF_FLAG_IPV4) {
			guint64 t = 0;

			memcpy (&t, cur_addr->addr4, sizeof (guint32));
			t |= ((guint64) (cur_addr->mech)) << 48u;
			t |= ((guint64) cur_addr->m.dual.mask_v4) << 32u;

			rec->digest = mum_hash_step (rec->digest, t);
		}
	}

	if (spf_lib_ctx->min_cache_ttl > 0) {
		if (rec->ttl != 0 && rec->ttl < spf_lib_ctx->min_cache_ttl) {
			msg_info_task ("increasing ttl from %d to %d as it lower than a limit",
					rec->ttl, spf_lib_ctx->min_cache_ttl);
			rec->ttl = spf_lib_ctx->min_cache_ttl;
		}
	}
}

static void
rspamd_spf_maybe_return (struct spf_record *rec)
{
	struct spf_resolved *flat;
	struct rspamd_task *task = rec->task;
	bool cached = false;

	if (rec->requests_inflight == 0 && !rec->done) {
		flat = rspamd_spf_record_flatten (rec);
		rspamd_spf_record_postprocess (flat, rec->task);

		if (flat->ttl > 0 && flat->flags == 0) {

			if (spf_lib_ctx->spf_hash) {
				rspamd_lru_hash_insert (spf_lib_ctx->spf_hash,
						g_strdup (flat->domain),
						spf_record_ref (flat),
						flat->timestamp, flat->ttl);

				msg_info_task ("stored SPF record for %s (0x%xuL) in LRU cache for %d seconds, "
							   "%d/%d elements in the cache",
						flat->domain,
						flat->digest,
						flat->ttl,
						rspamd_lru_hash_size (spf_lib_ctx->spf_hash),
						rspamd_lru_hash_capacity (spf_lib_ctx->spf_hash));
				cached = true;
			}
		}

		if (!cached) {
			/* Still write a log line */
			msg_info_task ("not stored SPF record for %s (0x%xuL) in LRU cache; flags=%d; ttl=%d",
					flat->domain,
					flat->digest,
					flat->flags,
					flat->ttl);
		}

		rec->callback (flat, rec->task, rec->cbdata);
		spf_record_unref (flat);
		rec->done = TRUE;
	}
}

static gboolean
spf_check_ptr_host (struct spf_dns_cb *cb, const char *name)
{
	const char *dend, *nend, *dstart, *nstart;
	struct spf_record *rec = cb->rec;

	if (cb->ptr_host != NULL) {
		dstart = cb->ptr_host;
	}
	else {
		dstart = cb->resolved->cur_domain;
	}

	if (name == NULL || dstart == NULL) {
		return FALSE;
	}

	msg_debug_spf ("check ptr %s vs %s", name, dstart);

	/* We need to check whether `cur_domain` is a subdomain for `name` */
	dend = dstart + strlen (dstart) - 1;
	nstart = name;
	nend = nstart + strlen (nstart) - 1;

	if (nend <= nstart || dend <= dstart) {
		return FALSE;
	}
	/* Strip last '.' from names */
	if (*nend == '.') {
		nend--;
	}
	if (*dend == '.') {
		dend--;
	}
	if (nend <= nstart || dend <= dstart) {
		return FALSE;
	}

	/* Now compare from end to start */
	for (;;) {
		if (g_ascii_tolower (*dend) != g_ascii_tolower (*nend)) {
			msg_debug_spf ("ptr records mismatch: %s and %s", dend, nend);
			return FALSE;
		}

		if (dend == dstart) {
			break;
		}
		if (nend == nstart) {
			/* Name is shorter than cur_domain */
			return FALSE;
		}
		nend--;
		dend--;
	}

	if (nend > nstart && *(nend - 1) != '.') {
		/* Not a subdomain */
		return FALSE;
	}

	return TRUE;
}

static void
spf_record_process_addr (struct spf_record *rec, struct spf_addr *addr, struct
		rdns_reply_entry *reply)
{
	struct spf_addr *naddr;

	if (!(addr->flags & RSPAMD_SPF_FLAG_PROCESSED)) {
		/* That's the first address */
		if (reply->type == RDNS_REQUEST_AAAA) {
			memcpy (addr->addr6,
					&reply->content.aaa.addr,
					sizeof (addr->addr6));
			addr->flags |= RSPAMD_SPF_FLAG_IPV6;
		}
		else if (reply->type == RDNS_REQUEST_A) {
			memcpy (addr->addr4, &reply->content.a.addr, sizeof (addr->addr4));
			addr->flags |= RSPAMD_SPF_FLAG_IPV4;
		}
		else {
			msg_err_spf (
					"internal error, bad DNS reply is treated as address: %s",
					rdns_strtype (reply->type));
		}

		addr->flags |= RSPAMD_SPF_FLAG_PROCESSED;
	}
	else {
		/* We need to create a new address */
		naddr = g_malloc0 (sizeof (*naddr));
		memcpy (naddr, addr, sizeof (*naddr));
		naddr->next = NULL;
		naddr->prev = NULL;

		if (reply->type == RDNS_REQUEST_AAAA) {
			memcpy (naddr->addr6,
					&reply->content.aaa.addr,
					sizeof (addr->addr6));
			naddr->flags |= RSPAMD_SPF_FLAG_IPV6;
		}
		else if (reply->type == RDNS_REQUEST_A) {
			memcpy (naddr->addr4, &reply->content.a.addr, sizeof (addr->addr4));
			naddr->flags |= RSPAMD_SPF_FLAG_IPV4;
		}
		else {
			msg_err_spf (
					"internal error, bad DNS reply is treated as address: %s",
					rdns_strtype (reply->type));
		}

		DL_APPEND (addr, naddr);
	}
}

static void
spf_record_addr_set (struct spf_addr *addr, gboolean allow_any)
{
	guchar fill;

	if (!(addr->flags & RSPAMD_SPF_FLAG_PROCESSED)) {
		if (allow_any) {
			fill = 0;
			addr->m.dual.mask_v4 = 0;
			addr->m.dual.mask_v6 = 0;
		}
		else {
			fill = 0xff;
		}

		memset (addr->addr4, fill, sizeof (addr->addr4));
		memset (addr->addr6, fill, sizeof (addr->addr6));


		addr->flags |= RSPAMD_SPF_FLAG_IPV4;
		addr->flags |= RSPAMD_SPF_FLAG_IPV6;
	}
}

static gboolean
spf_process_txt_record (struct spf_record *rec, struct spf_resolved_element *resolved,
		struct rdns_reply *reply, struct rdns_reply_entry **pselected)
{
	struct rdns_reply_entry *elt, *selected = NULL;
	gboolean ret = FALSE;

	/*
	 * We prefer spf version 1 as other records are mostly likely garbadge
	 * or incorrect records (e.g. spf2 records)
	 */
	LL_FOREACH (reply->entries, elt) {
		if (elt->type == RDNS_REQUEST_TXT) {
			if (strncmp(elt->content.txt.data, "v=spf1", sizeof("v=spf1") - 1)
				== 0) {
				selected = elt;

				if (pselected != NULL) {
					*pselected = selected;
				}

				break;
			}
		}
	}

	if (!selected) {
		LL_FOREACH (reply->entries, elt) {
			/*
			 * Rubbish spf record? Let's still try to process it, but merely for
			 * TXT RRs
			 */
			if (elt->type == RDNS_REQUEST_TXT) {
				if (start_spf_parse(rec, resolved, elt->content.txt.data)) {
					ret = TRUE;
					if (pselected != NULL) {
						*pselected = elt;
					}
					break;
				}
			}
		}
	}
	else {
		ret = start_spf_parse (rec, resolved, selected->content.txt.data);
	}

	return ret;
}

static void
spf_record_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct spf_dns_cb *cb = arg;
	struct rdns_reply_entry *elt_data;
	struct rspamd_task *task;
	struct spf_addr *addr;
	struct spf_record *rec;
	const struct rdns_request_name *req_name;

	rec = cb->rec;
	task = rec->task;

	cb->rec->requests_inflight--;
	addr = cb->addr;

	if (reply->code == RDNS_RC_NOERROR) {
		req_name = rdns_request_get_name (reply->request, NULL);

		LL_FOREACH (reply->entries, elt_data) {
			/* Adjust ttl if a resolved record has lower ttl than spf record itself */
			if ((guint)elt_data->ttl < rec->ttl) {
				msg_debug_spf ("reducing ttl from %d to %d after DNS resolving",
						rec->ttl, elt_data->ttl);
				rec->ttl = elt_data->ttl;
			}

			switch (cb->cur_action) {
				case SPF_RESOLVE_MX:
					if (elt_data->type == RDNS_REQUEST_MX) {
						/* Now resolve A record for this MX */
						msg_debug_spf ("resolve %s after resolving of MX",
								elt_data->content.mx.name);
						if (rspamd_dns_resolver_request_task_forced (task,
								spf_record_dns_callback, (void *) cb,
								RDNS_REQUEST_A,
								elt_data->content.mx.name)) {
							cb->rec->requests_inflight++;
						}

						if (!spf_lib_ctx->disable_ipv6) {
							if (rspamd_dns_resolver_request_task_forced (task,
									spf_record_dns_callback, (void *) cb,
									RDNS_REQUEST_AAAA,
									elt_data->content.mx.name)) {
								cb->rec->requests_inflight++;
							}
						}
						else {
							msg_debug_spf ("skip AAAA request for MX resolution");
						}
					}
					else {
						cb->addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
						cb->addr->flags &= ~RSPAMD_SPF_FLAG_PERMFAIL;
						msg_debug_spf ("resolved MX addr");
						spf_record_process_addr (rec, addr, elt_data);
					}
					break;
				case SPF_RESOLVE_A:
				case SPF_RESOLVE_AAA:
					cb->addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
					cb->addr->flags &= ~RSPAMD_SPF_FLAG_PERMFAIL;
					spf_record_process_addr (rec, addr, elt_data);
					break;
				case SPF_RESOLVE_PTR:
					if (elt_data->type == RDNS_REQUEST_PTR) {
						/* Validate returned records prior to making A requests */
						if (spf_check_ptr_host (cb,
								elt_data->content.ptr.name)) {
							msg_debug_spf ("resolve PTR %s after resolving of PTR",
									elt_data->content.ptr.name);
							if (rspamd_dns_resolver_request_task_forced (task,
									spf_record_dns_callback, (void *) cb,
									RDNS_REQUEST_A,
									elt_data->content.ptr.name)) {
								cb->rec->requests_inflight++;
							}

							if (!spf_lib_ctx->disable_ipv6) {
								if (rspamd_dns_resolver_request_task_forced (task,
										spf_record_dns_callback, (void *) cb,
										RDNS_REQUEST_AAAA,
										elt_data->content.ptr.name)) {
									cb->rec->requests_inflight++;
								}
							}
							else {
								msg_debug_spf ("skip AAAA request for PTR resolution");
							}
						}
						else {
							cb->addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
							cb->addr->flags &= ~RSPAMD_SPF_FLAG_PERMFAIL;
						}
					}
					else {
						cb->addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
						cb->addr->flags &= ~RSPAMD_SPF_FLAG_PERMFAIL;
						spf_record_process_addr (rec, addr, elt_data);
					}
					break;
				case SPF_RESOLVE_REDIRECT:
					if (elt_data->type == RDNS_REQUEST_TXT) {
						cb->addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
						if (reply->entries) {
							msg_debug_spf ("got redirection record for %s: '%s'",
									req_name->name,
									reply->entries[0].content.txt.data);
						}

						if (!spf_process_txt_record (rec, cb->resolved, reply, NULL)) {
							cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
						}
					}

					goto end;
					break;
				case SPF_RESOLVE_INCLUDE:
					if (elt_data->type == RDNS_REQUEST_TXT) {
						if (reply->entries) {
							msg_debug_spf ("got include record for %s: '%s'",
									req_name->name,
									reply->entries[0].content.txt.data);
						}

						cb->addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
						spf_process_txt_record (rec, cb->resolved, reply, NULL);
					}
					goto end;

					break;
				case SPF_RESOLVE_EXP:
					break;
				case SPF_RESOLVE_EXISTS:
					if (elt_data->type == RDNS_REQUEST_A ||
						elt_data->type == RDNS_REQUEST_AAAA) {
						/*
						 * If specified address resolves, we can accept
						 * connection from every IP
						 */
						addr->flags |= RSPAMD_SPF_FLAG_RESOLVED;
						spf_record_addr_set (addr, TRUE);
					}
					break;
			}
		}
	}
	else if (reply->code == RDNS_RC_NXDOMAIN || reply->code == RDNS_RC_NOREC) {
		switch (cb->cur_action) {
			case SPF_RESOLVE_MX:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
					msg_info_spf (
							"spf error for domain %s: cannot find MX"
							" record for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));
					spf_record_addr_set (addr, FALSE);
				}
				break;
			case SPF_RESOLVE_A:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
					msg_info_spf (
							"spf error for domain %s: cannot resolve A"
							" record for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));

					if (rdns_request_has_type (reply->request, RDNS_REQUEST_A)) {
						spf_record_addr_set (addr, FALSE);
					}
				}
				break;
			case SPF_RESOLVE_AAA:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
					msg_info_spf (
							"spf error for domain %s: cannot resolve AAAA"
							" record for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));
					if (rdns_request_has_type (reply->request, RDNS_REQUEST_AAAA)) {
						spf_record_addr_set (addr, FALSE);
					}
				}
				break;
			case SPF_RESOLVE_PTR:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					msg_info_spf (
							"spf error for domain %s: cannot resolve PTR"
							" record for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));
					cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;

					spf_record_addr_set (addr, FALSE);
				}
				break;
			case SPF_RESOLVE_REDIRECT:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
					msg_info_spf (
							"spf error for domain %s: cannot resolve REDIRECT"
							" record for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));
				}

				break;
			case SPF_RESOLVE_INCLUDE:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					msg_info_spf (
							"spf error for domain %s: cannot resolve INCLUDE"
							" record for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));

					cb->addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
				}
				break;
			case SPF_RESOLVE_EXP:
				break;
			case SPF_RESOLVE_EXISTS:
				if (!(cb->addr->flags & RSPAMD_SPF_FLAG_RESOLVED)) {
					msg_debug_spf (
							"spf macro resolution for domain %s: cannot resolve EXISTS"
							" macro for %s: %s",
							cb->rec->sender_domain,
							cb->resolved->cur_domain,
							rdns_strerror (reply->code));
					spf_record_addr_set (addr, FALSE);
				}
				break;
		}
	}
	else {
		cb->addr->flags |= RSPAMD_SPF_FLAG_TEMPFAIL;
		msg_info_spf (
				"spf error for domain %s: cannot resolve %s DNS record for"
				" %s: %s",
				cb->rec->sender_domain,
				rspamd_spf_dns_action_to_str (cb->cur_action),
				cb->ptr_host,
				rdns_strerror (reply->code));
	}

end:
	rspamd_spf_maybe_return (cb->rec);
}

/*
 * The syntax defined by the following BNF:
 * [ ":" domain-spec ] [ dual-cidr-length ]
 * ip4-cidr-length  = "/" 1*DIGIT
 * ip6-cidr-length  = "/" 1*DIGIT
 * dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
 */
static const gchar *
parse_spf_domain_mask (struct spf_record *rec, struct spf_addr *addr,
		struct spf_resolved_element *resolved,
		gboolean allow_mask)
{
	struct rspamd_task *task = rec->task;
	enum {
		parse_spf_elt = 0,
		parse_semicolon,
		parse_domain,
		parse_slash,
		parse_ipv4_mask,
		parse_second_slash,
		parse_ipv6_mask,
		skip_garbadge
	} state = 0;
	const gchar *p = addr->spf_string, *host, *c;
	gchar *hostbuf;
	gchar t;
	guint16 cur_mask = 0;

	host = resolved->cur_domain;
	c = p;

	while (*p) {
		t = *p;

		switch (state) {
			case parse_spf_elt:
				if (t == ':' || t == '=') {
					state = parse_semicolon;
				}
				else if (t == '/') {
					/* No domain but mask */
					state = parse_slash;
				}
				p++;
				break;
			case parse_semicolon:
				if (t == '/') {
					/* Empty domain, technically an error */
					state = parse_slash;
				}
				else {
					c = p;
					state = parse_domain;
				}
				break;
			case parse_domain:
				if (t == '/') {
					hostbuf = rspamd_mempool_alloc (task->task_pool, p - c + 1);
					rspamd_strlcpy (hostbuf, c, p - c + 1);
					host = hostbuf;
					state = parse_slash;
				}
				p++;
				break;
			case parse_slash:
				c = p;
				if (allow_mask) {
					state = parse_ipv4_mask;
				}
				else {
					state = skip_garbadge;
				}
				cur_mask = 0;
				break;
			case parse_ipv4_mask:
				if (g_ascii_isdigit (t)) {
					/* Ignore errors here */
					cur_mask = cur_mask * 10 + (t - '0');
				}
				else if (t == '/') {
					if (cur_mask <= 32) {
						addr->m.dual.mask_v4 = cur_mask;
					}
					else {
						msg_info_spf ("bad ipv4 mask for %s: %d",
								rec->sender_domain, cur_mask);
					}
					state = parse_second_slash;
				}
				p++;
				break;
			case parse_second_slash:
				c = p;
				state = parse_ipv6_mask;
				cur_mask = 0;
				break;
			case parse_ipv6_mask:
				if (g_ascii_isdigit (t)) {
					/* Ignore errors here */
					cur_mask = cur_mask * 10 + (t - '0');
				}
				p++;
				break;
			case skip_garbadge:
				p++;
				break;
		}
	}

	/* Process end states */
	if (state == parse_ipv4_mask) {
		if (cur_mask <= 32) {
			addr->m.dual.mask_v4 = cur_mask;
		}
		else {
			msg_info_spf ("bad ipv4 mask for %s: %d", rec->sender_domain, cur_mask);
		}
	}
	else if (state == parse_ipv6_mask) {
		if (cur_mask <= 128) {
			addr->m.dual.mask_v6 = cur_mask;
		}
		else {
			msg_info_spf ("bad ipv6 mask: %d", cur_mask);
		}
	}
	else if (state == parse_domain && p - c > 0) {
		hostbuf = rspamd_mempool_alloc (task->task_pool, p - c + 1);
		rspamd_strlcpy (hostbuf, c, p - c + 1);
		host = hostbuf;
	}

	if (cur_mask == 0) {
		addr->m.dual.mask_v4 = 32;
		addr->m.dual.mask_v6 = 64;
	}

	return host;
}

static gboolean
parse_spf_a (struct spf_record *rec,
		struct spf_resolved_element *resolved, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host = NULL;
	struct rspamd_task *task = rec->task;

	CHECK_REC (rec);

	host = parse_spf_domain_mask (rec, addr, resolved, TRUE);

	if (host == NULL) {
		return FALSE;
	}

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->ptr_host = host;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_A;
	cb->resolved = resolved;
	msg_debug_spf ("resolve a %s", host);

	if (rspamd_dns_resolver_request_task_forced (task,
			spf_record_dns_callback, (void *) cb, RDNS_REQUEST_A, host)) {
		rec->requests_inflight++;

		cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
		cb->rec = rec;
		cb->ptr_host = host;
		cb->addr = addr;
		cb->cur_action = SPF_RESOLVE_AAA;
		cb->resolved = resolved;

		if (!spf_lib_ctx->disable_ipv6) {
			if (rspamd_dns_resolver_request_task_forced (task,
					spf_record_dns_callback, (void *) cb, RDNS_REQUEST_AAAA, host)) {
				rec->requests_inflight++;
			}
		}
		else {
			msg_debug_spf ("skip AAAA request for a record resolution");
		}

		return TRUE;
	}
	else {
		msg_info_spf ("unresolvable A element for %s: %s", addr->spf_string,
				rec->sender_domain);
	}

	return FALSE;

}

static gboolean
parse_spf_ptr (struct spf_record *rec,
		struct spf_resolved_element *resolved, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host;
	gchar *ptr;
	struct rspamd_task *task = rec->task;

	CHECK_REC (rec);

	host = parse_spf_domain_mask (rec, addr, resolved, FALSE);

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_PTR;
	cb->resolved = resolved;
	cb->ptr_host = rspamd_mempool_strdup (task->task_pool, host);
	ptr =
			rdns_generate_ptr_from_str (rspamd_inet_address_to_string (
					task->from_addr));

	if (ptr == NULL) {
		return FALSE;
	}

	rspamd_mempool_add_destructor (task->task_pool, free, ptr);
	msg_debug_spf ("resolve ptr %s for %s", ptr, host);

	if (rspamd_dns_resolver_request_task_forced (task,
			spf_record_dns_callback, (void *) cb, RDNS_REQUEST_PTR, ptr)) {
		rec->requests_inflight++;
		rec->ttl = 0;
		msg_debug_spf ("disable SPF caching as there is PTR expansion");

		return TRUE;
	}
	else {
		msg_info_spf ("unresolvable PTR element for %s: %s", addr->spf_string,
				rec->sender_domain);
	}

	return FALSE;
}

static gboolean
parse_spf_mx (struct spf_record *rec,
		struct spf_resolved_element *resolved, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host;
	struct rspamd_task *task = rec->task;

	CHECK_REC (rec);

	host = parse_spf_domain_mask (rec, addr, resolved, TRUE);

	if (host == NULL) {
		return FALSE;
	}

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_MX;
	cb->ptr_host = host;
	cb->resolved = resolved;

	msg_debug_spf ("resolve mx for %s", host);
	if (rspamd_dns_resolver_request_task_forced (task,
			spf_record_dns_callback, (void *) cb, RDNS_REQUEST_MX, host)) {
		rec->requests_inflight++;

		return TRUE;
	}

	return FALSE;
}

static gboolean
parse_spf_all (struct spf_record *rec, struct spf_addr *addr)
{
	/* All is 0/0 */
	memset (&addr->addr4, 0, sizeof (addr->addr4));
	memset (&addr->addr6, 0, sizeof (addr->addr6));
	/* Here we set all masks to 0 */
	addr->m.idx = 0;
	addr->flags |= RSPAMD_SPF_FLAG_ANY|RSPAMD_SPF_FLAG_RESOLVED;
	msg_debug_spf ("parsed all elt");

	/* Disallow +all */
	if (addr->mech == SPF_PASS) {
		addr->flags |= RSPAMD_SPF_FLAG_INVALID;
		msg_info_spf ("allow any SPF record for %s, ignore it",
				rec->sender_domain);
	}

	return TRUE;
}

static gboolean
parse_spf_ip4 (struct spf_record *rec, struct spf_addr *addr)
{
	/* ip4:addr[/mask] */
	const gchar *semicolon, *slash;
	gsize len;
	gchar ipbuf[INET_ADDRSTRLEN + 1];
	guint32 mask;
	static const guint32 min_valid_mask = 8;

	semicolon = strchr (addr->spf_string, ':');

	if (semicolon == NULL) {
		semicolon = strchr (addr->spf_string, '=');

		if (semicolon == NULL) {
			msg_info_spf ("invalid ip4 element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}
	}

	semicolon++;
	slash = strchr (semicolon, '/');

	if (slash) {
		len = slash - semicolon;
	}
	else {
		len = strlen (semicolon);
	}

	rspamd_strlcpy (ipbuf, semicolon, MIN (len + 1, sizeof (ipbuf)));

	if (inet_pton (AF_INET, ipbuf, addr->addr4) != 1) {
		msg_info_spf ("invalid ip4 element for %s: %s", addr->spf_string,
				rec->sender_domain);
		return FALSE;
	}

	if (slash) {
		mask = strtoul (slash + 1, NULL, 10);
		if (mask > 32) {
			msg_info_spf ("invalid mask for ip4 element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}

		addr->m.dual.mask_v4 = mask;

		if (mask < min_valid_mask) {
			addr->flags |= RSPAMD_SPF_FLAG_INVALID;
			msg_info_spf ("too wide SPF record for %s: %s/%d",
					rec->sender_domain,
					ipbuf, addr->m.dual.mask_v4);
		}
	}
	else {
		addr->m.dual.mask_v4 = 32;
	}

	addr->flags |= RSPAMD_SPF_FLAG_IPV4|RSPAMD_SPF_FLAG_RESOLVED;
	msg_debug_spf ("parsed ipv4 record %s/%d", ipbuf, addr->m.dual.mask_v4);

	return TRUE;
}

static gboolean
parse_spf_ip6 (struct spf_record *rec, struct spf_addr *addr)
{
	/* ip6:addr[/mask] */
	const gchar *semicolon, *slash;
	gsize len;
	gchar ipbuf[INET6_ADDRSTRLEN + 1];
	guint32 mask;
	static const guint32 min_valid_mask = 8;

	semicolon = strchr (addr->spf_string, ':');

	if (semicolon == NULL) {
		semicolon = strchr (addr->spf_string, '=');

		if (semicolon == NULL) {
			msg_info_spf ("invalid ip6 element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}
	}

	semicolon++;
	slash = strchr (semicolon, '/');

	if (slash) {
		len = slash - semicolon;
	}
	else {
		len = strlen (semicolon);
	}

	rspamd_strlcpy (ipbuf, semicolon, MIN (len + 1, sizeof (ipbuf)));

	if (inet_pton (AF_INET6, ipbuf, addr->addr6) != 1) {
		msg_info_spf ("invalid ip6 element for %s: %s", addr->spf_string,
				rec->sender_domain);
		return FALSE;
	}

	if (slash) {
		mask = strtoul (slash + 1, NULL, 10);
		if (mask > 128) {
			msg_info_spf ("invalid mask for ip6 element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}

		addr->m.dual.mask_v6 = mask;

		if (mask < min_valid_mask) {
			addr->flags |= RSPAMD_SPF_FLAG_INVALID;
			msg_info_spf ("too wide SPF record for %s: %s/%d",
					rec->sender_domain,
					ipbuf, addr->m.dual.mask_v6);
		}
	}
	else {
		addr->m.dual.mask_v6 = 128;
	}

	addr->flags |= RSPAMD_SPF_FLAG_IPV6|RSPAMD_SPF_FLAG_RESOLVED;
	msg_debug_spf ("parsed ipv6 record %s/%d", ipbuf, addr->m.dual.mask_v6);

	return TRUE;
}


static gboolean
parse_spf_include (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *domain;
	struct rspamd_task *task = rec->task;

	CHECK_REC (rec);
	domain = strchr (addr->spf_string, ':');

	if (domain == NULL) {
		/* Common mistake */
		domain = strchr (addr->spf_string, '=');

		if (domain == NULL) {
			msg_info_spf ("invalid include element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}
	}

	domain++;

	rec->dns_requests++;

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_INCLUDE;
	addr->m.idx = rec->resolved->len;
	cb->resolved = rspamd_spf_new_addr_list (rec, domain);
	cb->ptr_host = domain;
	/* Set reference */
	addr->flags |= RSPAMD_SPF_FLAG_REFERENCE;
	msg_debug_spf ("resolve include %s", domain);

	if (rspamd_dns_resolver_request_task_forced (task,
			spf_record_dns_callback, (void *) cb, RDNS_REQUEST_TXT, domain)) {
		rec->requests_inflight++;

		return TRUE;
	}
	else {
		msg_info_spf ("unresolvable include element for %s: %s", addr->spf_string,
				rec->sender_domain);
	}


	return FALSE;
}

static gboolean
parse_spf_exp (struct spf_record *rec, struct spf_addr *addr)
{
	msg_info_spf ("exp record is ignored");
	return TRUE;
}

static gboolean
parse_spf_redirect (struct spf_record *rec,
		struct spf_resolved_element *resolved, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *domain;
	struct rspamd_task *task = rec->task;

	CHECK_REC (rec);

	domain = strchr (addr->spf_string, '=');

	if (domain == NULL) {
		/* Common mistake */
		domain = strchr (addr->spf_string, ':');

		if (domain == NULL) {
			msg_info_spf ("invalid redirect element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}
	}

	domain++;

	rec->dns_requests++;
	resolved->redirected = TRUE;

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	/* Set reference */
	addr->flags |= RSPAMD_SPF_FLAG_REFERENCE | RSPAMD_SPF_FLAG_REDIRECT;
	addr->m.idx = rec->resolved->len;

	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_REDIRECT;
	cb->resolved = rspamd_spf_new_addr_list (rec, domain);
	cb->ptr_host = domain;
	msg_debug_spf ("resolve redirect %s", domain);

	if (rspamd_dns_resolver_request_task_forced (task,
			spf_record_dns_callback, (void *) cb, RDNS_REQUEST_TXT, domain)) {
		rec->requests_inflight++;

		return TRUE;
	}
	else {
		msg_info_spf ("unresolvable redirect element for %s: %s", addr->spf_string,
				rec->sender_domain);
	}

	return FALSE;
}

static gboolean
parse_spf_exists (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host;
	struct rspamd_task *task = rec->task;
	struct spf_resolved_element *resolved;

	resolved = g_ptr_array_index (rec->resolved, rec->resolved->len - 1);
	CHECK_REC (rec);

	host = strchr (addr->spf_string, ':');
	if (host == NULL) {
		host = strchr (addr->spf_string, '=');

		if (host == NULL) {
			msg_info_spf ("invalid exists element for %s: %s", addr->spf_string,
					rec->sender_domain);
			return FALSE;
		}
	}

	host++;
	rec->dns_requests++;

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_EXISTS;
	cb->resolved = resolved;
	cb->ptr_host = host;

	msg_debug_spf ("resolve exists %s", host);
	if (rspamd_dns_resolver_request_task_forced (task,
			spf_record_dns_callback, (void *) cb, RDNS_REQUEST_A, host)) {
		rec->requests_inflight++;

		return TRUE;
	}
	else {
		msg_info_spf ("unresolvable exists element for %s: %s", addr->spf_string,
				rec->sender_domain);
	}

	return FALSE;
}

static gsize
rspamd_spf_split_elt (const gchar *val, gsize len, gint *pos,
		gsize poslen, gchar delim)
{
	const gchar *p, *end;
	guint cur_pos = 0, cur_st = 0, nsub = 0;

	p = val;
	end = val + len;

	while (p < end && cur_pos + 2 < poslen) {
		if (*p == delim) {
			if (p - val > cur_st) {
				pos[cur_pos] = cur_st;
				pos[cur_pos + 1] = p - val;
				cur_st = p - val + 1;
				cur_pos += 2;
				nsub ++;
			}

			p ++;
		}
		else {
			p ++;
		}
	}

	if (cur_pos + 2 < poslen) {
		if (end - val > cur_st) {
			pos[cur_pos] = cur_st;
			pos[cur_pos + 1] = end - val;
			nsub ++;
		}
	}
	else {
		pos[cur_pos] = p - val;
		pos[cur_pos + 1] = end - val;
		nsub ++;
	}

	return nsub;
}

static gsize
rspamd_spf_process_substitution (const gchar *macro_value,
		gsize macro_len, guint ndelim, gchar delim, gboolean reversed,
		gchar *dest)
{
	gchar *d = dest;
	const gchar canon_delim = '.';
	guint vlen, i;
	gint pos[49 * 2], tlen;

	if (!reversed && ndelim == 0 && delim == canon_delim) {
		/* Trivial case */
		memcpy (dest, macro_value, macro_len);

		return macro_len;
	}

	vlen = rspamd_spf_split_elt (macro_value, macro_len,
			pos, G_N_ELEMENTS (pos), delim);

	if (vlen > 0) {
		if (reversed) {
			for (i = vlen - 1; ; i--) {
				tlen = pos[i * 2 + 1] - pos[i * 2];

				if (i != 0) {
					memcpy (d, &macro_value[pos[i * 2]], tlen);
					d += tlen;
					*d++ = canon_delim;
				}
				else {
					memcpy (d, &macro_value[pos[i * 2]], tlen);
					d += tlen;
					break;
				}
			}
		}
		else {
			for (i = 0; i < vlen; i++) {
				tlen = pos[i * 2 + 1] - pos[i * 2];

				if (i != vlen - 1) {
					memcpy (d, &macro_value[pos[i * 2]], tlen);
					d += tlen;
					*d++ = canon_delim;
				}
				else {
					memcpy (d, &macro_value[pos[i * 2]], tlen);
					d += tlen;
				}
			}
		}
	}
	else {
		/* Trivial case */
		memcpy (dest, macro_value, macro_len);

		return macro_len;
	}

	return (d - dest);
}

static const gchar *
expand_spf_macro (struct spf_record *rec, struct spf_resolved_element *resolved,
		const gchar *begin)
{
	const gchar *p, *macro_value = NULL;
	gchar *c, *new, *tmp, delim = '.';
	gsize len = 0, slen = 0, macro_len = 0;
	gint state = 0, ndelim = 0;
	gchar ip_buf[64 + 1]; /* cannot use INET6_ADDRSTRLEN as we use ptr lookup */
	gboolean need_expand = FALSE, reversed;
	struct rspamd_task *task;

	g_assert (rec != NULL);
	g_assert (begin != NULL);

	task = rec->task;
	p = begin;
	/* Calculate length */
	while (*p) {
		switch (state) {
		case 0:
			/* Skip any character and wait for % in input */
			if (*p == '%') {
				state = 1;
			}
			else {
				len++;
			}

			slen++;
			p++;
			break;
		case 1:
			/* We got % sign, so we should whether wait for { or for - or for _ or for % */
			if (*p == '%' || *p == '_') {
				/* Just a single % sign or space */
				len++;
				state = 0;
			}
			else if (*p == '-') {
				/* %20 */
				len += sizeof ("%20") - 1;
				state = 0;
			}
			else if (*p == '{') {
				state = 2;
			}
			else {
				/* Something unknown */
				msg_info_spf (
						"spf error for domain %s: unknown spf element",
						rec->sender_domain);
				return begin;
			}
			p++;
			slen++;
			break;
		case 2:
			/* Read macro name */
			switch (g_ascii_tolower (*p)) {
			case 'i':
				len += sizeof (ip_buf) - 1;
				break;
			case 's':
				if (rec->sender) {
					len += strlen (rec->sender);
				}
				else {
					len += sizeof ("unknown") - 1;
				}
				break;
			case 'l':
				if (rec->local_part) {
					len += strlen (rec->local_part);
				}
				else {
					len += sizeof ("unknown") - 1;
				}
				break;
			case 'o':
				if (rec->sender_domain) {
					len += strlen (rec->sender_domain);
				}
				else {
					len += sizeof ("unknown") - 1;
				}
				break;
			case 'd':
				if (resolved->cur_domain) {
					len += strlen (resolved->cur_domain);
				}
				else {
					len += sizeof ("unknown") - 1;
				}
				break;
			case 'v':
				len += sizeof ("in-addr") - 1;
				break;
			case 'h':
				if (task->helo) {
					len += strlen (task->helo);
				}
				else {
					len += sizeof ("unknown") - 1;
				}
				break;
			default:
				msg_info_spf (
						"spf error for domain %s: unknown or "
								"unsupported spf macro %c in %s",
						rec->sender_domain,
						*p,
						begin);
				return begin;
			}
			p++;
			slen++;
			state = 3;
			break;
		case 3:
			/* Read modifier */
			if (*p == '}') {
				state = 0;
				need_expand = TRUE;
			}
			p++;
			slen++;
			break;

		default:
			g_assert_not_reached ();
		}
	}

	if (!need_expand) {
		/* No expansion needed */
		return begin;
	}

	new = rspamd_mempool_alloc (task->task_pool, len + 1);

	/* Reduce TTL to avoid caching of records with macros */
	if (rec->ttl != 0) {
		rec->ttl = 0;
		msg_debug_spf ("disable SPF caching as there is macro expansion");
	}

	c = new;
	p = begin;
	state = 0;
	/* Begin macro expansion */

	while (*p) {
		switch (state) {
		case 0:
			/* Skip any character and wait for % in input */
			if (*p == '%') {
				state = 1;
			}
			else {
				*c = *p;
				c++;
			}

			p++;
			break;
		case 1:
			/* We got % sign, so we should whether wait for { or for - or for _ or for % */
			if (*p == '%') {
				/* Just a single % sign or space */
				*c++ = '%';
				state = 0;
			}
			else if (*p == '_') {
				*c++ = ' ';
				state = 0;
			}
			else if (*p == '-') {
				/* %20 */
				*c++ = '%';
				*c++ = '2';
				*c++ = '0';
				state = 0;
			}
			else if (*p == '{') {
				state = 2;
			}
			else {
				/* Something unknown */
				msg_info_spf (
						"spf error for domain %s: unknown spf element",
						rec->sender_domain);
				return begin;
			}
			p++;
			break;
		case 2:
			/* Read macro name */
			switch (g_ascii_tolower (*p)) {
			case 'i':
				if (task->from_addr) {
					if (rspamd_inet_address_get_af (task->from_addr) == AF_INET) {
						macro_len = rspamd_strlcpy (ip_buf,
								rspamd_inet_address_to_string (task->from_addr),
								sizeof (ip_buf));
						macro_value = ip_buf;
					}
					else if (rspamd_inet_address_get_af (task->from_addr) == AF_INET6) {
						/* See #3625 for details */
						socklen_t slen;
						struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
								rspamd_inet_address_get_sa (task->from_addr, &slen);

						/* Expand IPv6 address */
#define IPV6_OCTET(x) bytes[(x)] >> 4, bytes[(x)] & 0xF
						unsigned char *bytes = (unsigned char *)&sin6->sin6_addr;
						macro_len = rspamd_snprintf (ip_buf, sizeof (ip_buf),
								"%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd."
								"%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd.%xd",
								IPV6_OCTET(0), IPV6_OCTET(1),
								IPV6_OCTET(2), IPV6_OCTET(3),
								IPV6_OCTET(4), IPV6_OCTET(5),
								IPV6_OCTET(6), IPV6_OCTET(7),
								IPV6_OCTET(8), IPV6_OCTET(9),
								IPV6_OCTET(10), IPV6_OCTET(11),
								IPV6_OCTET(12), IPV6_OCTET(13),
								IPV6_OCTET(14), IPV6_OCTET(15));
						macro_value = ip_buf;
#undef IPV6_OCTET
					}
					else {
						macro_len = rspamd_snprintf (ip_buf, sizeof (ip_buf),
								"127.0.0.1");
						macro_value = ip_buf;
					}
				}
				else {
					macro_len = rspamd_snprintf (ip_buf, sizeof (ip_buf),
							"127.0.0.1");
					macro_value = ip_buf;
				}
				break;
			case 's':
				if (rec->sender) {
					macro_len = strlen (rec->sender);
					macro_value = rec->sender;
				}
				else {
					macro_len = sizeof ("unknown") - 1;
					macro_value = "unknown";
				}
				break;
			case 'l':
				if (rec->local_part) {
					macro_len = strlen (rec->local_part);
					macro_value = rec->local_part;
				}
				else {
					macro_len = sizeof ("unknown") - 1;
					macro_value = "unknown";
				}
				break;
			case 'o':
				if (rec->sender_domain) {
					macro_len = strlen (rec->sender_domain);
					macro_value = rec->sender_domain;
				}
				else {
					macro_len = sizeof ("unknown") - 1;
					macro_value = "unknown";
				}
				break;
			case 'd':
				if (resolved && resolved->cur_domain) {
					macro_len = strlen (resolved->cur_domain);
					macro_value = resolved->cur_domain;
				}
				else {
					macro_len = sizeof ("unknown") - 1;
					macro_value = "unknown";
				}
				break;
			case 'v':
				if (task->from_addr) {
					if (rspamd_inet_address_get_af (task->from_addr) == AF_INET) {
						macro_len = sizeof ("in-addr") - 1;
						macro_value = "in-addr";
					} else {
						macro_len = sizeof ("ip6") - 1;
						macro_value = "ip6";
					}
				}
				else {
					macro_len = sizeof ("in-addr") - 1;
					macro_value = "in-addr";
				}
				break;
			case 'h':
				if (task->helo) {
					tmp = strchr (task->helo, '@');
					if (tmp) {
						macro_len = strlen (tmp + 1);
						macro_value = tmp + 1;
					}
					else {
						macro_len = strlen (task->helo);
						macro_value = task->helo;
					}
				}
				else {
					macro_len = sizeof ("unknown") - 1;
					macro_value = "unknown";
				}
				break;
			default:
				msg_info_spf (
						"spf error for domain %s: unknown or "
								"unsupported spf macro %c in %s",
						rec->sender_domain,
						*p,
						begin);
				return begin;
			}

			p++;
			state = 3;
			ndelim = 0;
			delim = '.';
			reversed = FALSE;
			break;

		case 3:
			/* Read modifier */
			if (*p == '}') {
				state = 0;
				len = rspamd_spf_process_substitution (macro_value,
						macro_len, ndelim, delim, reversed, c);
				c += len;
			}
			else if (*p == 'r' && len != 0) {
				reversed = TRUE;
			}
			else if (g_ascii_isdigit (*p)) {
				ndelim = strtoul (p, &tmp, 10);

				if (tmp == NULL || tmp == p) {
					p ++;
				}
				else {
					p = tmp;

					continue;
				}
			}
			else if (*p == '+' || *p == '-' ||
					*p == '.' || *p == ',' || *p == '/' || *p == '_' ||
					*p == '=') {
				delim = *p;
			}
			else {
				msg_info_spf ("spf error for domain %s: unknown or "
								"unsupported spf macro %c in %s",
						rec->sender_domain,
						*p,
						begin);
				return begin;
			}
			p++;
			break;
		}
	}
	/* Null terminate */
	*c = '\0';

	return new;

}

/* Read current element and try to parse record */
static gboolean
spf_process_element (struct spf_record *rec,
					 struct spf_resolved_element *resolved,
					 const gchar *elt,
					 const gchar **elts)
{
	struct spf_addr *addr = NULL;
	gboolean res = FALSE;
	const gchar *begin;
	gchar t;

	g_assert (elt != NULL);
	g_assert (rec != NULL);

	if (*elt == '\0' || resolved->redirected) {
		return TRUE;
	}

	begin = expand_spf_macro (rec, resolved, elt);
	addr = rspamd_spf_new_addr (rec, resolved, begin);
	g_assert (addr != NULL);
	t = g_ascii_tolower (addr->spf_string[0]);
	begin = addr->spf_string;

	/* Now check what we have */
	switch (t) {
		case 'a':
			/* all or a */
			if (g_ascii_strncasecmp (begin, SPF_ALL,
					sizeof (SPF_ALL) - 1) == 0) {
				res = parse_spf_all (rec, addr);
			}
			else if (g_ascii_strncasecmp (begin, SPF_A,
					sizeof (SPF_A) - 1) == 0) {
				res = parse_spf_a (rec, resolved, addr);
			}
			else {
				msg_info_spf ("spf error for domain %s: bad spf command %s",
						rec->sender_domain, begin);
			}
			break;
		case 'i':
			/* include or ip4 */
			if (g_ascii_strncasecmp (begin, SPF_IP4, sizeof (SPF_IP4) - 1) == 0) {
				res = parse_spf_ip4 (rec, addr);
			}
			else if (g_ascii_strncasecmp (begin, SPF_INCLUDE, sizeof (SPF_INCLUDE) - 1) == 0) {
				res = parse_spf_include (rec, addr);
			}
			else if (g_ascii_strncasecmp (begin, SPF_IP6, sizeof (SPF_IP6) - 1) == 0) {
				res = parse_spf_ip6 (rec, addr);
			}
			else if (g_ascii_strncasecmp (begin, SPF_IP4_ALT, sizeof (SPF_IP4_ALT) - 1) == 0) {
				res = parse_spf_ip4 (rec, addr);
			}
			else if (g_ascii_strncasecmp (begin, SPF_IP6_ALT, sizeof (SPF_IP6_ALT) - 1) == 0) {
				res = parse_spf_ip6 (rec, addr);
			}
			else {
				msg_info_spf ("spf error for domain %s: bad spf command %s",
						rec->sender_domain, begin);
			}
			break;
		case 'm':
			/* mx */
			if (g_ascii_strncasecmp (begin, SPF_MX, sizeof (SPF_MX) - 1) == 0) {
				res = parse_spf_mx (rec, resolved, addr);
			}
			else {
				msg_info_spf ("spf error for domain %s: bad spf command %s",
						rec->sender_domain, begin);
			}
			break;
		case 'p':
			/* ptr */
			if (g_ascii_strncasecmp (begin, SPF_PTR,
					sizeof (SPF_PTR) - 1) == 0) {
				res = parse_spf_ptr (rec, resolved, addr);
			}
			else {
				msg_info_spf ("spf error for domain %s: bad spf command %s",
						rec->sender_domain, begin);
			}
			break;
		case 'e':
			/* exp or exists */
			if (g_ascii_strncasecmp (begin, SPF_EXP,
					sizeof (SPF_EXP) - 1) == 0) {
				res = parse_spf_exp (rec, addr);
			}
			else if (g_ascii_strncasecmp (begin, SPF_EXISTS,
					sizeof (SPF_EXISTS) - 1) == 0) {
				res = parse_spf_exists (rec, addr);
			}
			else {
				msg_info_spf ("spf error for domain %s: bad spf command %s",
						rec->sender_domain, begin);
			}
			break;
		case 'r':
			/* redirect */
			if (g_ascii_strncasecmp (begin, SPF_REDIRECT,
					sizeof (SPF_REDIRECT) - 1) == 0) {
				/*
				 * According to https://tools.ietf.org/html/rfc7208#section-6.1
				 * There must be no ALL element anywhere in the record,
				 * redirect must be ignored
				 */
				gboolean ignore_redirect = FALSE;

				for (const gchar **tmp = elts; *tmp != NULL; tmp ++) {
					if (g_ascii_strcasecmp ((*tmp) + 1, "all") == 0) {
						ignore_redirect = TRUE;
						break;
					}
				}

				if (!ignore_redirect) {
					res = parse_spf_redirect (rec, resolved, addr);
				}
				else {
					msg_info_spf ("ignore SPF redirect (%s) for domain %s as there is also all element",
							begin, rec->sender_domain);

					/* Pop the current addr as it is ignored */
					g_ptr_array_remove_index_fast (resolved->elts,
							resolved->elts->len - 1);

					return TRUE;
				}
			}
			else {
				msg_info_spf ("spf error for domain %s: bad spf command %s",
						rec->sender_domain, begin);
			}
			break;
		case 'v':
			if (g_ascii_strncasecmp (begin, "v=spf",
					sizeof ("v=spf") - 1) == 0) {
				/* Skip this element till the end of record */
				while (*begin && !g_ascii_isspace (*begin)) {
					begin++;
				}
			}
			break;
		default:
			msg_info_spf ("spf error for domain %s: bad spf command %s",
					rec->sender_domain, begin);
			break;
	}

	if (res) {
		addr->flags |= RSPAMD_SPF_FLAG_PARSED;
	}

	return res;
}

static void
parse_spf_scopes (struct spf_record *rec, gchar **begin)
{
	for (; ;) {
		if (g_ascii_strncasecmp (*begin, SPF_SCOPE_PRA, sizeof (SPF_SCOPE_PRA) -
														1) == 0) {
			*begin += sizeof (SPF_SCOPE_PRA) - 1;
			/* XXX: Implement actual PRA check */
			/* extract_pra_info (rec); */
			continue;
		}
		else if (g_ascii_strncasecmp (*begin, SPF_SCOPE_MFROM,
				sizeof (SPF_SCOPE_MFROM) - 1) == 0) {
			/* mfrom is standard spf1 check */
			*begin += sizeof (SPF_SCOPE_MFROM) - 1;
			continue;
		}
		else if (**begin != ',') {
			break;
		}
		(*begin)++;
	}
}

static gboolean
start_spf_parse (struct spf_record *rec, struct spf_resolved_element *resolved,
		gchar *begin)
{
	gchar **elts, **cur_elt;
	gsize len;

	/* Skip spaces */
	while (g_ascii_isspace (*begin)) {
		begin++;
	}

	len = strlen (begin);

	if (g_ascii_strncasecmp (begin, SPF_VER1_STR, sizeof (SPF_VER1_STR) - 1) ==
		0) {
		begin += sizeof (SPF_VER1_STR) - 1;

		while (g_ascii_isspace (*begin) && *begin) {
			begin++;
		}
	}
	else if (g_ascii_strncasecmp (begin, SPF_VER2_STR, sizeof (SPF_VER2_STR) -
													   1) == 0) {
		/* Skip one number of record, so no we are here spf2.0/ */
		begin += sizeof (SPF_VER2_STR);
		if (*begin != '/') {
			msg_info_spf ("spf error for domain %s: sender id is invalid",
					rec->sender_domain);
		}
		else {
			begin++;
			parse_spf_scopes (rec, &begin);
		}
		/* Now common spf record */
	}
	else {
		msg_debug_spf (
				"spf error for domain %s: bad spf record start: %*s",
				rec->sender_domain,
				(gint)len,
				begin);

		return FALSE;
	}

	while (g_ascii_isspace (*begin) && *begin) {
		begin++;
	}

	elts = g_strsplit_set (begin, " ", 0);

	if (elts) {
		cur_elt = elts;

		while (*cur_elt) {
			spf_process_element (rec, resolved, *cur_elt, (const gchar **)elts);
			cur_elt++;
		}

		g_strfreev (elts);
	}

	rspamd_spf_maybe_return (rec);

	return TRUE;
}

static void
spf_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct spf_record *rec = arg;
	struct spf_resolved_element *resolved = NULL;
	struct spf_addr *addr;

	rec->requests_inflight--;

	if (reply->code == RDNS_RC_NOERROR) {
		resolved = rspamd_spf_new_addr_list (rec, rec->sender_domain);
		if (rec->resolved->len == 1) {
			/* Top level resolved element */
			rec->ttl = reply->entries->ttl;
		}
	}
	else if ((reply->code == RDNS_RC_NOREC || reply->code == RDNS_RC_NXDOMAIN)
			&& rec->dns_requests == 0) {
		resolved = rspamd_spf_new_addr_list (rec, rec->sender_domain);
		addr = g_malloc0 (sizeof(*addr));
		addr->flags |= RSPAMD_SPF_FLAG_NA;
		g_ptr_array_insert (resolved->elts, 0, addr);
	}
	else if (reply->code != RDNS_RC_NOREC && reply->code != RDNS_RC_NXDOMAIN
			&& rec->dns_requests == 0) {
		resolved = rspamd_spf_new_addr_list (rec, rec->sender_domain);
		addr = g_malloc0 (sizeof(*addr));
		addr->flags |= RSPAMD_SPF_FLAG_TEMPFAIL;
		g_ptr_array_insert (resolved->elts, 0, addr);
	}

	if (resolved) {
		struct rdns_reply_entry *selected = NULL;

		if (!spf_process_txt_record (rec, resolved, reply, &selected)) {
			resolved = g_ptr_array_index(rec->resolved, 0);

			if (rec->resolved->len > 1) {
				addr = g_ptr_array_index(resolved->elts, 0);
				if ((reply->code == RDNS_RC_NOREC || reply->code == RDNS_RC_NXDOMAIN)
						&& (addr->flags & RSPAMD_SPF_FLAG_REDIRECT)) {
					addr->flags |= RSPAMD_SPF_FLAG_PERMFAIL;
				} else {
					addr->flags |= RSPAMD_SPF_FLAG_TEMPFAIL;
				}
			}
			else {
				addr = g_malloc0 (sizeof(*addr));

				if (reply->code == RDNS_RC_NOREC || reply->code == RDNS_RC_NXDOMAIN
						|| reply->code == RDNS_RC_NOERROR) {
					addr->flags |= RSPAMD_SPF_FLAG_NA;
				}
				else {
					addr->flags |= RSPAMD_SPF_FLAG_TEMPFAIL;
				}
				g_ptr_array_insert (resolved->elts, 0, addr);
			}
		}
		else {
			rec->top_record = rspamd_mempool_strdup(rec->task->task_pool,
					selected->content.txt.data);
			rspamd_mempool_set_variable(rec->task->task_pool,
					RSPAMD_MEMPOOL_SPF_RECORD,
					(gpointer)rec->top_record, NULL);
		}
	}

	rspamd_spf_maybe_return (rec);
}

static struct rspamd_spf_cred *
rspamd_spf_cache_domain (struct rspamd_task *task)
{
	struct rspamd_email_address *addr;
	struct rspamd_spf_cred *cred = NULL;

	addr = rspamd_task_get_sender (task);
	if (!addr || (addr->flags & RSPAMD_EMAIL_ADDR_EMPTY)) {
		/* Get domain from helo */

		if (task->helo) {
			GString *fs = g_string_new ("");

			cred = rspamd_mempool_alloc (task->task_pool, sizeof (*cred));
			cred->domain = task->helo;
			cred->local_part = "postmaster";
			rspamd_printf_gstring (fs, "postmaster@%s", cred->domain);
			cred->sender = fs->str;
			rspamd_mempool_add_destructor (task->task_pool,
					rspamd_gstring_free_hard, fs);
		}
	}
	else {
		rspamd_ftok_t tok;

		cred = rspamd_mempool_alloc (task->task_pool, sizeof (*cred));
		tok.begin = addr->domain;
		tok.len = addr->domain_len;
		cred->domain = rspamd_mempool_ftokdup (task->task_pool, &tok);
		tok.begin = addr->user;
		tok.len = addr->user_len;
		cred->local_part = rspamd_mempool_ftokdup (task->task_pool, &tok);
		tok.begin = addr->addr;
		tok.len = addr->addr_len;
		cred->sender = rspamd_mempool_ftokdup (task->task_pool, &tok);
	}

	if (cred) {
		rspamd_mempool_set_variable (task->task_pool, RSPAMD_MEMPOOL_SPF_DOMAIN,
				cred, NULL);
	}

	return cred;
}

struct rspamd_spf_cred *
rspamd_spf_get_cred (struct rspamd_task *task)
{
	struct rspamd_spf_cred *cred;

	cred = rspamd_mempool_get_variable (task->task_pool,
			RSPAMD_MEMPOOL_SPF_DOMAIN);

	if (!cred) {
		cred = rspamd_spf_cache_domain (task);
	}

	return cred;
}

const gchar *
rspamd_spf_get_domain (struct rspamd_task *task)
{
	gchar *domain = NULL;
	struct rspamd_spf_cred *cred;

	cred = rspamd_spf_get_cred (task);

	if (cred) {
		domain = cred->domain;
	}

	return domain;
}

gboolean
rspamd_spf_resolve (struct rspamd_task *task, spf_cb_t callback,
		gpointer cbdata, struct rspamd_spf_cred *cred)
{
	struct spf_record *rec;

	if (!cred || !cred->domain) {
		return FALSE;
	}

	/* First lookup in the hash */
	if (spf_lib_ctx->spf_hash) {
		struct spf_resolved *cached;

		cached = rspamd_lru_hash_lookup (spf_lib_ctx->spf_hash, cred->domain,
				task->task_timestamp);

		if (cached) {
			cached->flags |= RSPAMD_SPF_FLAG_CACHED;

			if (cached->top_record) {
				rspamd_mempool_set_variable(task->task_pool,
						RSPAMD_MEMPOOL_SPF_RECORD,
						rspamd_mempool_strdup (task->task_pool,
								cached->top_record), NULL);
			}
			callback (cached, task, cbdata);

			return TRUE;
		}
	}


	rec = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct spf_record));
	rec->task = task;
	rec->callback = callback;
	rec->cbdata = cbdata;

	rec->resolved = g_ptr_array_sized_new (8);

	/* Add destructor */
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) spf_record_destructor,
			rec);

	/* Extract from data */
	rec->sender = cred->sender;
	rec->local_part = cred->local_part;
	rec->sender_domain = cred->domain;

	if (rspamd_dns_resolver_request_task_forced (task,
			spf_dns_callback,
			(void *) rec, RDNS_REQUEST_TXT, rec->sender_domain)) {
		rec->requests_inflight++;
		return TRUE;
	}

	return FALSE;
}

struct spf_resolved *
_spf_record_ref (struct spf_resolved *flat, const gchar *loc)
{
	REF_RETAIN (flat);
	return flat;
}

void
_spf_record_unref (struct spf_resolved *flat, const gchar *loc)
{
	REF_RELEASE (flat);
}

gchar *
spf_addr_mask_to_string (struct spf_addr *addr)
{
	GString *res;
	gchar *s, ipstr[INET6_ADDRSTRLEN + 1];

	if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
		res = g_string_new ("any");
	}
	else if (addr->flags & RSPAMD_SPF_FLAG_IPV4) {
		(void)inet_ntop (AF_INET, addr->addr4, ipstr, sizeof (ipstr));
		res = g_string_sized_new (sizeof (ipstr));
		rspamd_printf_gstring (res, "%s/%d", ipstr, addr->m.dual.mask_v4);
	}
	else if (addr->flags & RSPAMD_SPF_FLAG_IPV6) {
		(void)inet_ntop (AF_INET6, addr->addr6, ipstr, sizeof (ipstr));
		res = g_string_sized_new (sizeof (ipstr));
		rspamd_printf_gstring (res, "%s/%d", ipstr, addr->m.dual.mask_v6);
	}
	else {
		res = g_string_new (NULL);
		rspamd_printf_gstring (res, "unknown, flags = %d", addr->flags);
	}

	s = res->str;
	g_string_free (res, FALSE);


	return s;
}

struct spf_addr*
spf_addr_match_task (struct rspamd_task *task, struct spf_resolved *rec)
{
	const guint8 *s, *d;
	guint af, mask, bmask, addrlen;
	struct spf_addr *selected = NULL, *addr, *any_addr = NULL;
	guint i;

	if (task->from_addr == NULL) {
		return FALSE;
	}

	for (i = 0; i < rec->elts->len; i ++) {
		addr = &g_array_index (rec->elts, struct spf_addr, i);
		if (addr->flags & RSPAMD_SPF_FLAG_TEMPFAIL) {
			continue;
		}

		af = rspamd_inet_address_get_af (task->from_addr);
		/* Basic comparing algorithm */
		if (((addr->flags & RSPAMD_SPF_FLAG_IPV6) && af == AF_INET6) ||
			((addr->flags & RSPAMD_SPF_FLAG_IPV4) && af == AF_INET)) {
			d = rspamd_inet_address_get_hash_key (task->from_addr, &addrlen);

			if (af == AF_INET6) {
				s = (const guint8 *) addr->addr6;
				mask = addr->m.dual.mask_v6;
			}
			else {
				s = (const guint8 *) addr->addr4;
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
					mask = (0xffu << (CHAR_BIT - (mask - bmask * 8u))) & 0xffu;

					if ((*s & mask) == (*d & mask)) {
						selected = addr;
						break;
					}
				}
				else {
					selected = addr;
					break;
				}
			}
		}
		else {
			if (addr->flags & RSPAMD_SPF_FLAG_ANY) {
				any_addr = addr;
			}
		}
	}

	if (selected) {
		return selected;
	}

	return any_addr;
}