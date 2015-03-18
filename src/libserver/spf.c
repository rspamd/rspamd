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

#include "config.h"
#include "dns.h"
#include "spf.h"
#include "main.h"
#include "message.h"
#include "filter.h"
#include "utlist.h"

#define SPF_VER1_STR "v=spf1"
#define SPF_VER2_STR "spf2."
#define SPF_SCOPE_PRA "pra"
#define SPF_SCOPE_MFROM "mfrom"
#define SPF_ALL "all"
#define SPF_A "a"
#define SPF_IP4 "ip4"
#define SPF_IP6 "ip6"
#define SPF_PTR "ptr"
#define SPF_MX "mx"
#define SPF_EXISTS "exists"
#define SPF_INCLUDE "include"
#define SPF_REDIRECT "redirect"
#define SPF_EXP "exp"

/** SPF limits for avoiding abuse **/
#define SPF_MAX_NESTING 10
#define SPF_MAX_DNS_REQUESTS 30

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
	GArray *resolved; /* Array of struct spf_resolved_element */
	const gchar *sender;
	const gchar *sender_domain;
	gchar *local_part;
	struct rspamd_task *task;
	spf_cb_t callback;
	gboolean done;
};

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

struct spf_dns_cb {
	struct spf_record *rec;
	struct spf_addr *addr;
	struct spf_resolved_element *resolved;
	gchar *ptr_host;
	spf_action_t cur_action;
	gboolean in_include;
};

#define CHECK_REC(rec)                                          \
	do {                                                        \
		if ((rec)->nested > SPF_MAX_NESTING ||                  \
			(rec)->dns_requests > SPF_MAX_DNS_REQUESTS) {       \
			msg_info ("<%s> spf recursion limit %d is reached, domain: %s", \
				(rec)->task->message_id, (rec)->dns_requests,   \
				(rec)->sender_domain);                          \
			return FALSE;                                       \
		}                                                       \
	} while (0)                                                 \

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

static struct spf_addr *
rspamd_spf_new_addr (struct spf_record *rec,
		struct spf_resolved_element *resolved, const gchar *elt)
{
	gboolean need_shift = FALSE;
	struct spf_addr *naddr;

	naddr = g_slice_alloc0 (sizeof (*naddr));
	naddr->mech = check_spf_mech (elt, &need_shift);

	if (need_shift) {
		naddr->spf_string = g_strdup (elt + 1);
	}
	else {
		naddr->spf_string = g_strdup (elt);
	}

	g_ptr_array_add (resolved->elts, naddr);

	return naddr;
}

static void
rspamd_spf_free_addr (gpointer a)
{
	struct spf_addr *addr = a;

	if (addr) {
		g_free (addr->spf_string);
		g_slice_free1 (sizeof (*addr), addr);
	}
}

static struct spf_resolved_element *
rspamd_spf_new_addr_list (struct spf_record *rec, const gchar *domain)
{
	struct spf_resolved_element resolved;

	resolved.redirected = FALSE;
	resolved.cur_domain = g_strdup (domain);
	resolved.elts = g_ptr_array_new_full (8, rspamd_spf_free_addr);

	g_array_append_val (rec->resolved, resolved);

	return &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);
}

/* Debugging function that dumps spf record in log */
static void
dump_spf_record (GList *addrs)
{

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
		for (i = 0; i < rec->resolved->len; i ++) {
			elt = &g_array_index (rec->resolved, struct spf_resolved_element, i);

			/* Elts are destructed automatically here */
			g_ptr_array_free (elt->elts, TRUE);
			g_free (elt->cur_domain);
		}
		g_array_free (rec->resolved, TRUE);
	}
}

static void
rspamd_flatten_record_dtor (struct spf_resolved *r)
{
	struct spf_addr *addr;
	guint i;

	for (i = 0; i < r->elts->len; i ++) {
		addr = &g_array_index (r->elts, struct spf_addr, i);
		g_free (addr->spf_string);
	}

	g_free (r->domain);
	g_array_free (r->elts, TRUE);
	g_slice_free1 (sizeof (*r), r);
}

static void
rspamd_spf_process_reference (struct spf_resolved *target,
		struct spf_addr *addr, struct spf_record *rec, gboolean top)
{
	struct spf_resolved_element *elt;
	struct spf_addr *cur, taddr;
	guint i;

	if (addr) {
		g_assert (addr->m.idx < rec->resolved->len);

		elt = &g_array_index (rec->resolved, struct spf_resolved_element,
				addr->m.idx);
	}
	else {
		elt = &g_array_index (rec->resolved, struct spf_resolved_element, 0);
	}

	while (elt->redirected) {
		g_assert (elt->elts->len > 0);

		for (i = 0; i < elt->elts->len; i ++) {
			cur = g_ptr_array_index (elt->elts, i);
			if (cur->flags & RSPAMD_SPF_FLAG_PARSED) {
				break;
			}
		}

		if (!(cur->flags & RSPAMD_SPF_FLAG_PARSED)) {
			/* Unresolved redirect */
			msg_info ("redirect to %s cannot be resolved", cur->spf_string);
			return;
		}

		g_assert (cur->flags & RSPAMD_SPF_FLAG_REFRENCE);
		g_assert (cur->m.idx < rec->resolved->len);
		elt = &g_array_index (rec->resolved, struct spf_resolved_element,
				cur->m.idx);
	}

	for (i = 0; i < elt->elts->len; i ++) {
		cur = g_ptr_array_index (elt->elts, i);

		if (!(cur->flags & RSPAMD_SPF_FLAG_PARSED)) {
			/* Ignore unparsed addrs */
			continue;
		}
		else if (cur->flags & RSPAMD_SPF_FLAG_REFRENCE) {
			/* Process reference */
			rspamd_spf_process_reference (target, cur, rec, FALSE);
		}
		else {
			if ((cur->flags & RSPAMD_SPF_FLAG_ANY) && !top) {
				/* Ignore wide policies in includes */
				continue;
			}

			memcpy (&taddr, cur, sizeof (taddr));
			/* Steal element */
			cur->spf_string = NULL;
			g_array_append_val (target->elts, taddr);
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

	res = g_slice_alloc (sizeof (*res));
	res->elts = g_array_sized_new (FALSE, FALSE, sizeof (struct spf_addr),
			rec->resolved->len);
	res->domain = g_strdup (rec->sender_domain);
	res->ttl = rec->ttl;
	REF_INIT_RETAIN (res, rspamd_flatten_record_dtor);

	rspamd_spf_process_reference (res, NULL, rec, TRUE);

	return res;
}

static void
rspamd_spf_maybe_return (struct spf_record *rec)
{
	struct spf_resolved *flat;

	if (rec->requests_inflight == 0 && !rec->done) {
		flat = rspamd_spf_record_flatten (rec);
		rec->callback (flat, rec->task);
		REF_RELEASE (flat);
		rec->done = TRUE;
	}
}

static gboolean
spf_check_ptr_host (struct spf_dns_cb *cb, const char *name)
{
	const char *dend, *nend, *dstart, *nstart;

	if (name == NULL) {
		return FALSE;
	}
	if (cb->ptr_host != NULL) {
		dstart = cb->ptr_host;

	}
	else {
		dstart = cb->resolved->cur_domain;
	}

	msg_debug ("check ptr %s vs %s", name, dstart);

	/* We need to check whether `cur_domain` is a subdomain for `name` */
	dend = dstart + strlen (dstart) - 1;
	nstart = name;
	nend = nstart + strlen (nstart) - 1;

	if (nend == nstart || dend == dstart) {
		return FALSE;
	}
	/* Strip last '.' from names */
	if (*nend == '.') {
		nend --;
	}
	if (*dend == '.') {
		dend --;
	}

	/* Now compare from end to start */
	for (;;) {
		if (g_ascii_tolower (*dend) != g_ascii_tolower (*nend)) {
			msg_debug ("ptr records mismatch: %s and %s", dend, nend);
			return FALSE;
		}
		if (dend == dstart) {
			break;
		}
		if (nend == nstart) {
			/* Name is shorter than cur_domain */
			return FALSE;
		}
		nend --;
		dend --;
	}
	if (nend != nstart && *(nend - 1) != '.') {
		/* Not a subdomain */
		return FALSE;
	}

	return TRUE;
}

static void
spf_record_process_addr (struct spf_addr *addr, struct rdns_reply_entry *reply)
{
	if (reply->type == RDNS_REQUEST_AAAA) {
		memcpy (addr->addr6, &reply->content.aaa.addr, sizeof (addr->addr6));
		addr->flags |= RSPAMD_SPF_FLAG_IPV6;
	}
	else if (reply->type == RDNS_REQUEST_A) {
		memcpy (addr->addr4, &reply->content.a.addr, sizeof (addr->addr4));
		addr->flags |= RSPAMD_SPF_FLAG_IPV4;
	}
	else {
		msg_err ("internal error, bad DNS reply is treated as address: %s",
			rdns_strtype (reply->type));
	}
}

static void
spf_record_addr_set (struct spf_addr *addr, gboolean allow_any)
{
	guchar fill;
	guint maskv4, maskv6;

	if (allow_any) {
		fill = 0;
		maskv4 = 0;
		maskv6 = 0;
	}
	else {
		fill = 0xff;
		maskv4 = 32;
		maskv6 = 128;
	}

	memset (addr->addr4, fill, sizeof (addr->addr4));
	memset (addr->addr6, fill, sizeof (addr->addr6));
	addr->m.dual.mask_v4 = maskv4;
	addr->m.dual.mask_v6 = maskv6;

	addr->flags |= RSPAMD_SPF_FLAG_IPV4;
	addr->flags |= RSPAMD_SPF_FLAG_IPV6;
}

static void
spf_record_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct spf_dns_cb *cb = arg;
	gchar *begin;
	struct rdns_reply_entry *elt_data;
	struct rspamd_task *task;
	struct spf_addr *addr;
	gboolean ret;

	task = cb->rec->task;

	cb->rec->requests_inflight--;
	addr = cb->addr;

	if (reply->code == RDNS_RC_NOERROR) {
		/* Add all logic for all DNS states here */
		LL_FOREACH (reply->entries, elt_data)
		{
			switch (cb->cur_action) {
			case SPF_RESOLVE_MX:
				if (elt_data->type == RDNS_REQUEST_MX) {
					/* Now resolve A record for this MX */
					msg_debug ("resolve %s after resolving of MX",
							elt_data->content.mx.name);
					if (make_dns_request (task->resolver, task->s,
						task->task_pool,
						spf_record_dns_callback, (void *)cb, RDNS_REQUEST_A,
						elt_data->content.mx.name)) {
						task->dns_requests++;
						cb->rec->requests_inflight++;
					}
					if (make_dns_request (task->resolver, task->s,
						task->task_pool,
						spf_record_dns_callback, (void *)cb, RDNS_REQUEST_AAAA,
						elt_data->content.mx.name)) {
						task->dns_requests++;
						cb->rec->requests_inflight++;
					}
				}
				else {
					spf_record_process_addr (addr, elt_data);
				}
				break;
			case SPF_RESOLVE_A:
			case SPF_RESOLVE_AAA:
				spf_record_process_addr (addr, elt_data);
				break;
			case SPF_RESOLVE_PTR:
				if (elt_data->type == RDNS_REQUEST_PTR) {
					/* Validate returned records prior to making A requests */
					if (spf_check_ptr_host (cb, elt_data->content.ptr.name)) {
						msg_debug ("resolve %s after resolving of PTR",
								elt_data->content.ptr.name);
						if (make_dns_request (task->resolver, task->s,
								task->task_pool,
								spf_record_dns_callback, (void *)cb,
								RDNS_REQUEST_A,
								elt_data->content.ptr.name)) {
							task->dns_requests++;
							cb->rec->requests_inflight++;
						}
						if (make_dns_request (task->resolver, task->s,
								task->task_pool,
								spf_record_dns_callback, (void *)cb,
								RDNS_REQUEST_AAAA,
								elt_data->content.ptr.name)) {
							task->dns_requests++;
							cb->rec->requests_inflight++;
						}
					}
				}
				else {
					spf_record_process_addr (addr, elt_data);
				}
				break;
			case SPF_RESOLVE_REDIRECT:
				if (elt_data->type == RDNS_REQUEST_TXT) {
					begin = elt_data->content.txt.data;
					ret = start_spf_parse (cb->rec, cb->resolved, begin);

					if (ret) {
						cb->addr->flags |= RSPAMD_SPF_FLAG_PARSED;
					}
					else {
						cb->addr->flags &= ~RSPAMD_SPF_FLAG_PARSED;
					}
				}
				break;
			case SPF_RESOLVE_INCLUDE:
				if (elt_data->type == RDNS_REQUEST_TXT) {
					begin = elt_data->content.txt.data;
					ret = start_spf_parse (cb->rec, cb->resolved, begin);

					if (ret) {
						cb->addr->flags |= RSPAMD_SPF_FLAG_PARSED;
					}
					else {
						cb->addr->flags &= ~RSPAMD_SPF_FLAG_PARSED;
					}
				}
				break;
			case SPF_RESOLVE_EXP:
				break;
			case SPF_RESOLVE_EXISTS:
				if (elt_data->type == RDNS_REQUEST_A || elt_data->type ==
					RDNS_REQUEST_AAAA) {
					/* If specified address resolves, we can accept connection from every IP */
					spf_record_addr_set (addr, TRUE);
				}
				break;
			}
		}
	}
	else if (reply->code == RDNS_RC_NXDOMAIN) {
		switch (cb->cur_action) {
		case SPF_RESOLVE_MX:
			if (rdns_request_has_type (reply->request, RDNS_REQUEST_MX)) {
				msg_info (
					"<%s>: spf error for domain %s: cannot find MX record for %s",
					task->message_id,
					cb->rec->sender_domain,
					cb->resolved->cur_domain);
				spf_record_addr_set (addr, FALSE);
			}
			else {
				msg_info (
					"<%s>: spf error for domain %s: cannot resolve MX record for %s",
					task->message_id,
					cb->rec->sender_domain,
					cb->resolved->cur_domain);
				spf_record_addr_set (addr, FALSE);
			}
			break;
		case SPF_RESOLVE_A:
			if (rdns_request_has_type (reply->request, RDNS_REQUEST_A)) {
				spf_record_addr_set (addr, FALSE);
			}
			break;
		case SPF_RESOLVE_AAA:
			if (rdns_request_has_type (reply->request, RDNS_REQUEST_AAAA)) {
				spf_record_addr_set (addr, FALSE);
			}
			break;
		case SPF_RESOLVE_PTR:
			spf_record_addr_set (addr, FALSE);
			break;
		case SPF_RESOLVE_REDIRECT:
			msg_info (
				"<%s>: spf error for domain %s: cannot resolve TXT record for %s",
				task->message_id,
				cb->rec->sender_domain,
				cb->resolved->cur_domain);
			cb->addr->flags &= ~RSPAMD_SPF_FLAG_PARSED;
			break;
		case SPF_RESOLVE_INCLUDE:
			msg_info (
				"<%s>: spf error for domain %s: cannot resolve TXT record for %s",
				task->message_id,
				cb->rec->sender_domain,
				cb->resolved->cur_domain);
			cb->addr->flags &= ~RSPAMD_SPF_FLAG_PARSED;
			break;
		case SPF_RESOLVE_EXP:
			break;
		case SPF_RESOLVE_EXISTS:
			spf_record_addr_set (addr, FALSE);
			break;
		}
	}

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
		gboolean allow_mask)
{
	struct spf_resolved_element *resolved;
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

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
				rec->resolved->len - 1);
	host = resolved->cur_domain;

	while (*p) {
		t = *p;

		switch (state) {
		case parse_spf_elt:
			if (t == ':') {
				state = parse_semicolon;
			}
			else if (t == '/') {
				/* No domain but mask */
				state = parse_slash;
			}
			p ++;
			break;
		case parse_semicolon:
			if (t == '/') {
				/* Empty domain, technically an error */
				state = parse_slash;
			}
			c = p;
			state = parse_domain;
			break;
		case parse_domain:
			if (t == '/') {
				hostbuf = rspamd_mempool_alloc (task->task_pool, p - c + 1);
				rspamd_strlcpy (hostbuf, c, p - c + 1);
				host = hostbuf;
				state = parse_slash;
			}
			p ++;
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
					msg_info ("bad ipv4 mask: %d", cur_mask);
				}
				state = parse_second_slash;
			}
			p ++;
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
			p ++;
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
			msg_info ("bad ipv4 mask: %d", cur_mask);
		}
	}
	else if (state == parse_ipv6_mask) {
		if (cur_mask <= 128) {
			addr->m.dual.mask_v6 = cur_mask;
		}
		else {
			msg_info ("bad ipv6 mask: %d", cur_mask);
		}
	}
	else if (state == parse_domain && p - c > 0) {
		hostbuf = rspamd_mempool_alloc (task->task_pool, p - c + 1);
		rspamd_strlcpy (hostbuf, c, p - c + 1);
		host = hostbuf;
	}

	return host;
}

static gboolean
parse_spf_a (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host = NULL;
	struct rspamd_task *task = rec->task;
	struct spf_resolved_element *resolved;

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);
	CHECK_REC (rec);

	host = parse_spf_domain_mask (rec, addr, TRUE);

	if (host == NULL) {
		return FALSE;
	}

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_A;
	cb->resolved = resolved;
	msg_debug ("resolve a %s", host);

	if (make_dns_request (task->resolver, task->s, task->task_pool,
		spf_record_dns_callback, (void *)cb, RDNS_REQUEST_A, host)) {
		task->dns_requests++;
		rec->requests_inflight++;
		return TRUE;
	}

	return FALSE;

}

static gboolean
parse_spf_ptr (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host;
	gchar *ptr;
	struct rspamd_task *task = rec->task;
	struct spf_resolved_element *resolved;

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);
	CHECK_REC (rec);

	host = parse_spf_domain_mask (rec, addr, FALSE);

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
	msg_debug ("resolve ptr %s for %s", ptr, host);
	if (make_dns_request (task->resolver, task->s, task->task_pool,
		spf_record_dns_callback, (void *)cb, RDNS_REQUEST_PTR, ptr)) {
		task->dns_requests++;
		rec->requests_inflight++;

		return TRUE;
	}

	return FALSE;
}

static gboolean
parse_spf_mx (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *host;
	struct rspamd_task *task = rec->task;
	struct spf_resolved_element *resolved;

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);

	CHECK_REC (rec);

	host = parse_spf_domain_mask (rec, addr, TRUE);

	if (host == NULL) {
		return FALSE;
	}

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_MX;
	cb->resolved = resolved;

	msg_debug ("resolve mx for %s", host);
	if (make_dns_request (task->resolver, task->s, task->task_pool,
		spf_record_dns_callback, (void *)cb, RDNS_REQUEST_MX, host)) {
		task->dns_requests++;
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
	addr->flags |= RSPAMD_SPF_FLAG_ANY;

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

	CHECK_REC (rec);

	semicolon = strchr (addr->spf_string, ':');

	if (semicolon == NULL) {
		return FALSE;
	}

	semicolon ++;
	slash = strchr (semicolon, '/');

	if (slash) {
		len = slash - semicolon;
	}
	else {
		len = strlen (semicolon);
	}

	rspamd_strlcpy (ipbuf, semicolon, MIN (len + 1, sizeof (ipbuf)));

	if (inet_pton (AF_INET, ipbuf, addr->addr4) != 1) {
		return FALSE;
	}

	if (slash) {
		mask = strtoul (slash + 1, NULL, 10);
		if (mask > 32) {
			return FALSE;
		}
		addr->m.dual.mask_v4 = mask;
	}
	else {
		addr->m.dual.mask_v4 = 32;
	}

	addr->flags |= RSPAMD_SPF_FLAG_IPV4;

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

	CHECK_REC (rec);

	semicolon = strchr (addr->spf_string, ':');

	if (semicolon == NULL) {
		return FALSE;
	}

	semicolon ++;
	slash = strchr (semicolon, '/');

	if (slash) {
		len = slash - semicolon;
	}
	else {
		len = strlen (semicolon);
	}

	rspamd_strlcpy (ipbuf, semicolon, MIN (len + 1, sizeof (ipbuf)));

	if (inet_pton (AF_INET6, ipbuf, addr->addr6) != 1) {
		return FALSE;
	}

	if (slash) {
		mask = strtoul (slash + 1, NULL, 10);
		if (mask > 128) {
			return FALSE;
		}
		addr->m.dual.mask_v6 = mask;
	}
	else {
		addr->m.dual.mask_v6 = 128;
	}

	addr->flags |= RSPAMD_SPF_FLAG_IPV6;

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
		return FALSE;
	}

	domain++;

	rec->dns_requests++;

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_INCLUDE;
	addr->m.idx = rec->resolved->len;
	cb->resolved = rspamd_spf_new_addr_list (rec, domain);
	/* Set reference */
	addr->flags |= RSPAMD_SPF_FLAG_REFRENCE;
	msg_debug ("resolve include %s", domain);

	if (make_dns_request (task->resolver, task->s, task->task_pool,
		spf_record_dns_callback, (void *)cb, RDNS_REQUEST_TXT, domain)) {
		task->dns_requests++;
		rec->requests_inflight++;

		return TRUE;
	}


	return FALSE;
}

static gboolean
parse_spf_exp (struct spf_record *rec, struct spf_addr *addr)
{
	CHECK_REC (rec);

	msg_info ("exp record is ignored");
	return TRUE;
}

static gboolean
parse_spf_redirect (struct spf_record *rec,
		struct spf_resolved_element *resolved, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *domain;
	struct spf_addr *cur;
	struct rspamd_task *task = rec->task;
	guint i;

	CHECK_REC (rec);

	domain = strchr (addr->spf_string, '=');

	if (domain == NULL) {
		return FALSE;
	}

	domain++;

	rec->dns_requests++;
	resolved->redirected = TRUE;

	/* Now clear all elements but this one */
	for (i = 0; i < resolved->elts->len; i ++) {
		cur = g_ptr_array_index (resolved->elts, i);

		if (cur != addr) {
			cur->flags &= ~RSPAMD_SPF_FLAG_PARSED;
		}
	}

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	/* Set reference */
	addr->flags |= RSPAMD_SPF_FLAG_REFRENCE;
	addr->m.idx = rec->resolved->len;

	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_REDIRECT;
	cb->resolved = rspamd_spf_new_addr_list (rec, domain);
	msg_debug ("resolve redirect %s", domain);

	if (make_dns_request (task->resolver, task->s, task->task_pool,
		spf_record_dns_callback, (void *)cb, RDNS_REQUEST_TXT, domain)) {
		task->dns_requests++;
		rec->requests_inflight++;

		return TRUE;
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

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);
	CHECK_REC (rec);

	host = strchr (addr->spf_string, ':');
	if (host == NULL) {
		msg_info ("bad SPF exist record: %s", addr->spf_string);
		return FALSE;
	}

	host ++;
	rec->dns_requests++;

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_EXISTS;
	cb->resolved = resolved;

	msg_debug ("resolve exists %s", host);
	if (make_dns_request (task->resolver, task->s, task->task_pool,
		spf_record_dns_callback, (void *)cb, RDNS_REQUEST_A, host)) {
		task->dns_requests++;
		rec->requests_inflight++;

		return TRUE;
	}

	return FALSE;
}

static void
reverse_spf_ip (gchar *ip, gint len)
{
	gchar ipbuf[sizeof("255.255.255.255") - 1], *p, *c;
	gint t = 0, l = len;

	if (len > (gint)sizeof (ipbuf)) {
		msg_info ("cannot reverse string of length %d", len);
		return;
	}

	p = ipbuf + len;
	c = ip;
	while (--l) {
		if (*c == '.') {
			memcpy (p, c - t, t);
			*--p = '.';
			c++;
			t = 0;
			continue;
		}

		t++;
		c++;
		p--;
	}

	memcpy (p - 1, c - t, t + 1);
	memcpy (ip,	   ipbuf, len);
}

static const gchar *
expand_spf_macro (struct spf_record *rec,
	const gchar *begin)
{
	const gchar *p;
	gchar *c, *new, *tmp;
	gint len = 0, slen = 0, state = 0;
	gchar ip_buf[INET6_ADDRSTRLEN];
	gboolean need_expand = FALSE;
	struct rspamd_task *task;
	struct spf_resolved_element *resolved;

	g_assert (rec != NULL);
	g_assert (begin != NULL);

	task = rec->task;
	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);
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
				msg_info ("<%s>: spf error for domain %s: unknown spf element",
					task->message_id, rec->sender_domain);
				return begin;
			}
			p++;
			slen++;
			break;
		case 2:
			/* Read macro name */
			switch (g_ascii_tolower (*p)) {
			case 'i':
				len += INET6_ADDRSTRLEN - 1;
				break;
			case 's':
				len += strlen (rec->sender);
				break;
			case 'l':
				len += strlen (rec->local_part);
				break;
			case 'o':
				len += strlen (rec->sender_domain);
				break;
			case 'd':
				len += strlen (resolved->cur_domain);
				break;
			case 'v':
				len += sizeof ("in-addr") - 1;
				break;
			case 'h':
				if (task->helo) {
					len += strlen (task->helo);
				}
				break;
			default:
				msg_info (
					"<%s>: spf error for domain %s: unknown or unsupported spf macro %c in %s",
					task->message_id,
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
			else if (*p != 'r' && !g_ascii_isdigit (*p)) {
				msg_info (
					"<%s>: spf error for domain %s: unknown or unsupported spf modifier %c in %s",
					task->message_id,
					rec->sender_domain,
					*p,
					begin);
				return begin;
			}
			p++;
			slen++;
			break;
		}
	}

	if (!need_expand) {
		/* No expansion needed */
		return begin;
	}

	new = rspamd_mempool_alloc (task->task_pool, len + 1);

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
				msg_info ("<%s>: spf error for domain %s: unknown spf element",
					task->message_id, rec->sender_domain);
				return begin;
			}
			p++;
			break;
		case 2:
			/* Read macro name */
			switch (g_ascii_tolower (*p)) {
			case 'i':
				len = rspamd_strlcpy (ip_buf,
						rspamd_inet_address_to_string (task->from_addr),
						sizeof (ip_buf));
				memcpy (c, ip_buf, len);
				c += len;
				break;
			case 's':
				len = strlen (rec->sender);
				memcpy (c, rec->sender, len);
				c += len;
				break;
			case 'l':
				len = strlen (rec->local_part);
				memcpy (c, rec->local_part, len);
				c += len;
				break;
			case 'o':
				len = strlen (rec->sender_domain);
				memcpy (c, rec->sender_domain, len);
				c += len;
				break;
			case 'd':
				len = strlen (resolved->cur_domain);
				memcpy (c, resolved->cur_domain, len);
				c += len;
				break;
			case 'v':
				len = sizeof ("in-addr") - 1;
				memcpy (c, "in-addr", len);
				c += len;
				break;
			case 'h':
				if (task->helo) {
					tmp = strchr (task->helo, '@');
					if (tmp) {
						len = strlen (tmp + 1);
						memcpy (c, tmp + 1, len);
						c += len;
					}
				}
				break;
			default:
				msg_info (
					"<%s>: spf error for domain %s: unknown or unsupported spf macro %c in %s",
					task->message_id,
					rec->sender_domain,
					*p,
					begin);
				return begin;
			}
			p++;
			state = 3;
			break;
		case 3:
			/* Read modifier */
			if (*p == '}') {
				state = 0;
			}
			else if (*p == 'r' && len != 0) {
				reverse_spf_ip (c - len, len);
				len = 0;
			}
			else if (g_ascii_isdigit (*p)) {
				/*XXX: try to implement domain trimming */
			}
			else {
				msg_info (
					"<%s>: spf error for domain %s: unknown or unsupported spf macro %c in %s",
					task->message_id,
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
parse_spf_record (struct spf_record *rec, struct spf_resolved_element *resolved,
		const gchar *elt)
{
	struct spf_addr *addr = NULL;
	gboolean res = FALSE;
	const gchar *begin;
	struct rspamd_task *task;
	gchar t;

	g_assert (elt != NULL);
	g_assert (rec != NULL);

	if (*elt == '\0' || resolved->redirected) {
		return TRUE;
	}

	task = rec->task;
	begin = expand_spf_macro (rec, elt);
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
			res = parse_spf_a (rec, addr);
		}
		else {
			msg_info ("<%s>: spf error for domain %s: bad spf command %s",
					task->message_id, rec->sender_domain, begin);
		}
		break;
	case 'i':
		/* include or ip4 */
		if (g_ascii_strncasecmp (begin, SPF_IP4,
				sizeof (SPF_IP4) - 1) == 0) {
			res = parse_spf_ip4 (rec, addr);
		}
		else if (g_ascii_strncasecmp (begin, SPF_INCLUDE,
				sizeof (SPF_INCLUDE) - 1) == 0) {
			res = parse_spf_include (rec, addr);
		}
		else if (g_ascii_strncasecmp (begin, SPF_IP6, sizeof (SPF_IP6) -
				1) == 0) {
			res = parse_spf_ip6 (rec, addr);
		}
		else {
			msg_info ("<%s>: spf error for domain %s: bad spf command %s",
					task->message_id, rec->sender_domain, begin);
		}
		break;
	case 'm':
		/* mx */
		if (g_ascii_strncasecmp (begin, SPF_MX, sizeof (SPF_MX) - 1) == 0) {
			res = parse_spf_mx (rec, addr);
		}
		else {
			msg_info ("<%s>: spf error for domain %s: bad spf command %s",
					task->message_id, rec->sender_domain, begin);
		}
		break;
	case 'p':
		/* ptr */
		if (g_ascii_strncasecmp (begin, SPF_PTR,
				sizeof (SPF_PTR) - 1) == 0) {
			res = parse_spf_ptr (rec, addr);
		}
		else {
			msg_info ("<%s>: spf error for domain %s: bad spf command %s",
					task->message_id, rec->sender_domain, begin);
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
			msg_info ("<%s>: spf error for domain %s: bad spf command %s",
					task->message_id, rec->sender_domain, begin);
		}
		break;
	case 'r':
		/* redirect */
		if (g_ascii_strncasecmp (begin, SPF_REDIRECT,
				sizeof (SPF_REDIRECT) - 1) == 0) {
			res = parse_spf_redirect (rec, resolved, addr);
		}
		else {
			msg_info ("<%s>: spf error for domain %s: bad spf command %s",
					task->message_id, rec->sender_domain, begin);
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
		msg_info ("<%s>: spf error for domain %s: bad spf command %s",
				task->message_id, rec->sender_domain, begin);
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
	for (;; ) {
		if (g_ascii_strncasecmp (*begin, SPF_SCOPE_PRA, sizeof (SPF_SCOPE_PRA) -
			1) == 0) {
			*begin += sizeof (SPF_SCOPE_PRA) - 1;
			/* XXX: Implement actual PRA check */
			/* extract_pra_info (rec); */
			continue;
		}
		else if (g_ascii_strncasecmp (*begin, SPF_SCOPE_MFROM,
			sizeof (SPF_SCOPE_MFROM) - 1) == 0) {
			/* mfrom is standart spf1 check */
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

	/* Skip spaces */
	while (g_ascii_isspace (*begin)) {
		begin++;
	}

	if (g_ascii_strncasecmp (begin, SPF_VER1_STR, sizeof (SPF_VER1_STR) - 1) == 0) {
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
			msg_info ("<%s>: spf error for domain %s: sender id is invalid",
				rec->task->message_id, rec->sender_domain);
		}
		else {
			begin++;
			parse_spf_scopes (rec, &begin);
		}
		/* Now common spf record */
	}
	else {
		msg_debug ("<%s>: spf error for domain %s: bad spf record version: %*s",
			rec->task->message_id,
			rec->sender_domain,
			sizeof (SPF_VER1_STR) - 1,
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
			parse_spf_record (rec, resolved, *cur_elt);
			cur_elt ++;
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
	struct rdns_reply_entry *elt;
	struct spf_resolved_element *resolved;

	rec->requests_inflight--;

	if (reply->code == RDNS_RC_NOERROR) {
		resolved = rspamd_spf_new_addr_list (rec, rec->sender_domain);
		if (rec->resolved->len == 1) {
			/* Top level resolved element */
			rec->ttl = reply->entries->ttl;
		}

		LL_FOREACH (reply->entries, elt) {
			if (start_spf_parse (rec, resolved, elt->content.txt.data)) {
				break;
			}
		}
	}

	rspamd_spf_maybe_return (rec);
}

const gchar *
get_spf_domain (struct rspamd_task *task)
{
	const gchar *domain, *res = NULL;
	const gchar *sender;

	sender = rspamd_task_get_sender (task);

	if (sender != NULL) {
		domain = strchr (sender, '@');
		if (domain) {
			res = domain + 1;
		}
	}

	return res;
}

gboolean
resolve_spf (struct rspamd_task *task, spf_cb_t callback)
{
	struct spf_record *rec;
	gchar *domain;
	const gchar *sender;

	sender = rspamd_task_get_sender (task);

	rec = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct spf_record));
	rec->task = task;
	rec->callback = callback;

	rec->resolved = g_array_sized_new (FALSE, FALSE,
			sizeof (struct spf_resolved_element), 8);

	/* Add destructor */
	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)spf_record_destructor,
		rec);

	/* Extract from data */
	if (sender != NULL && (domain = strchr (sender, '@')) != NULL) {
		rec->sender = sender;

		rec->local_part = rspamd_mempool_alloc (task->task_pool,
				domain - sender);
		rspamd_strlcpy (rec->local_part, sender, domain - sender);
		rec->sender_domain = domain + 1;
	}
	else if (task->helo != NULL && strchr (task->helo, '.') != NULL) {
		/* For notifies we can check HELO identity and check SPF accordingly */
		/* XXX: very poor check */
		rec->local_part = rspamd_mempool_strdup (task->task_pool, "postmaster");
		rec->sender_domain = task->helo;
	}
	else {
		return FALSE;
	}

	if (make_dns_request (task->resolver, task->s, task->task_pool,
			spf_dns_callback,
			(void *)rec, RDNS_REQUEST_TXT, rec->sender_domain)) {
		task->dns_requests++;
		rec->requests_inflight++;
		return TRUE;
	}

	return FALSE;
}

struct spf_resolved *
spf_record_ref (struct spf_resolved *rec)
{
	REF_RETAIN (rec);
	return rec;
}

void
spf_record_unref (struct spf_resolved *rec)
{
	REF_RELEASE (rec);
}
