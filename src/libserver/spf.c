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
	gchar *ptr_host;
	spf_action_t cur_action;
	gboolean in_include;
};

#define CHECK_REC(rec)                                      \
	do {                                                        \
		if ((rec)->nested > SPF_MAX_NESTING ||                  \
			(rec)->dns_requests > SPF_MAX_DNS_REQUESTS) {       \
			msg_info ("<%s> spf recursion limit %d is reached, domain: %s", \
				(rec)->task->message_id, (rec)->dns_requests,   \
				(rec)->sender_domain);                          \
			return FALSE;                                       \
		}                                                       \
	} while (0)                                                 \

static gboolean parse_spf_record (struct spf_record *rec, const gchar *elt);
static gboolean start_spf_parse (struct spf_record *rec, gchar *begin,
	guint ttl);

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
rspamd_spf_new_addr (struct spf_record *rec, const gchar *elt)
{
	struct spf_resolved_element *resolved;
	gboolean need_shift = FALSE;
	struct spf_addr *naddr;

	/* Peek the top element */
	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);
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

static void
rspamd_spf_new_addr_list (struct spf_record *rec, const gchar *domain)
{
	struct spf_resolved_element resolved;

	resolved.redirected = FALSE;
	resolved.cur_domain = g_strdup (domain);
	resolved.elts = g_ptr_array_new_full (8, rspamd_spf_free_addr);

	g_array_append_val (rec->resolved, resolved);
}

/* Debugging function that dumps spf record in log */
static void
dump_spf_record (GList *addrs)
{
	struct spf_addr *addr;
	GList *cur;
	gint r = 0;
	gchar logbuf[BUFSIZ], c;
#ifdef HAVE_INET_PTON
	gchar ipbuf[INET6_ADDRSTRLEN];
#else
	struct in_addr ina;
#endif

	cur = addrs;

	while (cur) {
		addr = cur->data;
		if (!addr->is_list) {
			switch (addr->mech) {
			case SPF_FAIL:
				c = '-';
				break;
			case SPF_SOFT_FAIL:
			case SPF_NEUTRAL:
				c = '~';
				break;
			case SPF_PASS:
				c = '+';
				break;
			}
#ifdef HAVE_INET_PTON
			if (addr->data.normal.ipv6) {
				inet_ntop (AF_INET6, &addr->data.normal.d.in6, ipbuf,
					sizeof (ipbuf));

			}
			else {
				inet_ntop (AF_INET, &addr->data.normal.d.in4, ipbuf,
					sizeof (ipbuf));
			}
			r += snprintf (logbuf + r,
					sizeof (logbuf) - r,
					"%c%s/%d; ",
					c,
					ipbuf,
					addr->data.normal.mask);
#else
			ina.s_addr = addr->data.normal.d.in4.s_addr;
			r += snprintf (logbuf + r,
					sizeof (logbuf) - r,
					"%c%s/%d; ",
					c,
					inet_ntoa (ina),
					addr->data.normal.mask);
#endif
		}
		else {
			r += snprintf (logbuf + r,
					sizeof (logbuf) - r,
					"%s; ",
					addr->spf_string);
			dump_spf_record (addr->data.list);
		}
		cur = g_list_next (cur);
	}
	msg_info ("spf record: %s", logbuf);
}

/* Find position of address inside addrs list */
static GList *
spf_addr_find (GList *addrs, gpointer to_find)
{
	struct spf_addr *addr;
	GList *cur, *res = NULL;

	cur = addrs;
	while (cur) {
		addr = cur->data;
		if (addr->is_list) {
			if ((res = spf_addr_find (addr->data.list, to_find)) != NULL) {
				return cur;
			}
		}
		else {
			if (cur->data == to_find) {
				return cur;
			}
		}
		cur = g_list_next (cur);
	}

	return res;
}

/*
 * Destructor for spf record
 */
static void
spf_record_destructor (gpointer r)
{
	struct spf_record *rec = r;
	GList *cur;
	struct spf_addr *addr;

	if (rec->addrs) {
		cur = rec->addrs;
		while (cur) {
			addr = cur->data;
			if (addr->is_list && addr->data.list != NULL) {
				g_list_free (addr->data.list);
			}
			cur = g_list_next (cur);
		}
		g_list_free (rec->addrs);
	}
}

static gboolean
parse_spf_ipmask (const gchar *begin,
	struct spf_addr *addr,
	struct spf_record *rec)
{
	const gchar *pos;
	gchar mask_buf[5] = {'\0'}, *p;
	gint state = 0, dots = 0;
#ifdef HAVE_INET_PTON
	gchar ip_buf[INET6_ADDRSTRLEN];
#else
	gchar ip_buf[INET_ADDRSTRLEN];
#endif

	bzero (ip_buf,	 sizeof (ip_buf));
	bzero (mask_buf, sizeof (mask_buf));
	pos = begin;
	p = ip_buf;

	while (*pos) {
		switch (state) {
		case 0:
			/* Require ':' */
			if (*pos != ':') {
				msg_info ("<%s>: spf error for domain %s: semicolon missing",
					rec->task->message_id, rec->sender_domain);
				return FALSE;
			}
			state = 1;
			pos++;
			p = ip_buf;
			dots = 0;
			break;
		case 1:
#ifdef HAVE_INET_PTON
			if (p - ip_buf >= (gint)sizeof (ip_buf)) {
				return FALSE;
			}
			if (g_ascii_isxdigit (*pos)) {
				*p++ = *pos++;
			}
			else if (*pos == '.' || *pos == ':') {
				*p++ = *pos++;
				dots++;
			}
#else
			/* Begin parse ip */
			if (p - ip_buf >= (gint)sizeof (ip_buf) || dots > 3) {
				return FALSE;
			}
			if (g_ascii_isdigit (*pos)) {
				*p++ = *pos++;
			}
			else if (*pos == '.') {
				*p++ = *pos++;
				dots++;
			}
#endif
			else if (*pos == '/') {
				pos++;
				p = mask_buf;
				state = 2;
			}
			else {
				/* Invalid character */
				msg_info ("<%s>: spf error for domain %s: invalid ip address",
					rec->task->message_id, rec->sender_domain);
				return FALSE;
			}
			break;
		case 2:
			/* Parse mask */
			if (p - mask_buf >= (gint)sizeof (mask_buf)) {
				msg_info ("<%s>: spf error for domain %s: too long mask",
					rec->task->message_id, rec->sender_domain);
				return FALSE;
			}
			if (g_ascii_isdigit (*pos)) {
				*p++ = *pos++;
			}
			else {
				return FALSE;
			}
			break;
		}
	}

#ifdef HAVE_INET_PTON
	if (inet_pton (AF_INET, ip_buf, &addr->data.normal.d.in4) != 1) {
		if (inet_pton (AF_INET6, ip_buf, &addr->data.normal.d.in6) == 1) {
			addr->data.normal.ipv6 = TRUE;
		}
		else {
			msg_info ("<%s>: spf error for domain %s: invalid ip address",
				rec->task->message_id, rec->sender_domain);
			return FALSE;
		}
	}
	else {
		addr->data.normal.ipv6 = FALSE;
	}
#else
	if (!inet_aton (ip_buf, &addr->data.normal.d.in4)) {
		return FALSE;
	}
#endif
	if (state == 2) {
		/* Also parse mask */
		if (!addr->data.normal.ipv6) {
			addr->data.normal.mask = strtoul (mask_buf, NULL, 10);
			if (addr->data.normal.mask > 32) {
				msg_info (
					"<%s>: spf error for domain %s: bad ipmask value: '%s'",
					rec->task->message_id,
					rec->sender_domain,
					begin);
				return FALSE;
			}
		}
		else {
			addr->data.normal.mask = strtoul (mask_buf, NULL, 10);
			if (addr->data.normal.mask > 128) {
				msg_info (
					"<%s>: spf error for domain %s: bad ipmask value: '%s'",
					rec->task->message_id,
					rec->sender_domain,
					begin);
				return FALSE;
			}
		}
	}
	else {
		addr->data.normal.mask = addr->data.normal.ipv6 ? 128 : 32;
	}
	addr->data.normal.parsed = TRUE;
	return TRUE;

}

static void
spf_record_process_addr (struct rdns_reply_entry *elt,
	struct spf_dns_cb *cb, struct rspamd_task *task)
{
	struct spf_addr *addr = cb->addr, *new_addr;
	GList *tmp = NULL;

	if (elt->type == RDNS_REQUEST_A) {
		if (!addr->data.normal.parsed) {
			addr->data.normal.d.in4.s_addr = elt->content.a.addr.s_addr;
			addr->data.normal.parsed = TRUE;
		}
		else {
			/* Insert one more address */
			tmp = spf_addr_find (cb->rec->addrs, addr);
			if (tmp) {
				new_addr = rspamd_mempool_alloc (task->task_pool,
						sizeof (struct spf_addr));
				memcpy (new_addr, addr, sizeof (struct spf_addr));
				new_addr->data.normal.d.in4.s_addr = elt->content.a.addr.s_addr;
				new_addr->data.normal.parsed = TRUE;
				cb->rec->addrs = g_list_insert_before (cb->rec->addrs,
						tmp,
						new_addr);
			}
			else {
				msg_info ("<%s>: spf error for domain %s: addresses mismatch",
					task->message_id, cb->rec->sender_domain);
			}
		}

	}
	else if (elt->type == RDNS_REQUEST_AAAA) {
		if (!addr->data.normal.parsed) {
			memcpy (&addr->data.normal.d.in6,
				&elt->content.aaa.addr, sizeof (struct in6_addr));
			addr->data.normal.mask = 32;
			addr->data.normal.parsed = TRUE;
			addr->data.normal.ipv6 = TRUE;
		}
		else {
			/* Insert one more address */
			tmp = spf_addr_find (cb->rec->addrs, addr);
			if (tmp) {
				new_addr =
					rspamd_mempool_alloc (task->task_pool,
						sizeof (struct spf_addr));
				memcpy (new_addr, addr, sizeof (struct spf_addr));
				memcpy (&new_addr->data.normal.d.in6,
					&elt->content.aaa.addr, sizeof (struct in6_addr));
				new_addr->data.normal.parsed = TRUE;
				new_addr->data.normal.ipv6 = TRUE;
				cb->rec->addrs = g_list_insert_before (cb->rec->addrs,
						tmp,
						new_addr);
			}
			else {
				msg_info ("<%s>: spf error for domain %s: addresses mismatch",
					task->message_id, cb->rec->sender_domain);
			}
		}
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
		dstart = cb->rec->cur_domain;
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
			msg_debug ("ptr records missmatch: %s and %s", dend, nend);
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
spf_record_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct spf_dns_cb *cb = arg;
	gchar *begin;
	struct rdns_reply_entry *elt_data;
	GList *tmp = NULL;
	struct rspamd_task *task;
	gboolean ret;

	task = cb->rec->task;

	cb->rec->requests_inflight--;

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
					spf_record_process_addr (elt_data, cb, task);
				}
				break;
			case SPF_RESOLVE_A:
			case SPF_RESOLVE_AAA:
				spf_record_process_addr (elt_data, cb, task);
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
					spf_record_process_addr (elt_data, cb, task);
				}
				break;
			case SPF_RESOLVE_REDIRECT:
				if (elt_data->type == RDNS_REQUEST_TXT) {
					begin = elt_data->content.txt.data;

					if (!cb->in_include && cb->rec->addrs) {
						g_list_free (cb->rec->addrs);
						cb->rec->addrs = NULL;
					}
					start_spf_parse (cb->rec, begin, elt_data->ttl);

				}
				break;
			case SPF_RESOLVE_INCLUDE:
				if (elt_data->type == RDNS_REQUEST_TXT) {
					begin = elt_data->content.txt.data;
#ifdef SPF_DEBUG
					msg_info ("before include");
					dump_spf_record (cb->rec->addrs);
#endif
					tmp = cb->rec->addrs;
					cb->rec->addrs = NULL;
					cb->rec->in_include = TRUE;
					ret = start_spf_parse (cb->rec, begin, 0);
					cb->rec->in_include = FALSE;

#ifdef SPF_DEBUG
					msg_info ("after include");
					dump_spf_record (cb->rec->addrs);
#endif

					if (ret) {
						/* Insert new list */
						cb->addr->is_list = TRUE;
						cb->addr->data.list = cb->rec->addrs;
					}

					cb->rec->addrs = tmp;
				}
				break;
			case SPF_RESOLVE_EXP:
				break;
			case SPF_RESOLVE_EXISTS:
				if (elt_data->type == RDNS_REQUEST_A || elt_data->type ==
					RDNS_REQUEST_AAAA) {
					/* If specified address resolves, we can accept connection from every IP */
					cb->addr->data.normal.d.in4.s_addr = INADDR_NONE;
					cb->addr->data.normal.mask = 0;
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
					cb->rec->cur_domain);
				cb->addr->data.normal.d.in4.s_addr = INADDR_NONE;
				cb->addr->data.normal.mask = 32;
			}
			else {
				msg_info (
					"<%s>: spf error for domain %s: cannot resolve MX record for %s",
					task->message_id,
					cb->rec->sender_domain,
					cb->rec->cur_domain);
				cb->addr->data.normal.d.in4.s_addr = INADDR_NONE;
				cb->addr->data.normal.mask = 32;
			}
			break;
		case SPF_RESOLVE_A:
			if (rdns_request_has_type (reply->request, RDNS_REQUEST_A)) {
				cb->addr->data.normal.d.in4.s_addr = INADDR_NONE;
				cb->addr->data.normal.mask = 32;
			}
			break;
#ifdef HAVE_INET_PTON
		case SPF_RESOLVE_AAA:
			if (rdns_request_has_type (reply->request, RDNS_REQUEST_AAAA)) {
				memset (&cb->addr->data.normal.d.in6, 0xff,
					sizeof (struct in6_addr));
				cb->addr->data.normal.mask = 32;
			}
			break;
#endif
		case SPF_RESOLVE_PTR:
			break;
		case SPF_RESOLVE_REDIRECT:
			msg_info (
				"<%s>: spf error for domain %s: cannot resolve TXT record for %s",
				task->message_id,
				cb->rec->sender_domain,
				cb->rec->cur_domain);
			break;
		case SPF_RESOLVE_INCLUDE:
			msg_info (
				"<%s>: spf error for domain %s: cannot resolve TXT record for %s",
				task->message_id,
				cb->rec->sender_domain,
				cb->rec->cur_domain);
			break;
		case SPF_RESOLVE_EXP:
			break;
		case SPF_RESOLVE_EXISTS:
			cb->addr->data.normal.d.in4.s_addr = INADDR_NONE;
			cb->addr->data.normal.mask = 32;
			break;
		}
	}

	if (cb->rec->requests_inflight == 0) {
		cb->rec->callback (cb->rec, cb->rec->task);
	}
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
		parse_ipv6_mask
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
			state = parse_ipv4_mask;
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
parse_spf_a (struct rspamd_task *task,
	const gchar *begin,
	struct spf_record *rec,
	struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	gchar *host = NULL;

	CHECK_REC (rec);

	/*
	 * a
	 * a/<prefix-length>
	 * a:<domain>
	 * a:<domain>/<prefix-length>
	 */
	if (begin == NULL) {
		return FALSE;
	}
	if (*begin == '\0') {
		/* Use current domain only */
		host = rec->cur_domain;
		addr->data.normal.mask = 32;
	}
	else if (*begin == ':') {
		begin++;
	}
	else if (*begin != '/') {
		/* Invalid A record */
		return FALSE;
	}

	if (host == NULL) {
		host = parse_spf_hostmask (task, begin, addr, rec);
	}

	if (host == NULL) {
		return FALSE;
	}

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_A;
	cb->in_include = rec->in_include;
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
parse_spf_ptr (struct rspamd_task *task,
	const gchar *begin,
	struct spf_record *rec,
	struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	gchar *host, *ptr;

	CHECK_REC (rec);

	if (begin == NULL) {
		return FALSE;
	}
	if (*begin == ':') {
		begin++;
		host = rspamd_mempool_strdup (task->task_pool, begin);
	}
	else if (*begin == '\0') {
		host = NULL;
	}
	else {
		return FALSE;
	}

	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_PTR;
	cb->in_include = rec->in_include;
	cb->ptr_host = host;
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
	return TRUE;
}

static gboolean
parse_spf_mx (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	gchar *host;

	CHECK_REC (rec);

	if (begin == NULL) {
		return FALSE;
	}
	if (*begin == ':') {
		begin++;
	}

	host = parse_spf_hostmask (task, begin, addr, rec);

	if (host == NULL) {
		return FALSE;
	}
	rec->dns_requests++;
	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_MX;
	cb->in_include = rec->in_include;
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
	memset (&addr->addr, 0, sizeof (addr->addr));
	addr->m.mask = 0;
	addr->flags |= RSPAMD_SPF_FLAG_ANY;

	return TRUE;
}

static gboolean
parse_spf_ip4 (struct spf_record *rec, struct spf_addr *addr)
{
	/* ip4:addr[/mask] */

	CHECK_REC (rec);
	return parse_spf_ipmask (addr->spf_string, addr, rec);
}

#ifdef HAVE_INET_PTON
static gboolean
parse_spf_ip6 (struct spf_record *rec, struct spf_addr *addr)
{
	/* ip6:addr[/mask] */

	CHECK_REC (rec);
	return parse_spf_ipmask (addr->spf_string, addr, rec);
}
#endif

static gboolean
parse_spf_include (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	gchar *domain;
	struct spf_resolved_element *resolved;
	struct rspamd_task *task = rec->task;

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);

	CHECK_REC (rec);
	domain = strchr (addr->spf_string, '=');

	if (domain == NULL) {
		return FALSE;
	}

	domain++;

	rec->dns_requests++;

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_INCLUDE;
	/* Set reference */
	addr->flags |= RSPAMD_SPF_FLAG_REFRENCE;
	addr->m.mask = rec->resolved->len;
	rspamd_spf_new_addr_list (rec, domain);
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
parse_spf_redirect (struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	const gchar *domain;
	struct spf_resolved_element *resolved;
	struct spf_addr *cur;
	struct rspamd_task *task = rec->task;
	guint i;

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
			rec->resolved->len - 1);

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
			g_ptr_array_remove_index_fast (resolved->elts, i);
		}
	}

	cb = rspamd_mempool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	/* Set reference */
	addr->flags |= RSPAMD_SPF_FLAG_REFRENCE;
	addr->m.mask = rec->resolved->len;
	rspamd_spf_new_addr_list (rec, domain);

	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_REDIRECT;
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
	const gchar *p, *c;
	gchar *new, *tmp;
	gint len = 0, slen = 0, state = 0;
#ifdef HAVE_INET_PTON
	gchar ip_buf[INET6_ADDRSTRLEN];
#endif
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
#ifdef HAVE_INET_PTON
				len += INET6_ADDRSTRLEN - 1;
#else
				len += INET_ADDRSTRLEN - 1;
#endif
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
parse_spf_record (struct spf_record *rec, const gchar *elt)
{
	struct spf_addr *addr = NULL;
	gboolean res = FALSE;
	const gchar *begin;
	struct rspamd_task *task;
	struct spf_resolved_element *resolved;
	gchar t;

	resolved = &g_array_index (rec->resolved, struct spf_resolved_element,
		rec->resolved->len - 1);

	g_assert (elt != NULL);
	g_assert (rec != NULL);

	if (*elt == '\0' || resolved->redirected) {
		return TRUE;
	}

	task = rec->task;
	begin = expand_spf_macro (rec, elt);
	addr = rspamd_spf_new_addr (rec, begin);
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
			res = parse_spf_redirect (rec, addr);
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
		addr->flags |= RSPAMD_SPF_FLAG_VALID;
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
start_spf_parse (struct spf_record *rec, gchar *begin)
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
			parse_spf_record (rec, *cur_elt);
			cur_elt ++;
		}

		g_strfreev (elts);
	}
	return TRUE;
}

static void
spf_dns_callback (struct rdns_reply *reply, gpointer arg)
{
	struct spf_record *rec = arg;
	struct rdns_reply_entry *elt;

	rec->requests_inflight--;
	if (reply->code == RDNS_RC_NOERROR) {
		if (rec->resolved->len == 1) {
			/* Top level resolved element */
			rec->ttl = reply->entries->ttl;
		}

		LL_FOREACH (reply->entries, elt) {
			if (start_spf_parse (rec, elt->content.txt.data)) {
				break;
			}
		}
	}

	if (rec->requests_inflight == 0) {
		rec->callback (rec, rec->task);
	}
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

	rspamd_spf_new_addr_list (rec, rec->sender_domain);

	if (make_dns_request (task->resolver, task->s, task->task_pool,
			spf_dns_callback,
			(void *)rec, RDNS_REQUEST_TXT, rec->sender_domain)) {
		task->dns_requests++;
		rec->requests_inflight++;
		return TRUE;
	}
}

/*
 * vi:ts=4
 */
