/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "evdns/evdns.h"
#include "spf.h"
#include "main.h"
#include "message.h"
#include "filter.h"

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
#define SPF_MAX_NESTING 5
#define SPF_MAX_DNS_REQUESTS 10

/**
 * State machine for SPF record:
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

struct spf_dns_cb {
	struct spf_record *rec;
	struct spf_addr *addr;
	spf_action_t cur_action;
	gboolean in_include;
};

#define CHECK_REC(rec)										\
do {														\
	if ((rec)->nested > SPF_MAX_NESTING ||					\
		(rec)->dns_requests > SPF_MAX_DNS_REQUESTS) {		\
		return FALSE;										\
	}														\
} while (0)													\

static gboolean parse_spf_record (struct worker_task *task, struct spf_record *rec);
static void start_spf_parse (struct spf_record *rec, char *begin);

/* Determine spf mech */
static spf_mech_t
check_spf_mech (const char *elt, gboolean *need_shift)
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

static gboolean
parse_spf_ipmask (const char *begin, struct spf_addr *addr)
{
	const char *pos;
	char ip_buf[sizeof ("255.255.255.255")], mask_buf[3], *p;
	int state = 0, dots = 0;
	struct in_addr in;
	
	bzero (ip_buf, sizeof (ip_buf));
	bzero (mask_buf, sizeof (mask_buf));
	pos = begin;

	while (*pos) {
		switch (state) {
			case 0:
				/* Require ':' */
				if (*pos != ':') {
					return FALSE;
				}
				state = 1;
				pos ++;
				p = ip_buf;
				dots = 0;
				break;
			case 1:
				/* Begin parse ip */
				if (p - ip_buf >= sizeof (ip_buf) || dots > 3) {
					return FALSE;
				}
				if (g_ascii_isdigit (*pos)) {
					*p ++ = *pos ++;
				}
				else if (*pos == '.') {
					*p ++ = *pos ++;
					dots ++;
				}
				else if (*pos == '/') {
					pos ++;
					p = mask_buf;
					state = 2;
				}
				else {
					/* Invalid character */
					return FALSE;
				}
				break;
			case 2:
				/* Parse mask */
				if (p - mask_buf > 2) {
					return FALSE;
				}
				if (g_ascii_isdigit (*pos)) {
					*p ++ = *pos ++;
				}
				else {
					return FALSE;
				}
				break;
		}
	}

	if (!inet_aton (ip_buf, &in)) {
		return FALSE;
	}
	addr->addr = ntohl (in.s_addr);
	if (state == 2) {
		/* Also parse mask */
		addr->mask = (mask_buf[0] - '0') * 10 + mask_buf[1] - '0';
		if (addr->mask > 32) {
			msg_info ("bad ipmask value: '%s'", begin);
			return FALSE;
		}
	}
	else {
		addr->mask = 32;
	}

	return TRUE;

}

static char *
parse_spf_hostmask (struct worker_task *task, const char *begin, struct spf_addr *addr, struct spf_record *rec)
{
	char *host = NULL, *p,  mask_buf[3];
	int hostlen;

	bzero (mask_buf, sizeof (mask_buf));
	if (*begin == '\0' || *begin == '/') {
		/* Assume host as host to resolve from record */
		host = rec->cur_domain;
	}
	p = strchr (begin, '/');
	if (p != NULL) {
		/* Extract mask */
		g_strlcpy (mask_buf, p + 1, sizeof (mask_buf));
		addr->mask = mask_buf[0] * 10 + mask_buf[1];
		if (addr->mask > 32) {
			return FALSE;
		}
		if (host == NULL) {
			hostlen = p - begin;
			host = memory_pool_alloc (task->task_pool, hostlen);
			g_strlcpy (host, begin, hostlen);
		}
	}
	else {
		addr->mask = 32;
		if (host == NULL) {
			host = memory_pool_strdup (task->task_pool, begin);
		}
	}

	return host;
}

static void
spf_record_dns_callback (int result, char type, int count, int ttl, void *addresses, void *data)
{
	struct spf_dns_cb *cb = data;
	char *begin;
	struct evdns_mx *mx;
	GList *tmp = NULL, *elt, *last;

	if (result == DNS_ERR_NONE) {
		if (addresses != NULL) {
			/* Add all logic for all DNS states here */
			switch (cb->cur_action) {
				case SPF_RESOLVE_MX:
					if (type == DNS_MX) {
						mx = (struct evdns_mx *)addresses;
						/* Now resolve A record for this MX */
						if (evdns_resolve_ipv4 (mx->host, DNS_QUERY_NO_SEARCH, spf_record_dns_callback, (void *)cb) == 0) {
							return;
						}
					}
					else if (type == DNS_IPv4_A) {
						/* XXX: process only one record */
						cb->addr->addr = ntohl (*((uint32_t *)addresses));
					}
					break;
				case SPF_RESOLVE_A:
					if (type == DNS_IPv4_A) {
						/* XXX: process only one record */
						cb->addr->addr = ntohl (*((uint32_t *)addresses));
					}
					break;
				case SPF_RESOLVE_PTR:
					break;
				case SPF_RESOLVE_REDIRECT:
					if (type == DNS_TXT) {
						if (addresses != NULL) {
							begin = *(char **)addresses;

							if (!cb->in_include && cb->rec->addrs) {
								g_list_free (cb->rec->addrs);
								cb->rec->addrs = NULL;
							}
							start_spf_parse (cb->rec, begin);
						}
					}
					break;
				case SPF_RESOLVE_INCLUDE:
					if (type == DNS_TXT) {
						if (addresses != NULL) {
							begin = *(char **)addresses;
							if (cb->rec->addrs) {
								tmp = cb->rec->addrs;
								cb->rec->addrs = NULL;
							}
							cb->rec->in_include = TRUE;
							start_spf_parse (cb->rec, begin);
							cb->rec->in_include = FALSE;

							if (tmp) {
								elt = g_list_find (tmp, cb->addr);
								if (elt) {
									/* Insert new list in place of include element */
									last = g_list_last (cb->rec->addrs);

									if (elt->prev == NULL && elt->next == NULL) {
										g_list_free1 (elt);
									}
									else {

										if (elt->prev) {
											elt->prev->next = cb->rec->addrs;
										}
										else {
											/* Elt is the first element, so we need to shift temporary list */
											tmp = elt->next;
											tmp->prev = NULL;
										}
										if (elt->next) {
											elt->next->prev = last;
											if (last != NULL) {
												last->next = elt->next;
											}
										}
										
										if (cb->rec->addrs != NULL) {
											cb->rec->addrs->prev = elt->prev;
										}

										/* Shift temporary list */
										while (tmp->prev) {
											tmp = tmp->prev;
										}

										cb->rec->addrs = tmp;
										g_list_free1 (elt);
									}
								}
							}
						}
					}
					break;
				case SPF_RESOLVE_EXP:
					break;
				case SPF_RESOLVE_EXISTS:
					if (type == DNS_IPv4_A) {
						/* If specified address resolves, we can accept connection from every IP */
						cb->addr->addr = ntohl (INADDR_ANY);
						cb->addr->mask = 0;
					}
					break;
			}
		}
	}
	else if (result == DNS_ERR_NOTEXIST) {
		switch (cb->cur_action) {
				case SPF_RESOLVE_MX:
					if (type == DNS_MX) {
						msg_info ("cannot find MX record for %s", cb->rec->cur_domain);
						cb->addr->addr = ntohl (INADDR_NONE);
					}
					else if (type == DNS_IPv4_A) {
						msg_info ("cannot resolve MX record for %s", cb->rec->cur_domain);
						cb->addr->addr = ntohl (INADDR_NONE);
					}
					break;
				case SPF_RESOLVE_A:
					if (type == DNS_IPv4_A) {
						/* XXX: process only one record */
						cb->addr->addr = ntohl (INADDR_NONE);
					}
					break;
				case SPF_RESOLVE_PTR:
					break;
				case SPF_RESOLVE_REDIRECT:
					msg_info ("cannot resolve TXT record for redirect action");
					break;
				case SPF_RESOLVE_INCLUDE:
					msg_info ("cannot resolve TXT record for include action");
					break;
				case SPF_RESOLVE_EXP:
					break;
				case SPF_RESOLVE_EXISTS:
					cb->addr->addr = ntohl (INADDR_NONE);
					break;
		}
	}

	cb->rec->task->save.saved--;
	if (cb->rec->task->save.saved == 0 && cb->rec->callback) {
		cb->rec->callback (cb->rec, cb->rec->task);
		if (cb->rec->addrs) {
			g_list_free (cb->rec->addrs);
			cb->rec->addrs = NULL;
		}
	}
	remove_forced_event (cb->rec->task->s, (event_finalizer_t) spf_record_dns_callback);

}

static gboolean
parse_spf_a (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	char *host;
	
	CHECK_REC (rec);
	
	if (begin == NULL || *begin != ':') {
		return FALSE;
	}
	begin ++;
	
	host = parse_spf_hostmask (task, begin, addr, rec);
	
	if (!host) {
		return FALSE;
	}

	rec->dns_requests ++;
	cb = memory_pool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_A;
	cb->in_include = rec->in_include;

	if (evdns_resolve_ipv4 (host, DNS_QUERY_NO_SEARCH, spf_record_dns_callback, (void *)cb) == 0) {
		task->save.saved++;
		register_async_event (task->s, (event_finalizer_t) spf_record_dns_callback, NULL, TRUE);
		
		return TRUE;
	}

	return FALSE;

}

static gboolean
parse_spf_ptr (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	CHECK_REC (rec);
	
	msg_info ("ptr parsing is unimplemented");
	return FALSE;
}

static gboolean
parse_spf_mx (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	char *host;
	
	CHECK_REC (rec);
	
	if (begin == NULL) {
		return FALSE;
	}
	if (*begin == ':') {
		begin ++;
	}
	
	host = parse_spf_hostmask (task, begin, addr, rec);
	
	if (!host) {
		return FALSE;
	}

	rec->dns_requests ++;
	cb = memory_pool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_MX;
	cb->in_include = rec->in_include;

	if (evdns_resolve_mx (host, DNS_QUERY_NO_SEARCH, spf_record_dns_callback, (void *)cb) == 0) {
		task->save.saved++;
		register_async_event (task->s, (event_finalizer_t) spf_record_dns_callback, NULL, TRUE);
		
		return TRUE;
	}

	return FALSE;
}

static gboolean
parse_spf_all (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	/* All is 0/0 */
	if (rec->in_include) {
		/* Ignore all record in include */
		addr->addr = 0;
		addr->mask = 32;
	}
	else {
		addr->addr = 0;
		addr->mask = 0;
	}

	return TRUE;
}

static gboolean
parse_spf_ip4 (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	/* ip4:addr[/mask] */

	CHECK_REC (rec);
	return parse_spf_ipmask (begin, addr);
}

static gboolean
parse_spf_include (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	char              *domain;

	CHECK_REC (rec);

	if (begin == NULL || *begin != ':') {
		return FALSE;
	}
	begin ++;
	rec->dns_requests ++;

	cb = memory_pool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_INCLUDE;
	cb->in_include = rec->in_include;
	domain = memory_pool_strdup (task->task_pool, begin);

	if (evdns_resolve_txt (domain, DNS_QUERY_NO_SEARCH, spf_record_dns_callback, (void *)cb) == 0) {
		task->save.saved++;
		register_async_event (task->s, (event_finalizer_t) spf_record_dns_callback, NULL, TRUE);
		
		return TRUE;
	}

	return FALSE;
}

static gboolean
parse_spf_exp (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	CHECK_REC (rec);

	msg_info ("exp record is ignored");
	return TRUE;
}

static gboolean
parse_spf_redirect (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	char              *domain;

	CHECK_REC (rec);

	if (begin == NULL || *begin != '=') {
		return FALSE;
	}
	begin ++;
	rec->dns_requests ++;

	cb = memory_pool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_REDIRECT;
	cb->in_include = rec->in_include;
	domain = memory_pool_strdup (task->task_pool, begin);

	if (evdns_resolve_txt (domain, DNS_QUERY_NO_SEARCH, spf_record_dns_callback, (void *)cb) == 0) {
		task->save.saved++;
		register_async_event (task->s, (event_finalizer_t) spf_record_dns_callback, NULL, TRUE);
		
		return TRUE;
	}

	return FALSE;
}

static gboolean
parse_spf_exists (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
	char              *host;

	CHECK_REC (rec);
	
	if (begin == NULL || *begin != ':') {
		return FALSE;
	}
	begin ++;
	rec->dns_requests ++;

	addr->mask = 32;
	cb = memory_pool_alloc (task->task_pool, sizeof (struct spf_dns_cb));
	cb->rec = rec;
	cb->addr = addr;
	cb->cur_action = SPF_RESOLVE_EXISTS;
	cb->in_include = rec->in_include;
	host = memory_pool_strdup (task->task_pool, begin);

	if (evdns_resolve_ipv4 (host, DNS_QUERY_NO_SEARCH, spf_record_dns_callback, (void *)cb) == 0) {
		task->save.saved++;
		register_async_event (task->s, (event_finalizer_t) spf_record_dns_callback, NULL, TRUE);
		
		return TRUE;
	}

	return FALSE;
}

static void
reverse_spf_ip (char *ip, int len)
{
	char ipbuf[sizeof("255.255.255.255") - 1], *p, *c;
	int t = 0, l = len;

	if (len > sizeof (ipbuf)) {
		msg_info ("cannot reverse string of length %d", len);
		return;
	}

	p = ipbuf + len;
	c = ip; 
	while (-- l) {
		if (*c == '.') {
			memcpy (p, c - t, t);
			*--p = '.';
			c ++;
			t = 0;
			continue;
		}

		t ++;
		c ++;
		p --;
	}

	memcpy (p - 1, c - t, t + 1);

	memcpy (ip, ipbuf, len);
}

static char *
expand_spf_macro (struct worker_task *task, struct spf_record *rec, char *begin)
{
	char *p, *c, *new, *tmp;
	int len = 0, slen = 0, state = 0;

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
					len ++;
				}

				slen ++;
				p ++;
				break;
			case 1:
				/* We got % sign, so we should whether wait for { or for - or for _ or for % */
				if (*p == '%' || *p == '-') {
					/* Just a single % sign or space */
					len ++;
				}
				else if (*p == '_') {
					/* %20 */
					len += sizeof ("%20") - 1;
				}
				else if (*p == '{') {
					state = 2;
				}
				else {
					/* Something unknown */
					msg_info ("bad spf element: %s", begin);
					return begin;
				}
				p ++;
				slen ++;
				break;
			case 2:
				/* Read macro name */
				switch (*p) {
					case 'i':
						len += sizeof ("255.255.255.255") - 1;
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
						len += strlen (rec->cur_domain);
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
						msg_info ("unknown or unsupported spf macro %c in %s", *p, begin);
						return begin;
				}
				p ++;
				slen ++;
				state = 3;
				break;
			case 3:
				/* Read modifier */
				if (*p == '}') {
					state = 0;
				}
				else if (*p != 'r' && !g_ascii_isdigit (*p)) {
					msg_info ("unknown or unsupported spf modifier %c in %s", *p, begin);
					return begin;
				} 
				p ++;
				slen ++;
				break;
		}
	}

	if (slen == len) {
		/* No expansion needed */
		return begin;
	}
	
	new = memory_pool_alloc (task->task_pool, len + 1);

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
					c ++;
				}

				p ++;
				break;
			case 1:
				/* We got % sign, so we should whether wait for { or for - or for _ or for % */
				if (*p == '%') {
					/* Just a single % sign or space */
					*c++ = '%';
				}
				else if (*p == '-') {
					*c++ = ' ';
				}
				else if (*p == '_') {
					/* %20 */
					*c++ = '%';
					*c++ = '2';
					*c++ = '0';
				}
				else if (*p == '{') {
					state = 2;
				}
				else {
					/* Something unknown */
					msg_info ("bad spf element: %s", begin);
					return begin;
				}
				p ++;
				break;
			case 2:
				/* Read macro name */
				switch (*p) {
					case 'i':
						tmp = inet_ntoa (task->from_addr);
						len = strlen (tmp);
						memcpy (c, tmp, len);
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
						len = strlen (rec->cur_domain);
						memcpy (c, rec->cur_domain, len);
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
						msg_info ("unknown or unsupported spf macro %c in %s", *p, begin);
						return begin;
				}
				p ++;
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
					/*XXX: try to implement domain strimming */
				}
				else {
					msg_info ("unknown or unsupported spf modifier %c in %s", *p, begin);
					return begin;
				} 
				p ++;
				break;
		}
	}
	/* Null terminate */
	*c = '\0';
	msg_info ("%s", new);
	return new;
	
}

#define NEW_ADDR(x) do {														\
	(x) = memory_pool_alloc (task->task_pool, sizeof (struct spf_addr));		\
	(x)->mech = check_spf_mech (rec->cur_elt, &need_shift);						\
	(x)->spf_string = memory_pool_strdup (task->task_pool, begin);				\
} while (0);

/* Read current element and try to parse record */
static gboolean
parse_spf_record (struct worker_task *task, struct spf_record *rec)
{
	struct spf_addr *new = NULL;
	gboolean need_shift, res = FALSE;
	char *begin;
	
	rec->cur_elt = rec->elts[rec->elt_num];
	if (rec->cur_elt == NULL) {
		return FALSE;
	}
	else if (*rec->cur_elt == '\0') {
		/* Silently skip empty elements */
		rec->elt_num ++;
		return TRUE;
	}
	else {
		begin = expand_spf_macro (task, rec, rec->cur_elt);
		if (*begin == '?' || *begin == '+' || *begin == '-' || *begin == '~') {
			begin ++;
		}


		/* Now check what we have */
		switch (*begin) {
			case 'a':
				/* all or a */
				if (strncmp (begin, SPF_ALL, sizeof (SPF_ALL) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_ALL) - 1;
					res = parse_spf_all (task, begin, rec, new);
				}
				else if (strncmp (begin, SPF_A, sizeof (SPF_A) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_A) - 1;
					res = parse_spf_a (task, begin, rec, new);
				}
				else {
					msg_info ("bad spf command: %s", begin);
				}
				break;
			case 'i':
				/* include or ip4 */
				if (strncmp (begin, SPF_IP4, sizeof (SPF_IP4) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_IP4) - 1;
					res = parse_spf_ip4 (task, begin, rec, new);
				}
				else if (strncmp (begin, SPF_INCLUDE, sizeof (SPF_INCLUDE) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_INCLUDE) - 1;
					res = parse_spf_include (task, begin, rec, new);
				}
				else if (strncmp (begin, SPF_IP6, sizeof (SPF_IP4) - 1) == 0) {
					begin += sizeof (SPF_IP6) - 1;
					msg_info ("ignoring ip6 spf command as IPv6 is not supported: %s", begin);
					new = NULL;
					res = TRUE;
				}
				else {
					msg_info ("bad spf command: %s", begin);
				}
				break;
			case 'm':
				/* mx */
				if (strncmp (begin, SPF_MX, sizeof (SPF_MX) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_MX) - 1;
					res = parse_spf_mx (task, begin, rec, new);
				}
				else {
					msg_info ("bad spf command: %s", begin);
				}
				break;
			case 'p':
				/* ptr */
				if (strncmp (begin, SPF_PTR, sizeof (SPF_PTR) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_PTR) - 1;
					res = parse_spf_ptr (task, begin, rec, new);
				}
				else {
					msg_info ("bad spf command: %s", begin);
				}
				break;
			case 'e':
				/* exp or exists */
				if (strncmp (begin, SPF_EXP, sizeof (SPF_EXP) - 1) == 0) {
					begin += sizeof (SPF_EXP) - 1;
					res = parse_spf_exp (task, begin, rec, NULL);
				}
				else if (strncmp (begin, SPF_EXISTS, sizeof (SPF_EXISTS) - 1) == 0) {
					NEW_ADDR (new);
					begin += sizeof (SPF_EXISTS) - 1;
					res = parse_spf_exists (task, begin, rec, new);
				}
				else {
					msg_info ("bad spf command: %s", begin);
				}
				break;
			case 'r':
				/* redirect */
				if (strncmp (begin, SPF_REDIRECT, sizeof (SPF_REDIRECT) - 1) == 0) {
					begin += sizeof (SPF_REDIRECT) - 1;
					res = parse_spf_redirect (task, begin, rec, NULL);
				}
				else {
					msg_info ("bad spf command: %s", begin);
				}
				break;
			default:
				msg_info ("bad spf command: %s", begin);
				break;
		}
		if (res) {
			if (new != NULL) {
				rec->addrs = g_list_prepend (rec->addrs, new);
			}
			rec->elt_num ++;
		}
	}

	return res;
}
#undef NEW_ADDR

static void
parse_spf_scopes (struct spf_record *rec, char **begin)
{
	for (;;) {
		if (g_ascii_strncasecmp (*begin, SPF_SCOPE_PRA, sizeof (SPF_SCOPE_PRA) - 1) == 0) {
			*begin += sizeof (SPF_SCOPE_PRA) - 1;
			/* XXX: Implement actual PRA check */
			/* extract_pra_info (rec); */
			continue;
		}
		else if (g_ascii_strncasecmp (*begin, SPF_SCOPE_MFROM, sizeof (SPF_SCOPE_MFROM) - 1) == 0) {
			/* mfrom is standart spf1 check */
			*begin += sizeof (SPF_SCOPE_MFROM) - 1;
			continue;
		}
		else if (**begin != ',') {
			break;
		}
		(*begin) ++;
	}
}

static void
start_spf_parse (struct spf_record *rec, char *begin)
{
	/* Skip spaces */
	while (g_ascii_isspace (*begin)) {
		begin ++;
	}

	if (g_ascii_strncasecmp (begin, SPF_VER1_STR, sizeof (SPF_VER1_STR) - 1) == 0) {
		begin += sizeof (SPF_VER1_STR) - 1;
		while (g_ascii_isspace (*begin) && *begin) {
			begin ++;
		}
		rec->elts = g_strsplit_set (begin, " ", 0);
		rec->elt_num = 0;
		if (rec->elts) {
			memory_pool_add_destructor (rec->task->task_pool, (pool_destruct_func)g_strfreev, rec->elts);
			rec->cur_elt = rec->elts[0];
			while (parse_spf_record (rec->task, rec));
			if (rec->addrs) {
				rec->addrs = g_list_reverse (rec->addrs);
			}
		}
	}
	else if (g_ascii_strncasecmp (begin, SPF_VER2_STR, sizeof (SPF_VER2_STR) - 1) == 0) {
		/* Skip one number of record, so no we are here spf2.0/ */
		begin += sizeof (SPF_VER2_STR);
		if (*begin != '/') {
			msg_info ("sender id string has not valid skope");
		}
		else {
			begin ++;
			parse_spf_scopes (rec, &begin);
		}
		/* Now common spf record */
		while (g_ascii_isspace (*begin) && *begin) {
			begin ++;
		}
		rec->elts = g_strsplit_set (begin, " ", 0);
		rec->elt_num = 0;
		if (rec->elts) {
			memory_pool_add_destructor (rec->task->task_pool, (pool_destruct_func)g_strfreev, rec->elts);
			rec->cur_elt = rec->elts[0];
			while (parse_spf_record (rec->task, rec));
			if (rec->addrs) {
				rec->addrs = g_list_reverse (rec->addrs);
			}
		}
	}
	else {
		msg_info ("bad spf record version: %*s", sizeof (SPF_VER1_STR) - 1, begin);
	}
}

static void
spf_dns_callback (int result, char type, int count, int ttl, void *addresses, void *data)
{
	struct spf_record *rec = data;
	char *begin;

	if (result == DNS_ERR_NONE && type == DNS_TXT) {
		if (addresses != NULL) {
			begin = *(char **)addresses;
			start_spf_parse (rec, begin);
		}
	}

	rec->task->save.saved--;
	if (rec->task->save.saved == 0 && rec->callback) {
		rec->callback (rec, rec->task);
	}
	remove_forced_event (rec->task->s, (event_finalizer_t) spf_dns_callback);

}


gboolean
resolve_spf (struct worker_task *task, spf_cb_t callback)
{
	struct spf_record *rec;
	char *domain;
	GList *domains;

	rec = memory_pool_alloc0 (task->task_pool, sizeof (struct spf_record));
	rec->task = task;
	rec->callback = callback;

	if (task->from && (domain = strchr (task->from, '@'))) {
		rec->sender = task->from;

		rec->local_part = memory_pool_strdup (task->task_pool, task->from);
		*(rec->local_part + (domain - task->from)) = '\0';
		if (*rec->local_part == '<') {
			memmove (rec->local_part, rec->local_part + 1, strlen (rec->local_part));
		}
		rec->cur_domain = memory_pool_strdup (task->task_pool, domain + 1);
		if ((domain = strchr (rec->cur_domain, '>')) != NULL) {
			*domain = '\0';
		}
		rec->sender_domain = rec->cur_domain;

		if (evdns_resolve_txt (rec->cur_domain, DNS_QUERY_NO_SEARCH, spf_dns_callback, (void *)rec) == 0) {
			task->save.saved++;
			register_async_event (task->s, (event_finalizer_t) spf_dns_callback, NULL, TRUE);

			return TRUE;
		}
	}
	else {
		domains = message_get_header (task->task_pool, task->message, "From");

		if (domains != NULL) {
			rec->cur_domain = memory_pool_strdup (task->task_pool, domains->data);
			g_list_free (domains);

			if ((domain = strchr (rec->cur_domain, '@')) == NULL) {
				return FALSE;
			}
			rec->sender = memory_pool_strdup (task->task_pool, rec->cur_domain);
			rec->local_part = rec->cur_domain;
			*domain = '\0';
			rec->cur_domain = domain + 1;

			if ((domain = strchr (rec->local_part, '<')) != NULL) {
				memmove (rec->local_part, domain + 1, strlen (domain));
			}

			if ((domain = strchr (rec->cur_domain, '>')) != NULL) {
				*domain = '\0';
			}
			rec->sender_domain = rec->cur_domain;
			if (evdns_resolve_txt (rec->cur_domain, DNS_QUERY_NO_SEARCH, spf_dns_callback, (void *)rec) == 0) {
				task->save.saved++;
				register_async_event (task->s, (event_finalizer_t) spf_dns_callback, NULL, TRUE);
	
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* 
 * vi:ts=4 
 */
