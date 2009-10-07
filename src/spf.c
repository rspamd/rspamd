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

#define SPF_VER_STR "spf=v1"
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
};

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

static void
parse_spf_a (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;
}

static void
parse_spf_ptr (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;

}

static void
parse_spf_mx (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;

}

static void
parse_spf_all (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{

}

static void
parse_spf_ip4 (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{

}

static void
parse_spf_include (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;

}

static void
parse_spf_exp (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;

}

static void
parse_spf_redirect (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;

}

static void
parse_spf_exists (struct worker_task *task, const char *begin, struct spf_record *rec, struct spf_addr *addr)
{
	struct spf_dns_cb *cb;

}

/* Read current element and try to parse record */
static gboolean
parse_spf_record (struct worker_task *task, struct spf_record *rec)
{
	struct spf_addr *new;
	gboolean need_shift;
	char *begin;

	if (*rec->cur_elt == NULL) {
		return TRUE;
	}
	else {
		/* Check spf mech */
		new = memory_pool_alloc (task->task_pool, sizeof (struct spf_addr));
		new->mech = check_spf_mech (*rec->cur_elt, &need_shift);
		if (need_shift) {
			begin = (*rec->cur_elt)++;
		}
		else {
			begin = *rec->cur_elt;
		}
		/* Now check what we have */
		switch (*begin) {
			case 'a':
				/* all or a */
				if (strncmp (begin, SPF_A, sizeof (SPF_A) - 1) == 0) {
					begin += sizeof (SPF_A) - 1;
					parse_spf_a (task, begin, rec, new);
				}
				else if (strncmp (begin, SPF_ALL, sizeof (SPF_ALL) - 1) == 0) {
					begin += sizeof (SPF_ALL) - 1;
					parse_spf_all (task, begin, rec, new);
				}
				else {
					msg_info ("parse_spf_record: bad spf command");
				}
				break;
			case 'i':
				/* include or ip4 */
				if (strncmp (begin, SPF_IP4, sizeof (SPF_IP4) - 1) == 0) {
					begin += sizeof (SPF_IP4) - 1;
					parse_spf_ip4 (task, begin, rec, new);
				}
				else if (strncmp (begin, SPF_INCLUDE, sizeof (SPF_INCLUDE) - 1) == 0) {
					begin += sizeof (SPF_INCLUDE) - 1;
					parse_spf_include (task, begin, rec, new);
				}
				else {
					msg_info ("parse_spf_record: bad spf command");
				}
				break;
			case 'm':
				/* mx */
				if (strncmp (begin, SPF_MX, sizeof (SPF_MX) - 1) == 0) {
					begin += sizeof (SPF_MX) - 1;
					parse_spf_mx (task, begin, rec, new);
				}
				else {
					msg_info ("parse_spf_record: bad spf command");
				}
				break;
			case 'p':
				/* ptr */
				if (strncmp (begin, SPF_PTR, sizeof (SPF_PTR) - 1) == 0) {
					begin += sizeof (SPF_PTR) - 1;
					parse_spf_ptr (task, begin, rec, new);
				}
				else {
					msg_info ("parse_spf_record: bad spf command");
				}
				break;
			case 'e':
				/* exp or exists */
				if (strncmp (begin, SPF_EXP, sizeof (SPF_EXP) - 1) == 0) {
					begin += sizeof (SPF_EXP) - 1;
					parse_spf_exp (task, begin, rec, new);
				}
				else if (strncmp (begin, SPF_EXISTS, sizeof (SPF_EXISTS) - 1) == 0) {
					begin += sizeof (SPF_EXISTS) - 1;
					parse_spf_exists (task, begin, rec, new);
				}
				else {
					msg_info ("parse_spf_record: bad spf command");
				}
				break;
			case 'r':
				/* redirect */
				if (strncmp (begin, SPF_REDIRECT, sizeof (SPF_REDIRECT) - 1) == 0) {
					begin += sizeof (SPF_REDIRECT) - 1;
					parse_spf_redirect (task, begin, rec, new);
				}
				else {
					msg_info ("parse_spf_record: bad spf command");
				}
				break;
			default:
				msg_info ("parse_spf_record: bad spf command");
				break;
		}
		rec->addrs = g_list_prepend (rec->addrs, new);
		rec->cur_elt ++;
	}
}

static void
spf_dns_callback (int result, char type, int count, int ttl, void *addresses, void *data)
{
	struct spf_record *rec = data;
	char *begin;

	if (result == DNS_ERR_NONE && type == DNS_TXT) {
		if (addresses != NULL) {
			begin = (char *)addresses;
			if (strncmp (begin, SPF_VER_STR, sizeof (SPF_VER_STR) - 1) == 0) {
				begin += sizeof (SPF_VER_STR) - 1;
				while (g_ascii_isspace (*begin) && *begin) {
					begin ++;
				}
			}
			rec->elts = g_strsplit (begin, " ", 0);
			if (rec->elts) {
				memory_pool_add_destructor (rec->task->task_pool, (pool_destruct_func)g_strfreev, rec->elts);
				rec->cur_elt = rec->elts;
				while (!parse_spf_record (rec->task, rec));
			}
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

	domain = strchr (task->from, '@');
	if (domain != NULL) {
		rec->cur_domain = memory_pool_strdup (task->task_pool, domain);
		if ((domain = strchr (rec->cur_domain, '>')) != NULL) {
			*domain = '\0';
		}

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
			if ((domain = strchr (rec->cur_domain, '>')) != NULL) {
				*domain = '\0';
			}
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
