/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rspamd.h"
#include "message.h"
#include "utlist.h"
#include "libserver/http/http_private.h"
#include "worker_private.h"
#include "libserver/cfg_file_private.h"
#include "libmime/scan_result_private.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "protocol_internal.h"
#include "libserver/mempool_vars_internal.h"
#include "libserver/worker_util.h"
#include "rspamd_simdutf.h"
#include "task.h"
#include "lua/lua_classnames.h"
#include "multipart_form.h"
#include "multipart_response.h"
#include "libmime/content_type.h"
#include <math.h>

#ifdef SYS_ZSTD
#include "zstd.h"
#else
#include "contrib/zstd/zstd.h"
#endif

INIT_LOG_MODULE(protocol)

#define msg_err_protocol(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,                 \
														  "protocol", task->task_pool->tag.uid, \
														  G_STRFUNC,                            \
														  __VA_ARGS__)
#define msg_warn_protocol(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,                  \
														   "protocol", task->task_pool->tag.uid, \
														   G_STRFUNC,                            \
														   __VA_ARGS__)
#define msg_info_protocol(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                     \
														   "protocol", task->task_pool->tag.uid, \
														   G_STRFUNC,                            \
														   __VA_ARGS__)
#define msg_debug_protocol(...) rspamd_conditional_debug_fast(NULL, NULL,                                                   \
															  rspamd_protocol_log_id, "protocol", task->task_pool->tag.uid, \
															  G_STRFUNC,                                                    \
															  __VA_ARGS__)

static GQuark
rspamd_protocol_quark(void)
{
	return g_quark_from_static_string("protocol-error");
}

/*
 * Remove <> from the fixed string and copy it to the pool
 */
static char *
rspamd_protocol_escape_braces(struct rspamd_task *task, rspamd_ftok_t *in)
{
	unsigned int nchars = 0;
	const char *p;
	rspamd_ftok_t tok;
	gboolean has_obrace = FALSE;

	g_assert(in != NULL);
	g_assert(in->len > 0);

	p = in->begin;

	while ((g_ascii_isspace(*p) || *p == '<') && nchars < in->len) {
		if (*p == '<') {
			has_obrace = TRUE;
		}

		p++;
		nchars++;
	}

	tok.begin = p;

	p = in->begin + in->len - 1;
	tok.len = in->len - nchars;

	while (g_ascii_isspace(*p) && tok.len > 0) {
		p--;
		tok.len--;
	}

	if (has_obrace && *p == '>') {
		tok.len--;
	}

	return rspamd_mempool_ftokdup(task->task_pool, &tok);
}

#define COMPARE_CMD(str, cmd, len) (sizeof(cmd) - 1 == (len) && rspamd_lc_cmp((str), (cmd), (len)) == 0)

static gboolean
rspamd_protocol_handle_url(struct rspamd_task *task,
						   struct rspamd_http_message *msg)
{
	GHashTable *query_args;
	GHashTableIter it;
	struct http_parser_url u;
	const char *p;
	gsize pathlen;
	rspamd_ftok_t *key, *value;
	gpointer k, v;

	if (msg->url == NULL || msg->url->len == 0) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400, "missing command");
		return FALSE;
	}

	if (http_parser_parse_url(msg->url->str, msg->url->len, 0, &u) != 0) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400, "bad request URL");

		return FALSE;
	}

	if (!(u.field_set & (1 << UF_PATH))) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"bad request URL: missing path");

		return FALSE;
	}

	p = msg->url->str + u.field_data[UF_PATH].off;
	pathlen = u.field_data[UF_PATH].len;

	if (*p == '/') {
		p++;
		pathlen--;
	}

	switch (*p) {
	case 'c':
	case 'C':
		/* check */
		if (COMPARE_CMD(p, MSG_CMD_CHECK_V3, pathlen)) {
			task->cmd = CMD_CHECK_V3;
			task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_MULTIPART_V3;
			msg_debug_protocol("got checkv3 command");
		}
		else if (COMPARE_CMD(p, MSG_CMD_CHECK_V2, pathlen)) {
			task->cmd = CMD_CHECK_V2;
			msg_debug_protocol("got checkv2 command");
		}
		else if (COMPARE_CMD(p, MSG_CMD_CHECK, pathlen)) {
			task->cmd = CMD_CHECK;
			msg_debug_protocol("got check command");
		}
		else {
			goto err;
		}
		break;
	case 's':
	case 'S':
		/* symbols, skip */
		if (COMPARE_CMD(p, MSG_CMD_SYMBOLS, pathlen)) {
			task->cmd = CMD_CHECK;
			msg_debug_protocol("got symbols -> old check command");
		}
		else if (COMPARE_CMD(p, MSG_CMD_SCAN, pathlen)) {
			task->cmd = CMD_CHECK;
			msg_debug_protocol("got scan -> old check command");
		}
		else if (COMPARE_CMD(p, MSG_CMD_SKIP, pathlen)) {
			msg_debug_protocol("got skip command");
			task->cmd = CMD_SKIP;
		}
		else {
			goto err;
		}
		break;
	case 'p':
	case 'P':
		/* ping, process */
		if (COMPARE_CMD(p, MSG_CMD_PING, pathlen)) {
			msg_debug_protocol("got ping command");
			task->cmd = CMD_PING;
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
			task->processed_stages |= RSPAMD_TASK_STAGE_DONE; /* Skip all */
		}
		else if (COMPARE_CMD(p, MSG_CMD_PROCESS, pathlen)) {
			msg_debug_protocol("got process -> old check command");
			task->cmd = CMD_CHECK;
		}
		else {
			goto err;
		}
		break;
	case 'r':
	case 'R':
		/* report, report_ifspam */
		if (COMPARE_CMD(p, MSG_CMD_REPORT, pathlen)) {
			msg_debug_protocol("got report -> old check command");
			task->cmd = CMD_CHECK;
		}
		else if (COMPARE_CMD(p, MSG_CMD_REPORT_IFSPAM, pathlen)) {
			msg_debug_protocol("got reportifspam -> old check command");
			task->cmd = CMD_CHECK;
		}
		else {
			goto err;
		}
		break;
	case 'M':
	case 'm':
		/* metrics, process */
		if (COMPARE_CMD(p, MSG_CMD_METRICS, pathlen)) {
			msg_debug_protocol("got metrics command");
			task->cmd = CMD_METRICS;
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
			task->processed_stages |= RSPAMD_TASK_STAGE_DONE; /* Skip all */
		}
		else {
			goto err;
		}
		break;
	default:
		goto err;
	}

	if (u.field_set & (1u << UF_QUERY)) {
		/* In case if we have a query, we need to store it somewhere */
		query_args = rspamd_http_message_parse_query(msg);

		/* Insert the rest of query params as HTTP headers */
		g_hash_table_iter_init(&it, query_args);

		while (g_hash_table_iter_next(&it, &k, &v)) {
			char *key_cpy;
			key = k;
			value = v;

			key_cpy = rspamd_mempool_ftokdup(task->task_pool, key);

			rspamd_http_message_add_header_len(msg, key_cpy,
											   value->begin, value->len);
			msg_debug_protocol("added header \"%T\" -> \"%T\" from HTTP query",
							   key, value);
		}

		g_hash_table_unref(query_args);
	}

	return TRUE;

err:
	g_set_error(&task->err, rspamd_protocol_quark(), 400, "invalid command");

	return FALSE;
}

static void
rspamd_protocol_process_recipients(struct rspamd_task *task,
								   const rspamd_ftok_t *hdr)
{
	enum {
		skip_spaces,
		quoted_string,
		normal_string,
	} state = skip_spaces;
	const char *p, *end, *start_addr;
	struct rspamd_email_address *addr;

	p = hdr->begin;
	end = hdr->begin + hdr->len;
	start_addr = NULL;

	while (p < end) {
		switch (state) {
		case skip_spaces:
			if (g_ascii_isspace(*p)) {
				p++;
			}
			else if (*p == '"') {
				start_addr = p;
				p++;
				state = quoted_string;
			}
			else {
				state = normal_string;
				start_addr = p;
			}
			break;
		case quoted_string:
			if (*p == '"') {
				state = normal_string;
				p++;
			}
			else if (*p == '\\') {
				/* Quoted pair */
				p += 2;
			}
			else {
				p++;
			}
			break;
		case normal_string:
			if (*p == '"') {
				state = quoted_string;
				p++;
			}
			else if (*p == ',' && start_addr != NULL && p > start_addr) {
				/* We have finished address, check what we have */
				addr = rspamd_email_address_from_smtp(start_addr,
													  p - start_addr);

				if (addr) {
					if (task->rcpt_envelope == NULL) {
						task->rcpt_envelope = g_ptr_array_sized_new(
							2);
					}

					g_ptr_array_add(task->rcpt_envelope, addr);
				}
				else {
					msg_err_protocol("bad rcpt address: '%*s'",
									 (int) (p - start_addr), start_addr);
					task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
				}
				start_addr = NULL;
				p++;
				state = skip_spaces;
			}
			else {
				p++;
			}
			break;
		}
	}

	/* Check remainder */
	if (start_addr && p > start_addr) {
		switch (state) {
		case normal_string:
			addr = rspamd_email_address_from_smtp(start_addr, end - start_addr);

			if (addr) {
				if (task->rcpt_envelope == NULL) {
					task->rcpt_envelope = g_ptr_array_sized_new(
						2);
				}

				g_ptr_array_add(task->rcpt_envelope, addr);
			}
			else {
				msg_err_protocol("bad rcpt address: '%*s'",
								 (int) (end - start_addr), start_addr);
				task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
			}
			break;
		case skip_spaces:
			/* Do nothing */
			break;
		case quoted_string:
		default:
			msg_err_protocol("bad state when parsing rcpt address: '%*s'",
							 (int) (end - start_addr), start_addr);
			task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
		}
	}
}

#define COMPARE_FLAG_LIT(lit) (len == sizeof(lit) - 1 && memcmp((lit), str, len) == 0)
#define CHECK_PROTOCOL_FLAG(lit, fl)                         \
	do {                                                     \
		if (!known && COMPARE_FLAG_LIT(lit)) {               \
			task->protocol_flags |= (fl);                    \
			known = TRUE;                                    \
			msg_debug_protocol("add protocol flag %s", lit); \
		}                                                    \
	} while (0)
#define CHECK_TASK_FLAG(lit, fl)                         \
	do {                                                 \
		if (!known && COMPARE_FLAG_LIT(lit)) {           \
			task->flags |= (fl);                         \
			known = TRUE;                                \
			msg_debug_protocol("add task flag %s", lit); \
		}                                                \
	} while (0)

static void
rspamd_protocol_handle_flag(struct rspamd_task *task, const char *str,
							gsize len)
{
	gboolean known = FALSE;

	CHECK_TASK_FLAG("pass_all", RSPAMD_TASK_FLAG_PASS_ALL);
	CHECK_TASK_FLAG("no_log", RSPAMD_TASK_FLAG_NO_LOG);
	CHECK_TASK_FLAG("skip", RSPAMD_TASK_FLAG_SKIP);
	CHECK_TASK_FLAG("skip_process", RSPAMD_TASK_FLAG_SKIP_PROCESS);
	CHECK_TASK_FLAG("no_stat", RSPAMD_TASK_FLAG_NO_STAT);
	CHECK_TASK_FLAG("ssl", RSPAMD_TASK_FLAG_SSL);
	CHECK_TASK_FLAG("profile", RSPAMD_TASK_FLAG_PROFILE);

	CHECK_PROTOCOL_FLAG("milter", RSPAMD_TASK_PROTOCOL_FLAG_MILTER);
	CHECK_PROTOCOL_FLAG("zstd", RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED);
	CHECK_PROTOCOL_FLAG("ext_urls", RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS);
	CHECK_PROTOCOL_FLAG("body_block", RSPAMD_TASK_PROTOCOL_FLAG_BODY_BLOCK);
	CHECK_PROTOCOL_FLAG("groups", RSPAMD_TASK_PROTOCOL_FLAG_GROUPS);

	if (!known) {
		msg_warn_protocol("unknown flag: %*s", (int) len, str);
	}
}

#undef COMPARE_FLAG
#undef CHECK_PROTOCOL_FLAG

static void
rspamd_protocol_process_flags(struct rspamd_task *task, const rspamd_ftok_t *hdr)
{
	enum {
		skip_spaces,
		read_flag,
	} state = skip_spaces;
	const char *p, *end, *start;

	p = hdr->begin;
	end = hdr->begin + hdr->len;
	start = NULL;

	while (p < end) {
		switch (state) {
		case skip_spaces:
			if (g_ascii_isspace(*p)) {
				p++;
			}
			else {
				state = read_flag;
				start = p;
			}
			break;
		case read_flag:
			if (*p == ',') {
				if (p > start) {
					rspamd_protocol_handle_flag(task, start, p - start);
				}
				start = NULL;
				state = skip_spaces;
				p++;
			}
			else {
				p++;
			}
			break;
		}
	}

	/* Check remainder */
	if (start && end > start && state == read_flag) {
		rspamd_protocol_handle_flag(task, start, end - start);
	}
}

/*
 * Shared helpers for populating task fields from both v2 (HTTP headers) and
 * v3 (UCL metadata) request formats.
 */

static void
rspamd_protocol_set_from_envelope(struct rspamd_task *task,
								  const char *from_str, gsize from_len)
{
	if (from_len == 0) {
		from_str = "<>";
		from_len = 2;
	}

	task->from_envelope = rspamd_email_address_from_smtp(from_str, from_len);

	if (!task->from_envelope) {
		msg_err_protocol("bad from value: '%*s'", (int) from_len, from_str);
		task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
	}
}

static void
rspamd_protocol_set_ip(struct rspamd_task *task,
					   const char *ip_str, gsize ip_len,
					   gboolean *has_ip)
{
	if (!rspamd_parse_inet_address(&task->from_addr,
								   ip_str, ip_len,
								   RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
		msg_err_protocol("bad ip value: '%*s'", (int) ip_len, ip_str);
	}
	else {
		msg_debug_protocol("read IP value: %*s", (int) ip_len, ip_str);
		*has_ip = TRUE;
	}
}

static void
rspamd_protocol_set_settings_id(struct rspamd_task *task,
								const char *id_str, gsize id_len)
{
	task->settings_elt = rspamd_config_find_settings_name_ref(
		task->cfg, id_str, id_len);

	if (!task->settings_elt) {
		msg_warn_protocol("unknown settings id: '%*s'", (int) id_len, id_str);
	}
}

static void
rspamd_protocol_set_log_tag(struct rspamd_task *task,
							const char *tag, gsize tag_len)
{
	if (rspamd_fast_utf8_validate(tag, tag_len) == 0) {
		int len = MIN(tag_len, sizeof(task->task_pool->tag.uid) - 1);
		memcpy(task->task_pool->tag.uid, tag, len);
		task->task_pool->tag.uid[len] = '\0';
		/* Keep UUID random portion in sync with the new log tag */
		rspamd_uuid_v7_patch_uid(task->task_uuid, tag, tag_len);
	}
}

static void
rspamd_protocol_add_mail_esmtp_arg(struct rspamd_task *task,
								   const char *key, gsize key_len,
								   const char *val, gsize val_len)
{
	if (!task->mail_esmtp_args) {
		task->mail_esmtp_args = g_hash_table_new_full(
			rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal,
			rspamd_fstring_mapped_ftok_free,
			rspamd_fstring_mapped_ftok_free);
	}

	rspamd_fstring_t *fkey = rspamd_fstring_new_init(key, key_len);
	rspamd_fstring_t *fval = rspamd_fstring_new_init(val, val_len);
	rspamd_ftok_t *key_tok = rspamd_ftok_map(fkey);
	rspamd_ftok_t *val_tok = rspamd_ftok_map(fval);

	g_hash_table_replace(task->mail_esmtp_args, key_tok, val_tok);
}

static void
rspamd_protocol_add_rcpt_esmtp_arg(struct rspamd_task *task,
								   int rcpt_idx,
								   const char *key, gsize key_len,
								   const char *val, gsize val_len)
{
	if (!task->rcpt_esmtp_args) {
		task->rcpt_esmtp_args = g_ptr_array_new();
	}

	while ((int) task->rcpt_esmtp_args->len <= rcpt_idx) {
		g_ptr_array_add(task->rcpt_esmtp_args, NULL);
	}

	GHashTable *rcpt_args = g_ptr_array_index(task->rcpt_esmtp_args, rcpt_idx);
	if (!rcpt_args) {
		rcpt_args = g_hash_table_new_full(
			rspamd_ftok_icase_hash,
			rspamd_ftok_icase_equal,
			rspamd_fstring_mapped_ftok_free,
			rspamd_fstring_mapped_ftok_free);
		g_ptr_array_index(task->rcpt_esmtp_args, rcpt_idx) = rcpt_args;
	}

	rspamd_fstring_t *fkey = rspamd_fstring_new_init(key, key_len);
	rspamd_fstring_t *fval = rspamd_fstring_new_init(val, val_len);
	rspamd_ftok_t *key_tok = rspamd_ftok_map(fkey);
	rspamd_ftok_t *val_tok = rspamd_ftok_map(fval);

	g_hash_table_replace(rcpt_args, key_tok, val_tok);
}

#define IF_HEADER(name)          \
	srch.begin = (name);         \
	srch.len = sizeof(name) - 1; \
	if (rspamd_ftok_casecmp(hn_tok, &srch) == 0)

gboolean
rspamd_protocol_handle_headers(struct rspamd_task *task,
							   struct rspamd_http_message *msg)
{
	rspamd_ftok_t *hn_tok, *hv_tok, srch;
	gboolean has_ip = FALSE, seen_settings_header = FALSE;
	struct rspamd_http_header *header, *h;
	char *ntok;

	kh_foreach_value (msg->headers, header, {
		DL_FOREACH (header, h) {
			ntok = rspamd_mempool_ftokdup (task->task_pool, &h->name);
			hn_tok = rspamd_mempool_alloc (task->task_pool, sizeof (*hn_tok));
			hn_tok->begin = ntok;
			hn_tok->len = h->name.len;


			ntok = rspamd_mempool_ftokdup (task->task_pool, &h->value);
			hv_tok = rspamd_mempool_alloc (task->task_pool, sizeof (*hv_tok));
			hv_tok->begin = ntok;
			hv_tok->len = h->value.len;

			switch (*hn_tok->begin) {
		case 'd':
		case 'D':
			IF_HEADER(DELIVER_TO_HEADER)
			{
				task->deliver_to = rspamd_protocol_escape_braces(task, hv_tok);
				msg_debug_protocol("read deliver-to header, value: %s",
								   task->deliver_to);
			}
			else
			{
				msg_debug_protocol("wrong header: %T", hn_tok);
			}
			break;
		case 'h':
		case 'H':
			IF_HEADER(HELO_HEADER)
			{
				task->helo = rspamd_mempool_ftokdup(task->task_pool, hv_tok);
				msg_debug_protocol("read helo header, value: %s", task->helo);
			}
			IF_HEADER(HOSTNAME_HEADER)
			{
				task->hostname = rspamd_mempool_ftokdup(task->task_pool,
														hv_tok);
				msg_debug_protocol("read hostname header, value: %s", task->hostname);
			}
			break;
		case 'f':
		case 'F':
			IF_HEADER(FROM_HEADER)
			{
				msg_debug_protocol("read from header, value: %T", hv_tok);
				rspamd_protocol_set_from_envelope(task, hv_tok->begin, hv_tok->len);
			}
			IF_HEADER(FILENAME_HEADER)
			{
				task->msg.fpath = rspamd_mempool_ftokdup(task->task_pool,
														 hv_tok);
				msg_debug_protocol("read filename header, value: %s", task->msg.fpath);
			}
			IF_HEADER(FLAGS_HEADER)
			{
				msg_debug_protocol("read flags header, value: %T", hv_tok);
				rspamd_protocol_process_flags(task, hv_tok);
			}
			break;
		case 'q':
		case 'Q':
			IF_HEADER(QUEUE_ID_HEADER)
			{
				task->queue_id = rspamd_mempool_ftokdup(task->task_pool,
														hv_tok);
				msg_debug_protocol("read queue_id header, value: %s", task->queue_id);
			}
			else
			{
				msg_debug_protocol("wrong header: %T", hn_tok);
			}
			break;
		case 'r':
		case 'R':
			IF_HEADER(RCPT_HEADER)
			{
				rspamd_protocol_process_recipients(task, hv_tok);
				msg_debug_protocol("read rcpt header, value: %T", hv_tok);
			}
			IF_HEADER(RAW_DATA_HEADER)
			{
				srch.begin = "yes";
				srch.len = 3;

				msg_debug_protocol("read raw data header, value: %T", hv_tok);

				if (rspamd_ftok_casecmp(hv_tok, &srch) == 0) {
					task->flags &= ~RSPAMD_TASK_FLAG_MIME;
					msg_debug_protocol("disable mime parsing");
				}
			}
			break;
		case 'i':
		case 'I':
			IF_HEADER(IP_ADDR_HEADER)
			{
				rspamd_protocol_set_ip(task, hv_tok->begin, hv_tok->len, &has_ip);
			}
			else
			{
				msg_debug_protocol("wrong header: %T", hn_tok);
			}
			break;
		case 'p':
		case 'P':
			IF_HEADER(PASS_HEADER)
			{
				srch.begin = "all";
				srch.len = 3;

				msg_debug_protocol("read pass header, value: %T", hv_tok);

				if (rspamd_ftok_casecmp(hv_tok, &srch) == 0) {
					task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
					msg_debug_protocol("pass all filters");
				}
			}
			IF_HEADER(PROFILE_HEADER)
			{
				msg_debug_protocol("read profile header, value: %T", hv_tok);
				task->flags |= RSPAMD_TASK_FLAG_PROFILE;
			}
			break;
		case 's':
		case 'S':
			IF_HEADER(SETTINGS_ID_HEADER)
			{
				msg_debug_protocol("read settings-id header, value: %T", hv_tok);
				rspamd_protocol_set_settings_id(task, hv_tok->begin, hv_tok->len);

				if (task->settings_elt == NULL) {
					GString *known_ids = g_string_new(NULL);
					struct rspamd_config_settings_elt *cur;

					DL_FOREACH(task->cfg->setting_ids, cur)
					{
						rspamd_printf_gstring(known_ids, "%s(%ud);",
											  cur->name, cur->id);
					}

					msg_warn_protocol("settings id %T(%d) not found; known_ids: %v",
									  hv_tok,
									  rspamd_config_name_to_id(hv_tok->begin, hv_tok->len),
									  known_ids);

					g_string_free(known_ids, TRUE);
				}
				else {
					msg_debug_protocol("applied settings id %T -> %ud", hv_tok,
									   task->settings_elt->id);
				}
			}
			IF_HEADER(SETTINGS_HEADER)
			{
				msg_debug_protocol("read settings header, value: %T", hv_tok);
				seen_settings_header = TRUE;
			}
			break;
		case 'u':
		case 'U':
			IF_HEADER(USER_HEADER)
			{
				/*
								 * We must ignore User header in case of spamc, as SA has
								 * different meaning of this header
								 */
				msg_debug_protocol("read user header, value: %T", hv_tok);
				if (!RSPAMD_TASK_IS_SPAMC(task)) {
					task->auth_user = rspamd_mempool_ftokdup(task->task_pool,
															 hv_tok);
				}
				else {
					msg_info_protocol("ignore user header: legacy SA protocol");
				}
			}
			IF_HEADER(URLS_HEADER)
			{
				msg_debug_protocol("read urls header, value: %T", hv_tok);

				srch.begin = "extended";
				srch.len = 8;

				if (rspamd_ftok_casecmp(hv_tok, &srch) == 0) {
					task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS;
					msg_debug_protocol("extended urls information");
				}

				/* TODO: add more formats there */
			}
			IF_HEADER(USER_AGENT_HEADER)
			{
				msg_debug_protocol("read user-agent header, value: %T", hv_tok);

				if (hv_tok->len == 6 &&
					rspamd_lc_cmp(hv_tok->begin, "rspamc", 6) == 0) {
					task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_LOCAL_CLIENT;
				}
			}
			break;
		case 'l':
		case 'L':
			IF_HEADER(NO_LOG_HEADER)
			{
				msg_debug_protocol("read log header, value: %T", hv_tok);
				srch.begin = "no";
				srch.len = 2;

				if (rspamd_ftok_casecmp(hv_tok, &srch) == 0) {
					task->flags |= RSPAMD_TASK_FLAG_NO_LOG;
				}
			}
			IF_HEADER(LOG_TAG_HEADER)
			{
				msg_debug_protocol("read log-tag header, value: %T", hv_tok);
				rspamd_protocol_set_log_tag(task, hv_tok->begin, hv_tok->len);
			}
			break;
		case 'm':
		case 'M':
			IF_HEADER(MTA_TAG_HEADER)
			{
				char *mta_tag;
				mta_tag = rspamd_mempool_ftokdup(task->task_pool, hv_tok);
				rspamd_mempool_set_variable(task->task_pool,
											RSPAMD_MEMPOOL_MTA_TAG,
											mta_tag, NULL);
				msg_debug_protocol("read MTA-Tag header, value: %s", mta_tag);
			}
			IF_HEADER(MTA_NAME_HEADER)
			{
				char *mta_name;
				mta_name = rspamd_mempool_ftokdup(task->task_pool, hv_tok);
				rspamd_mempool_set_variable(task->task_pool,
											RSPAMD_MEMPOOL_MTA_NAME,
											mta_name, NULL);
				msg_debug_protocol("read MTA-Name header, value: %s", mta_name);
			}
			IF_HEADER(MILTER_HEADER)
			{
				task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_MILTER;
				msg_debug_protocol("read Milter header, value: %T", hv_tok);
			}
			break;
		case 't':
		case 'T':
			IF_HEADER(TLS_CIPHER_HEADER)
			{
				task->flags |= RSPAMD_TASK_FLAG_SSL;
				msg_debug_protocol("read TLS cipher header, value: %T", hv_tok);
			}
			break;
		case 'x':
		case 'X':
			IF_HEADER("X-Rspamd-Mail-Esmtp-Args")
			{
				/* Parse KEY=VALUE format */
				const char *eq = memchr(hv_tok->begin, '=', hv_tok->len);

				if (eq && eq > hv_tok->begin) {
					rspamd_protocol_add_mail_esmtp_arg(task,
													   hv_tok->begin, eq - hv_tok->begin,
													   eq + 1, hv_tok->begin + hv_tok->len - eq - 1);
					msg_debug_protocol("parsed mail ESMTP arg from header");
				}
			}
			IF_HEADER("X-Rspamd-Rcpt-Esmtp-Args")
			{
				/* Parse IDX:KEY=VALUE format */
				const char *p = hv_tok->begin;
				const char *end = hv_tok->begin + hv_tok->len;
				const char *colon = memchr(p, ':', hv_tok->len);

				if (colon && colon > p) {
					char *endptr;
					int rcpt_idx = strtol(p, &endptr, 10);

					if (endptr == colon) {
						/* Parse KEY=VALUE */
						p = colon + 1;
						const char *eq = memchr(p, '=', end - p);

						if (eq && eq > p) {
							rspamd_protocol_add_rcpt_esmtp_arg(task, rcpt_idx,
															   p, eq - p,
															   eq + 1, end - eq - 1);
							msg_debug_protocol("parsed rcpt ESMTP arg for idx %d", rcpt_idx);
						}
					}
				}
			}
			break;
		default:
			msg_debug_protocol("generic header: %T", hn_tok);
			break;
				}

				rspamd_task_add_request_header (task, hn_tok, hv_tok);
}
}); /* End of kh_foreach_value */

if (seen_settings_header && task->settings_elt) {
	msg_warn_task("ignore settings id %s as settings header is also presented",
				  task->settings_elt->name);
	REF_RELEASE(task->settings_elt);

	task->settings_elt = NULL;
}

if (!has_ip) {
	task->flags |= RSPAMD_TASK_FLAG_NO_IP;
}

return TRUE;
}

gboolean
rspamd_protocol_handle_request(struct rspamd_task *task,
							   struct rspamd_http_message *msg)
{
	gboolean ret = TRUE;

	if (msg->method == HTTP_SYMBOLS) {
		msg_debug_protocol("got legacy SYMBOLS method, enable rspamc protocol workaround");
		task->cmd = CMD_CHECK_RSPAMC;
	}
	else if (msg->method == HTTP_CHECK) {
		msg_debug_protocol("got legacy CHECK method, enable rspamc protocol workaround");
		task->cmd = CMD_CHECK_RSPAMC;
	}
	else {
		ret = rspamd_protocol_handle_url(task, msg);
	}

	if (msg->flags & RSPAMD_HTTP_FLAG_SPAMC) {
		msg_debug_protocol("got legacy SA input, enable spamc protocol workaround");
		task->cmd = CMD_CHECK_SPAMC;
	}

	return ret;
}

/* Structure for writing tree data */
struct tree_cb_data {
	ucl_object_t *top;
	khash_t(rspamd_url_host_hash) * seen;
	struct rspamd_task *task;
};

static ucl_object_t *
rspamd_protocol_extended_url(struct rspamd_task *task,
							 struct rspamd_url *url,
							 const char *encoded, gsize enclen)
{
	ucl_object_t *obj, *elt;

	obj = ucl_object_typed_new(UCL_OBJECT);

	elt = ucl_object_fromstring_common(encoded, enclen, 0);
	ucl_object_insert_key(obj, elt, "url", 0, false);

	if (url->tldlen > 0) {
		elt = ucl_object_fromstring_common(rspamd_url_tld_unsafe(url),
										   url->tldlen, 0);
		ucl_object_insert_key(obj, elt, "tld", 0, false);
	}
	if (url->hostlen > 0) {
		elt = ucl_object_fromstring_common(rspamd_url_host_unsafe(url),
										   url->hostlen, 0);
		ucl_object_insert_key(obj, elt, "host", 0, false);
	}

	ucl_object_t *flags = ucl_object_typed_new(UCL_ARRAY);

	for (unsigned int i = 0; i < RSPAMD_URL_MAX_FLAG_SHIFT; i++) {
		if (url->flags & (1u << i)) {
			ucl_object_t *fl = ucl_object_fromstring(rspamd_url_flag_to_string(1u << i));
			ucl_array_append(flags, fl);
		}
	}

	ucl_object_insert_key(obj, flags, "flags", 0, false);

	if (url->ext && url->ext->linked_url) {
		encoded = rspamd_url_encode(url->ext->linked_url, &enclen, task->task_pool);
		elt = rspamd_protocol_extended_url(task, url->ext->linked_url, encoded,
										   enclen);
		ucl_object_insert_key(obj, elt, "linked_url", 0, false);
	}

	return obj;
}

/*
 * Callback for writing urls
 */
static void
urls_protocol_cb(struct rspamd_url *url, struct tree_cb_data *cb)
{
	ucl_object_t *obj;
	struct rspamd_task *task = cb->task;
	const char *user_field = "unknown", *encoded = NULL;
	gboolean has_user = FALSE;
	unsigned int len = 0;
	gsize enclen = 0;

	if (!(task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS)) {
		if (url->hostlen > 0) {
			if (rspamd_url_host_set_has(cb->seen, url)) {
				return;
			}

			goffset err_offset;

			if ((err_offset = rspamd_fast_utf8_validate(rspamd_url_host_unsafe(url),
														url->hostlen)) == 0) {
				obj = ucl_object_fromstring_common(rspamd_url_host_unsafe(url),
												   url->hostlen, 0);
			}
			else {
				obj = ucl_object_fromstring_common(rspamd_url_host_unsafe(url),
												   err_offset - 1, 0);
			}
		}
		else {
			return;
		}

		rspamd_url_host_set_add(cb->seen, url);
	}
	else {
		encoded = rspamd_url_encode(url, &enclen, task->task_pool);
		obj = rspamd_protocol_extended_url(task, url, encoded, enclen);
	}

	ucl_array_append(cb->top, obj);

	if (cb->task->cfg->log_urls) {
		if (task->auth_user) {
			user_field = task->auth_user;
			len = strlen(task->auth_user);
			has_user = TRUE;
		}
		else if (task->from_envelope) {
			user_field = task->from_envelope->addr;
			len = task->from_envelope->addr_len;
		}

		if (!encoded) {
			encoded = rspamd_url_encode(url, &enclen, task->task_pool);
		}

		msg_notice_task_encrypted("<%s> %s: %*s; ip: %s; URL: %*s",
								  MESSAGE_FIELD_CHECK(task, message_id),
								  has_user ? "user" : "from",
								  len, user_field,
								  rspamd_inet_address_to_string(task->from_addr),
								  (int) enclen, encoded);
	}
}

static ucl_object_t *
rspamd_urls_tree_ucl(khash_t(rspamd_url_hash) * set,
					 struct rspamd_task *task)
{
	struct tree_cb_data cb;
	ucl_object_t *obj;
	struct rspamd_url *u;

	obj = ucl_object_typed_new(UCL_ARRAY);
	cb.top = obj;
	cb.task = task;
	cb.seen = kh_init(rspamd_url_host_hash);

	kh_foreach_key(set, u, {
		if (!(u->protocol & PROTOCOL_MAILTO)) {
			urls_protocol_cb(u, &cb);
		}
	});

	kh_destroy(rspamd_url_host_hash, cb.seen);

	return obj;
}

static void
emails_protocol_cb(struct rspamd_url *url, struct tree_cb_data *cb)
{
	ucl_object_t *obj;

	if (url->userlen > 0 && url->hostlen > 0) {
		obj = ucl_object_fromlstring(rspamd_url_user_unsafe(url),
									 url->userlen + url->hostlen + 1);
		ucl_array_append(cb->top, obj);
	}
}

static ucl_object_t *
rspamd_emails_tree_ucl(khash_t(rspamd_url_hash) * set,
					   struct rspamd_task *task)
{
	struct tree_cb_data cb;
	ucl_object_t *obj;
	struct rspamd_url *u;

	obj = ucl_object_typed_new(UCL_ARRAY);
	cb.top = obj;
	cb.task = task;

	kh_foreach_key(set, u, {
		if ((u->protocol & PROTOCOL_MAILTO)) {
			emails_protocol_cb(u, &cb);
		}
	});


	return obj;
}


/* Write new subject */
static const char *
rspamd_protocol_rewrite_subject(struct rspamd_task *task)
{
	GString *subj_buf;
	char *res;
	const char *s, *c, *p;
	gsize slen = 0;

	c = rspamd_mempool_get_variable(task->task_pool, "metric_subject");

	if (c == NULL) {
		c = task->cfg->subject;
	}

	if (c == NULL) {
		c = SPAM_SUBJECT;
	}

	p = c;
	s = MESSAGE_FIELD_CHECK(task, subject);

	if (s) {
		slen = strlen(s);
	}

	subj_buf = g_string_sized_new(strlen(c) + slen);

	while (*p) {
		if (*p == '%') {
			switch (p[1]) {
			case 's':
				g_string_append_len(subj_buf, c, p - c);

				if (s) {
					g_string_append_len(subj_buf, s, slen);
				}
				c = p + 2;
				p += 2;
				break;
			case 'd':
				g_string_append_len(subj_buf, c, p - c);
				rspamd_printf_gstring(subj_buf, "%.2f", task->result->score);
				c = p + 2;
				p += 2;
				break;
			case '%':
				g_string_append_len(subj_buf, c, p - c);
				g_string_append_c(subj_buf, '%');
				c = p + 2;
				p += 2;
				break;
			default:
				p++; /* Just % something unknown */
				break;
			}
		}
		else {
			p++;
		}
	}

	if (p > c) {
		g_string_append_len(subj_buf, c, p - c);
	}

	res = rspamd_mime_header_encode(subj_buf->str, subj_buf->len, false);

	rspamd_mempool_add_destructor(task->task_pool,
								  (rspamd_mempool_destruct_t) g_free,
								  res);
	g_string_free(subj_buf, TRUE);

	return res;
}

static ucl_object_t *
rspamd_metric_symbol_ucl(struct rspamd_task *task, struct rspamd_symbol_result *sym)
{
	ucl_object_t *obj = NULL, *ar;
	const char *description = NULL;
	struct rspamd_symbol_option *opt;

	if (sym->sym != NULL) {
		description = sym->sym->description;
	}

	obj = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(obj, ucl_object_fromstring(sym->name), "name", 0, false);
	ucl_object_insert_key(obj, ucl_object_fromdouble(sym->score), "score", 0, false);

	if (task->cmd == CMD_CHECK_V2 || task->cmd == CMD_CHECK_V3) {
		if (sym->sym) {
			ucl_object_insert_key(obj, ucl_object_fromdouble(sym->sym->score), "metric_score", 0, false);
		}
		else {
			ucl_object_insert_key(obj, ucl_object_fromdouble(0.0),
								  "metric_score", 0, false);
		}
	}

	if (description) {
		ucl_object_insert_key(obj, ucl_object_fromstring(description),
							  "description", 0, false);
	}

	if (sym->options != NULL) {
		ar = ucl_object_typed_new(UCL_ARRAY);

		DL_FOREACH(sym->opts_head, opt)
		{
			ucl_array_append(ar, ucl_object_fromstring_common(opt->option,
															  opt->optlen, 0));
		}

		ucl_object_insert_key(obj, ar, "options", 0, false);
	}

	return obj;
}

static ucl_object_t *
rspamd_metric_group_ucl(struct rspamd_task *task,
						struct rspamd_symbols_group *gr, double score)
{
	ucl_object_t *obj = NULL;

	obj = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(obj, ucl_object_fromdouble(score),
						  "score", 0, false);

	if (gr->description) {
		ucl_object_insert_key(obj, ucl_object_fromstring(gr->description),
							  "description", 0, false);
	}

	return obj;
}

static ucl_object_t *
rspamd_scan_result_ucl(struct rspamd_task *task,
					   struct rspamd_scan_result *mres, ucl_object_t *top)
{
	struct rspamd_symbol_result *sym;
	gboolean is_spam;
	struct rspamd_action *action;
	ucl_object_t *obj = NULL, *sobj;
	const char *subject;
	struct rspamd_passthrough_result *pr = NULL;

	action = rspamd_check_action_metric(task, &pr, NULL);
	is_spam = !(action->flags & RSPAMD_ACTION_HAM);

	if (task->cmd == CMD_CHECK) {
		obj = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(obj,
							  ucl_object_frombool(is_spam),
							  "is_spam", 0, false);
	}
	else {
		obj = top;
	}

	if (pr) {
		if (pr->message && !(pr->flags & RSPAMD_PASSTHROUGH_NO_SMTP_MESSAGE)) {
			/* Add smtp message if it does not exist: see #3269 for details */
			if (ucl_object_lookup(task->messages, "smtp_message") == NULL) {
				ucl_object_insert_key(task->messages,
									  ucl_object_fromstring_common(pr->message, 0, UCL_STRING_RAW),
									  "smtp_message", 0,
									  false);
			}
		}

		ucl_object_insert_key(obj,
							  ucl_object_fromstring(pr->module),
							  "passthrough_module", 0, false);
	}

	ucl_object_insert_key(obj,
						  ucl_object_frombool(RSPAMD_TASK_IS_SKIPPED(task)),
						  "is_skipped", 0, false);

	if (!isnan(mres->score)) {
		ucl_object_insert_key(obj, ucl_object_fromdouble(mres->score),
							  "score", 0, false);
	}
	else {
		ucl_object_insert_key(obj,
							  ucl_object_fromdouble(0.0), "score", 0, false);
	}

	ucl_object_insert_key(obj,
						  ucl_object_fromdouble(rspamd_task_get_required_score(task, mres)),
						  "required_score", 0, false);
	ucl_object_insert_key(obj,
						  ucl_object_fromstring(action->name),
						  "action", 0, false);

	if (action->action_type == METRIC_ACTION_REWRITE_SUBJECT) {
		subject = rspamd_protocol_rewrite_subject(task);

		if (subject) {
			ucl_object_insert_key(obj, ucl_object_fromstring(subject),
								  "subject", 0, false);
		}
	}
	if (action->flags & RSPAMD_ACTION_MILTER) {
		/* Treat milter action specially */
		if (action->action_type == METRIC_ACTION_DISCARD) {
			ucl_object_insert_key(obj, ucl_object_fromstring("discard"),
								  "reject", 0, false);
		}
		else if (action->action_type == METRIC_ACTION_QUARANTINE) {
			ucl_object_insert_key(obj, ucl_object_fromstring("quarantine"),
								  "reject", 0, false);
		}
	}

	/* Now handle symbols */
	if (task->cmd != CMD_CHECK) {
		/* Insert actions thresholds */
		ucl_object_t *actions_obj = ucl_object_typed_new(UCL_OBJECT);

		for (int i = task->result->nactions - 1; i >= 0; i--) {
			struct rspamd_action_config *action_lim = &task->result->actions_config[i];

			if (!isnan(action_lim->cur_limit) &&
				!(action_lim->action->flags & (RSPAMD_ACTION_NO_THRESHOLD | RSPAMD_ACTION_HAM))) {
				ucl_object_insert_key(actions_obj, ucl_object_fromdouble(action_lim->cur_limit),
									  action_lim->action->name, 0, true);
			}
		}

		ucl_object_insert_key(obj, actions_obj, "thresholds", 0, false);

		/* For checkv2 we insert symbols as a separate object */
		obj = ucl_object_typed_new(UCL_OBJECT);
	}

	kh_foreach_value(mres->symbols, sym, {
		if (!(sym->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
			sobj = rspamd_metric_symbol_ucl(task, sym);
			ucl_object_insert_key(obj, sobj, sym->name, 0, false);
		}
	});

	if (task->cmd != CMD_CHECK) {
		/* For checkv2 we insert symbols as a separate object */
		ucl_object_insert_key(top, obj, "symbols", 0, false);
	}
	else {
		/* For legacy check we just insert it as "default" all together */
		ucl_object_insert_key(top, obj, DEFAULT_METRIC, 0, false);
	}

	/* Handle groups if needed */
	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_GROUPS) {
		struct rspamd_symbols_group *gr;
		double gr_score;

		obj = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_reserve(obj, kh_size(mres->sym_groups));

		kh_foreach(mres->sym_groups, gr, gr_score, {
			if (task->cfg->public_groups_only &&
				!(gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)) {
				continue;
			}
			sobj = rspamd_metric_group_ucl(task, gr, gr_score);
			ucl_object_insert_key(obj, sobj, gr->name, 0, false);
		});

		ucl_object_insert_key(top, obj, "groups", 0, false);
	}

	return obj;
}

void rspamd_ucl_torspamc_output(const ucl_object_t *top,
								rspamd_fstring_t **out)
{
	const ucl_object_t *symbols, *score,
		*required_score, *is_spam, *elt, *cur;
	ucl_object_iter_t iter = NULL;

	score = ucl_object_lookup(top, "score");
	required_score = ucl_object_lookup(top, "required_score");
	is_spam = ucl_object_lookup(top, "is_spam");
	rspamd_printf_fstring(out,
						  "Metric: default; %s; %.2f / %.2f / 0.0\r\n",
						  ucl_object_toboolean(is_spam) ? "True" : "False",
						  ucl_object_todouble(score),
						  ucl_object_todouble(required_score));
	elt = ucl_object_lookup(top, "action");
	if (elt != NULL) {
		rspamd_printf_fstring(out, "Action: %s\r\n",
							  ucl_object_tostring(elt));
	}

	elt = ucl_object_lookup(top, "subject");
	if (elt != NULL) {
		rspamd_printf_fstring(out, "Subject: %s\r\n",
							  ucl_object_tostring(elt));
	}

	symbols = ucl_object_lookup(top, "symbols");

	if (symbols != NULL) {
		iter = NULL;
		while ((elt = ucl_object_iterate(symbols, &iter, true)) != NULL) {
			if (elt->type == UCL_OBJECT) {
				const ucl_object_t *sym_score;
				sym_score = ucl_object_lookup(elt, "score");
				rspamd_printf_fstring(out, "Symbol: %s(%.2f)\r\n",
									  ucl_object_key(elt),
									  ucl_object_todouble(sym_score));
			}
		}
	}

	elt = ucl_object_lookup(top, "messages");
	if (elt != NULL) {
		iter = NULL;
		while ((cur = ucl_object_iterate(elt, &iter, true)) != NULL) {
			if (cur->type == UCL_STRING) {
				rspamd_printf_fstring(out, "Message: %s\r\n",
									  ucl_object_tostring(cur));
			}
		}
	}

	elt = ucl_object_lookup(top, "message-id");
	if (elt != NULL) {
		rspamd_printf_fstring(out, "Message-ID: %s\r\n",
							  ucl_object_tostring(elt));
	}
}

void rspamd_ucl_tospamc_output(const ucl_object_t *top,
							   rspamd_fstring_t **out)
{
	const ucl_object_t *symbols, *score,
		*required_score, *is_spam, *elt;
	ucl_object_iter_t iter = NULL;
	rspamd_fstring_t *f;

	score = ucl_object_lookup(top, "score");
	required_score = ucl_object_lookup(top, "required_score");
	is_spam = ucl_object_lookup(top, "is_spam");
	rspamd_printf_fstring(out,
						  "Spam: %s ; %.2f / %.2f\r\n\r\n",
						  ucl_object_toboolean(is_spam) ? "True" : "False",
						  ucl_object_todouble(score),
						  ucl_object_todouble(required_score));

	symbols = ucl_object_lookup(top, "symbols");

	if (symbols != NULL) {
		while ((elt = ucl_object_iterate(symbols, &iter, true)) != NULL) {
			if (elt->type == UCL_OBJECT) {
				rspamd_printf_fstring(out, "%s,",
									  ucl_object_key(elt));
			}
		}
		/* Ugly hack, but the whole spamc is ugly */
		f = *out;
		if (f->str[f->len - 1] == ',') {
			f->len--;

			*out = rspamd_fstring_append(*out, CRLF, 2);
		}
	}
}

static void
rspamd_protocol_output_profiling(struct rspamd_task *task,
								 ucl_object_t *top)
{
	GHashTable *tbl;
	GHashTableIter it;
	gpointer k, v;
	ucl_object_t *prof;
	double val;

	prof = ucl_object_typed_new(UCL_OBJECT);
	tbl = rspamd_mempool_get_variable(task->task_pool, "profile");

	if (tbl) {
		g_hash_table_iter_init(&it, tbl);

		while (g_hash_table_iter_next(&it, &k, &v)) {
			val = *(double *) v;
			ucl_object_insert_key(prof, ucl_object_fromdouble(val),
								  (const char *) k, 0, false);
		}
	}

	ucl_object_insert_key(top, prof, "profile", 0, false);
}

ucl_object_t *
rspamd_protocol_write_ucl(struct rspamd_task *task,
						  enum rspamd_protocol_flags flags)
{
	ucl_object_t *top = NULL;
	GString *dkim_sig;
	GList *dkim_sigs;
	const ucl_object_t *milter_reply;

	rspamd_task_set_finish_time(task);
	top = ucl_object_typed_new(UCL_OBJECT);

	rspamd_mempool_add_destructor(task->task_pool,
								  (rspamd_mempool_destruct_t) ucl_object_unref, top);

	if (flags & RSPAMD_PROTOCOL_METRICS) {
		rspamd_scan_result_ucl(task, task->result, top);
	}

	if (flags & RSPAMD_PROTOCOL_MESSAGES) {
		if (G_UNLIKELY(task->cfg->compat_messages)) {
			const ucl_object_t *cur;
			ucl_object_t *msg_object;
			ucl_object_iter_t iter = NULL;

			msg_object = ucl_object_typed_new(UCL_ARRAY);

			while ((cur = ucl_object_iterate(task->messages, &iter, true)) != NULL) {
				if (cur->type == UCL_STRING) {
					ucl_array_append(msg_object, ucl_object_ref(cur));
				}
			}

			ucl_object_insert_key(top, msg_object, "messages", 0, false);
		}
		else {
			ucl_object_insert_key(top, ucl_object_ref(task->messages),
								  "messages", 0, false);
		}
	}

	if (flags & RSPAMD_PROTOCOL_URLS && task->message) {
		if (kh_size(MESSAGE_FIELD(task, urls)) > 0) {
			ucl_object_insert_key(top,
								  rspamd_urls_tree_ucl(MESSAGE_FIELD(task, urls), task),
								  "urls", 0, false);
			ucl_object_insert_key(top,
								  rspamd_emails_tree_ucl(MESSAGE_FIELD(task, urls), task),
								  "emails", 0, false);
		}
	}

	if (flags & RSPAMD_PROTOCOL_EXTRA) {
		if (G_UNLIKELY(RSPAMD_TASK_IS_PROFILING(task))) {
			rspamd_protocol_output_profiling(task, top);
		}
	}

	if (flags & RSPAMD_PROTOCOL_BASIC) {
		ucl_object_insert_key(top,
							  ucl_object_fromstring(MESSAGE_FIELD_CHECK(task, message_id)),
							  "message-id", 0, false);
		ucl_object_insert_key(top,
							  ucl_object_fromdouble(task->time_real_finish - task->task_timestamp),
							  "time_real", 0, false);
	}

	if (flags & RSPAMD_PROTOCOL_DKIM) {
		dkim_sigs = rspamd_mempool_get_variable(task->task_pool,
												RSPAMD_MEMPOOL_DKIM_SIGNATURE);

		if (dkim_sigs) {
			if (dkim_sigs->next) {
				/* Multiple DKIM signatures */
				ucl_object_t *ar = ucl_object_typed_new(UCL_ARRAY);

				for (; dkim_sigs != NULL; dkim_sigs = dkim_sigs->next) {
					GString *folded_header;
					dkim_sig = (GString *) dkim_sigs->data;

					if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER ||
						!task->message) {

						folded_header = rspamd_header_value_fold(
							"DKIM-Signature", strlen("DKIM-Signature"),
							dkim_sig->str, dkim_sig->len,
							80, RSPAMD_TASK_NEWLINES_LF, NULL);
					}
					else {
						folded_header = rspamd_header_value_fold(
							"DKIM-Signature", strlen("DKIM-Signature"),
							dkim_sig->str, dkim_sig->len,
							80,
							MESSAGE_FIELD(task, nlines_type),
							NULL);
					}

					ucl_array_append(ar,
									 ucl_object_fromstring_common(folded_header->str,
																  folded_header->len, UCL_STRING_RAW));
					g_string_free(folded_header, TRUE);
				}

				ucl_object_insert_key(top,
									  ar,
									  "dkim-signature", 0,
									  false);
			}
			else {
				/* Single DKIM signature */
				GString *folded_header;
				dkim_sig = (GString *) dkim_sigs->data;

				if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) {
					folded_header = rspamd_header_value_fold(
						"DKIM-Signature", strlen("DKIM-Signature"),
						dkim_sig->str, dkim_sig->len,
						80, RSPAMD_TASK_NEWLINES_LF, NULL);
				}
				else {
					folded_header = rspamd_header_value_fold(
						"DKIM-Signature", strlen("DKIM-Signature"),
						dkim_sig->str, dkim_sig->len,
						80, MESSAGE_FIELD(task, nlines_type),
						NULL);
				}

				ucl_object_insert_key(top,
									  ucl_object_fromstring_common(folded_header->str,
																   folded_header->len, UCL_STRING_RAW),
									  "dkim-signature", 0, false);
				g_string_free(folded_header, TRUE);
			}
		}
	}

	if (flags & RSPAMD_PROTOCOL_RMILTER) {
		milter_reply = rspamd_mempool_get_variable(task->task_pool,
												   RSPAMD_MEMPOOL_MILTER_REPLY);

		if (milter_reply) {
			if (task->cmd != CMD_CHECK) {
				ucl_object_insert_key(top, ucl_object_ref(milter_reply),
									  "milter", 0, false);
			}
			else {
				ucl_object_insert_key(top, ucl_object_ref(milter_reply),
									  "rmilter", 0, false);
			}
		}
	}

	return top;
}

/*
 * Helper: update rolling history and write task log.
 * Shared between v2 and v3 reply handlers.
 */
static void
rspamd_protocol_update_history_and_log(struct rspamd_task *task)
{
	if (!(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		if (task->worker->srv->history) {
			rspamd_roll_history_update(task->worker->srv->history, task);
		}
	}
	else {
		msg_debug_protocol("skip history update due to no log flag");
	}

	rspamd_task_write_log(task);
}

/*
 * Helper: update action stats, messages_scanned counter, and avg processing time.
 * Shared between v2 and v3 reply handlers.
 */
static void
rspamd_protocol_update_stats(struct rspamd_task *task)
{
	if (!(task->flags & RSPAMD_TASK_FLAG_NO_STAT)) {
		struct rspamd_scan_result *metric_res = task->result;

		if (metric_res != NULL) {
			struct rspamd_action *action = rspamd_check_action_metric(task, NULL, NULL);

			if (action->action_type == METRIC_ACTION_SOFT_REJECT &&
				(task->flags & RSPAMD_TASK_FLAG_GREYLISTED)) {
#ifndef HAVE_ATOMIC_BUILTINS
				task->worker->srv->stat->actions_stat[METRIC_ACTION_GREYLIST]++;
#else
				__atomic_add_fetch(&task->worker->srv->stat->actions_stat[METRIC_ACTION_GREYLIST],
								   1, __ATOMIC_RELEASE);
#endif
			}
			else if (action->action_type < METRIC_ACTION_MAX) {
#ifndef HAVE_ATOMIC_BUILTINS
				task->worker->srv->stat->actions_stat[action->action_type]++;
#else
				__atomic_add_fetch(&task->worker->srv->stat->actions_stat[action->action_type],
								   1, __ATOMIC_RELEASE);
#endif
			}
		}

#ifndef HAVE_ATOMIC_BUILTINS
		task->worker->srv->stat->messages_scanned++;
#else
		__atomic_add_fetch(&task->worker->srv->stat->messages_scanned,
						   1, __ATOMIC_RELEASE);
#endif

		/* Set average processing time */
		uint32_t slot;
		float processing_time = task->time_real_finish - task->task_timestamp;

#ifndef HAVE_ATOMIC_BUILTINS
		slot = task->worker->srv->stat->avg_time.cur_slot++;
#else
		slot = __atomic_fetch_add(&task->worker->srv->stat->avg_time.cur_slot,
								  1, __ATOMIC_RELEASE);
#endif
		slot = slot % MAX_AVG_TIME_SLOTS;
		task->worker->srv->stat->avg_time.avg_time[slot] = processing_time;
	}
}

/*
 * Helper: compute the rewritten message body start and length.
 * For milter protocol, skip past the raw headers to return only the body.
 * Shared between v2 and v3 reply handlers.
 */
static void
rspamd_protocol_get_rewritten_body(struct rspamd_task *task,
								   const char **body_start,
								   gsize *body_len)
{
	*body_start = task->msg.begin;
	*body_len = task->msg.len;

	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) {
		goffset hdr_off = MESSAGE_FIELD(task, raw_headers_content).len;

		if (hdr_off < (goffset) *body_len) {
			*body_start += hdr_off;
			*body_len -= hdr_off;

			/* Skip the \r\n separator between headers and body */
			if (**body_start == '\r' && *body_len > 0) {
				(*body_start)++;
				(*body_len)--;
			}

			if (**body_start == '\n' && *body_len > 0) {
				(*body_start)++;
				(*body_len)--;
			}
		}
	}
}

void rspamd_protocol_http_reply(struct rspamd_http_message *msg,
								struct rspamd_task *task, ucl_object_t **pobj, int how)
{
	const struct rspamd_re_cache_stat *restat;
	ucl_object_t *top = NULL;
	rspamd_fstring_t *reply;
	int flags = RSPAMD_PROTOCOL_DEFAULT;

	/* Removed in 2.0 */
#if 0
	GHashTableIter hiter;
	gpointer h, v;
	/* Write custom headers */
	g_hash_table_iter_init (&hiter, task->reply_headers);
	while (g_hash_table_iter_next (&hiter, &h, &v)) {
		rspamd_ftok_t *hn = h, *hv = v;

		rspamd_http_message_add_header (msg, hn->begin, hv->begin);
	}
#endif

	flags |= RSPAMD_PROTOCOL_URLS;

	top = rspamd_protocol_write_ucl(task, flags);

	if (pobj) {
		*pobj = top;
	}

	rspamd_protocol_update_history_and_log(task);

	if (task->cfg->log_flags & RSPAMD_LOG_FLAG_RE_CACHE) {
		restat = rspamd_re_cache_get_stat(task->re_rt);
		g_assert(restat != NULL);
		msg_notice_task(
			"regexp statistics: %ud pcre regexps scanned, %ud regexps matched,"
			" %ud regexps total, %ud regexps cached,"
			" %HL scanned using pcre, %HL scanned total",
			restat->regexp_checked,
			restat->regexp_matched,
			restat->regexp_total,
			restat->regexp_fast_cached,
			restat->bytes_scanned_pcre,
			restat->bytes_scanned);
	}

	reply = rspamd_fstring_sized_new(1000);

	if (msg->method < HTTP_SYMBOLS && !RSPAMD_TASK_IS_SPAMC(task)) {
		msg_debug_protocol("writing json reply");
		rspamd_ucl_emit_fstring(top, how, &reply);
	}
	else {
		if (RSPAMD_TASK_IS_SPAMC(task)) {
			msg_debug_protocol("writing spamc legacy reply to client");
			rspamd_ucl_tospamc_output(top, &reply);
		}
		else {
			msg_debug_protocol("writing rspamc legacy reply to client");
			rspamd_ucl_torspamc_output(top, &reply);
		}
	}

	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_BODY_BLOCK) {
		/* Check if we need to insert a body block */
		if (task->flags & RSPAMD_TASK_FLAG_MESSAGE_REWRITE) {
			GString *hdr_offset = g_string_sized_new(30);

			rspamd_printf_gstring(hdr_offset, "%z", RSPAMD_FSTRING_LEN(reply));
			rspamd_http_message_add_header(msg, MESSAGE_OFFSET_HEADER,
										   hdr_offset->str);
			msg_debug_protocol("write body block at position %s",
							   hdr_offset->str);
			g_string_free(hdr_offset, TRUE);

			const char *body_start;
			gsize body_len;

			rspamd_protocol_get_rewritten_body(task, &body_start, &body_len);
			msg_debug_protocol("body block size %d (milter=%s)",
							   (int) body_len,
							   (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) ? "yes" : "no");
			reply = rspamd_fstring_append(reply, body_start, body_len);
		}
	}

	/* Check if we should compress the response */
	gboolean should_compress = FALSE;

	/* Rule 1: If request had compression, preserve it (existing behavior) */
	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED) {
		should_compress = TRUE;
	}

	/* Rule 2: If client supports zstd compression, honor it (takes precedence) */
	const rspamd_ftok_t *accept_encoding = rspamd_task_get_request_header(task, "Accept-Encoding");
	if (accept_encoding && rspamd_substring_search_caseless(accept_encoding->begin, accept_encoding->len, "zstd", 4) != -1) {
		should_compress = TRUE;
	}

	if (should_compress && rspamd_libs_reset_compression(task->cfg->libs_ctx)) {
		/* We can compress output */
		ZSTD_inBuffer zin;
		ZSTD_outBuffer zout;
		ZSTD_CStream *zstream;
		rspamd_fstring_t *compressed_reply;
		gsize r;

		zstream = task->cfg->libs_ctx->out_zstream;
		compressed_reply = rspamd_fstring_sized_new(ZSTD_compressBound(reply->len));
		zin.pos = 0;
		zin.src = reply->str;
		zin.size = reply->len;
		zout.pos = 0;
		zout.dst = compressed_reply->str;
		zout.size = compressed_reply->allocated;

		while (zin.pos < zin.size) {
			r = ZSTD_compressStream(zstream, &zout, &zin);

			if (ZSTD_isError(r)) {
				msg_err_protocol("cannot compress: %s", ZSTD_getErrorName(r));
				rspamd_fstring_free(compressed_reply);
				rspamd_http_message_set_body_from_fstring_steal(msg, reply);

				goto end;
			}
		}

		ZSTD_flushStream(zstream, &zout);
		r = ZSTD_endStream(zstream, &zout);

		if (ZSTD_isError(r)) {
			msg_err_protocol("cannot finalize compress: %s", ZSTD_getErrorName(r));
			rspamd_fstring_free(compressed_reply);
			rspamd_http_message_set_body_from_fstring_steal(msg, reply);

			goto end;
		}

		msg_info_protocol("writing compressed results: %z bytes before "
						  "%z bytes after",
						  zin.pos, zout.pos);
		compressed_reply->len = zout.pos;
		rspamd_fstring_free(reply);
		rspamd_http_message_set_body_from_fstring_steal(msg, compressed_reply);
		rspamd_http_message_add_header(msg, COMPRESSION_HEADER, "zstd");
		rspamd_http_message_add_header(msg, CONTENT_ENCODING_HEADER, "zstd");

		if (task->cfg->libs_ctx->out_dict &&
			task->cfg->libs_ctx->out_dict->id != 0) {
			char dict_str[32];

			rspamd_snprintf(dict_str, sizeof(dict_str), "%ud",
							task->cfg->libs_ctx->out_dict->id);
			rspamd_http_message_add_header(msg, "Dictionary", dict_str);
		}
	}
	else {
		rspamd_http_message_set_body_from_fstring_steal(msg, reply);
	}

end:
	rspamd_protocol_update_stats(task);
}

void rspamd_protocol_write_log_pipe(struct rspamd_task *task)
{
	struct rspamd_worker_log_pipe *lp;
	struct rspamd_protocol_log_message_sum *ls;
	lua_State *L = task->cfg->lua_state;
	struct rspamd_scan_result *mres;
	struct rspamd_symbol_result *sym;
	int id, i;
	uint32_t n = 0, nextra = 0;
	gsize sz;
	GArray *extra;
	struct rspamd_protocol_log_symbol_result er;
	struct rspamd_task **ptask;

	/* Get extra results from lua plugins */
	extra = g_array_new(FALSE, FALSE, sizeof(er));

	lua_getglobal(L, "rspamd_plugins");
	if (lua_istable(L, -1)) {
		lua_pushnil(L);

		while (lua_next(L, -2)) {
			if (lua_istable(L, -1)) {
				lua_pushvalue(L, -2);
				/* stack:
				 * -1: copy of key
				 * -2: value (module table)
				 * -3: key (module name)
				 * -4: global
				 */
				lua_pushstring(L, "log_callback");
				lua_gettable(L, -3);
				/* stack:
				 * -1: func
				 * -2: copy of key
				 * -3: value (module table)
				 * -3: key (module name)
				 * -4: global
				 */
				if (lua_isfunction(L, -1)) {
					ptask = lua_newuserdata(L, sizeof(*ptask));
					*ptask = task;
					rspamd_lua_setclass(L, rspamd_task_classname, -1);
					/* stack:
					 * -1: task
					 * -2: func
					 * -3: key copy
					 * -4: value (module table)
					 * -5: key (module name)
					 * -6: global
					 */
					msg_debug_protocol("calling for %s", lua_tostring(L, -3));
					if (lua_pcall(L, 1, 1, 0) != 0) {
						msg_info_protocol("call to log callback %s failed: %s",
										  lua_tostring(L, -2), lua_tostring(L, -1));
						lua_pop(L, 1);
						/* stack:
						 * -1: key copy
						 * -2: value
						 * -3: key
						 */
					}
					else {
						/* stack:
						 * -1: result
						 * -2: key copy
						 * -3: value
						 * -4: key
						 */
						if (lua_istable(L, -1)) {
							/* Another iteration */
							lua_pushnil(L);

							while (lua_next(L, -2)) {
								/* stack:
								 * -1: value
								 * -2: key
								 * -3: result table (pcall)
								 * -4: key copy (parent)
								 * -5: value (parent)
								 * -6: key (parent)
								 */
								if (lua_istable(L, -1)) {
									er.id = 0;
									er.score = 0.0;

									lua_rawgeti(L, -1, 1);
									if (lua_isnumber(L, -1)) {
										er.id = lua_tonumber(L, -1);
									}
									lua_rawgeti(L, -2, 2);
									if (lua_isnumber(L, -1)) {
										er.score = lua_tonumber(L, -1);
									}
									/* stack:
									 * -1: value[2]
									 * -2: value[1]
									 * -3: values
									 * -4: key
									 * -5: result table (pcall)
									 * -6: key copy (parent)
									 * -7: value (parent)
									 * -8: key (parent)
									 */
									lua_pop(L, 2); /* Values */
									g_array_append_val(extra, er);
								}

								lua_pop(L, 1); /* Value for lua_next */
							}

							lua_pop(L, 1); /* Table result of pcall */
						}
						else {
							msg_info_protocol("call to log callback %s returned "
											  "wrong type: %s",
											  lua_tostring(L, -2),
											  lua_typename(L, lua_type(L, -1)));
							lua_pop(L, 1); /* Returned error */
						}
					}
				}
				else {
					lua_pop(L, 1);
					/* stack:
					 * -1: key copy
					 * -2: value
					 * -3: key
					 */
				}
			}

			lua_pop(L, 2); /* Top table + key copy */
		}

		lua_pop(L, 1); /* rspamd_plugins global */
	}
	else {
		lua_pop(L, 1);
	}

	nextra = extra->len;

	LL_FOREACH(task->cfg->log_pipes, lp)
	{
		if (lp->fd != -1) {
			switch (lp->type) {
			case RSPAMD_LOG_PIPE_SYMBOLS:
				mres = task->result;

				if (mres) {
					n = kh_size(mres->symbols);
					sz = sizeof(*ls) +
						 sizeof(struct rspamd_protocol_log_symbol_result) *
							 (n + nextra);
					ls = g_malloc0(sz);

					/* Handle settings id */

					if (task->settings_elt) {
						ls->settings_id = task->settings_elt->id;
					}
					else {
						ls->settings_id = 0;
					}

					ls->score = mres->score;
					ls->required_score = rspamd_task_get_required_score(task,
																		mres);
					ls->nresults = n;
					ls->nextra = nextra;

					i = 0;

					kh_foreach_value(mres->symbols, sym, {
						id = rspamd_symcache_find_symbol(task->cfg->cache,
														 sym->name);

						if (id >= 0) {
							ls->results[i].id = id;
							ls->results[i].score = sym->score;
						}
						else {
							ls->results[i].id = -1;
							ls->results[i].score = 0.0;
						}

						i++;
					});

					memcpy(&ls->results[n], extra->data, nextra * sizeof(er));
				}
				else {
					sz = sizeof(*ls);
					ls = g_malloc0(sz);
					ls->nresults = 0;
				}

				/* We don't really care about return value here */
				if (write(lp->fd, ls, sz) == -1) {
					msg_info_protocol("cannot write to log pipe: %s",
									  strerror(errno));
				}

				g_free(ls);
				break;
			default:
				msg_err_protocol("unknown log format %d", lp->type);
				break;
			}
		}
	}

	g_array_free(extra, TRUE);
}

/*
 * Handle metadata from a parsed UCL object for v3 protocol.
 * Maps structured metadata fields to task fields.
 */
static gboolean
rspamd_protocol_handle_metadata(struct rspamd_task *task,
								const ucl_object_t *metadata)
{
	const ucl_object_t *elt, *cur;
	gboolean has_ip = FALSE;

	if (!metadata || ucl_object_type(metadata) != UCL_OBJECT) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"metadata is not a valid object");
		return FALSE;
	}

	/* from */
	elt = ucl_object_lookup(metadata, "from");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		const char *from_str = ucl_object_tostring(elt);
		rspamd_protocol_set_from_envelope(task, from_str, strlen(from_str));
	}

	/* rcpt (array) */
	elt = ucl_object_lookup(metadata, "rcpt");
	if (elt) {
		if (ucl_object_type(elt) == UCL_ARRAY) {
			ucl_object_iter_t it = NULL;

			while ((cur = ucl_object_iterate(elt, &it, true)) != NULL) {
				if (ucl_object_type(cur) == UCL_STRING) {
					const char *rcpt_str = ucl_object_tostring(cur);
					struct rspamd_email_address *addr =
						rspamd_email_address_from_smtp(rcpt_str, strlen(rcpt_str));

					if (addr) {
						if (!task->rcpt_envelope) {
							task->rcpt_envelope = g_ptr_array_sized_new(2);
						}
						g_ptr_array_add(task->rcpt_envelope, addr);
					}
					else {
						msg_err_protocol("bad rcpt in metadata: '%s'", rcpt_str);
						task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
					}
				}
			}
		}
		else if (ucl_object_type(elt) == UCL_STRING) {
			/* Single recipient as string */
			const char *rcpt_str = ucl_object_tostring(elt);
			struct rspamd_email_address *addr =
				rspamd_email_address_from_smtp(rcpt_str, strlen(rcpt_str));

			if (addr) {
				if (!task->rcpt_envelope) {
					task->rcpt_envelope = g_ptr_array_sized_new(2);
				}
				g_ptr_array_add(task->rcpt_envelope, addr);
			}
		}
	}

	/* ip */
	elt = ucl_object_lookup(metadata, "ip");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		const char *ip_str = ucl_object_tostring(elt);
		rspamd_protocol_set_ip(task, ip_str, strlen(ip_str), &has_ip);
	}

	if (!has_ip) {
		task->flags |= RSPAMD_TASK_FLAG_NO_IP;
	}

	/* helo */
	elt = ucl_object_lookup(metadata, "helo");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		task->helo = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
	}

	/* hostname */
	elt = ucl_object_lookup(metadata, "hostname");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		task->hostname = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
	}

	/* queue_id */
	elt = ucl_object_lookup(metadata, "queue_id");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		task->queue_id = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
	}

	/* user */
	elt = ucl_object_lookup(metadata, "user");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		task->auth_user = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
	}

	/* deliver_to */
	elt = ucl_object_lookup(metadata, "deliver_to");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		task->deliver_to = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
	}

	/* settings_id */
	elt = ucl_object_lookup(metadata, "settings_id");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		const char *sid = ucl_object_tostring(elt);
		rspamd_protocol_set_settings_id(task, sid, strlen(sid));
	}

	/* settings (inline UCL object) */
	elt = ucl_object_lookup(metadata, "settings");
	if (elt && ucl_object_type(elt) == UCL_OBJECT) {
		/* If both settings_id and settings are present, settings wins */
		if (task->settings_elt) {
			msg_warn_protocol("ignore settings_id because inline settings is also present");
			REF_RELEASE(task->settings_elt);
			task->settings_elt = NULL;
		}
		task->settings = ucl_object_ref(elt);
	}

	/* tls.cipher - sets SSL flag */
	elt = ucl_object_lookup_path(metadata, "tls.cipher");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		task->flags |= RSPAMD_TASK_FLAG_SSL;
	}

	/* mta.tag */
	elt = ucl_object_lookup_path(metadata, "mta.tag");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		char *mta_tag = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
		rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_MTA_TAG, mta_tag, NULL);
	}

	/* mta.name */
	elt = ucl_object_lookup_path(metadata, "mta.name");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		char *mta_name = rspamd_mempool_strdup(task->task_pool, ucl_object_tostring(elt));
		rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_MTA_NAME, mta_name, NULL);
	}

	/* flags (array of strings) */
	elt = ucl_object_lookup(metadata, "flags");
	if (elt && ucl_object_type(elt) == UCL_ARRAY) {
		ucl_object_iter_t it = NULL;

		while ((cur = ucl_object_iterate(elt, &it, true)) != NULL) {
			if (ucl_object_type(cur) == UCL_STRING) {
				const char *flag_str = ucl_object_tostring(cur);
				rspamd_protocol_handle_flag(task, flag_str, strlen(flag_str));
			}
		}
	}

	/* raw - disable MIME parsing */
	elt = ucl_object_lookup(metadata, "raw");
	if (elt && ucl_object_type(elt) == UCL_BOOLEAN) {
		if (ucl_object_toboolean(elt)) {
			task->flags &= ~RSPAMD_TASK_FLAG_MIME;
		}
	}

	/* log_tag */
	elt = ucl_object_lookup(metadata, "log_tag");
	if (elt && ucl_object_type(elt) == UCL_STRING) {
		const char *tag = ucl_object_tostring(elt);
		rspamd_protocol_set_log_tag(task, tag, strlen(tag));
	}

	/* mail_esmtp_args (object: key -> value) */
	elt = ucl_object_lookup(metadata, "mail_esmtp_args");
	if (elt && ucl_object_type(elt) == UCL_OBJECT) {
		ucl_object_iter_t it = NULL;
		while ((cur = ucl_object_iterate(elt, &it, true)) != NULL) {
			if (ucl_object_type(cur) == UCL_STRING) {
				const char *key = ucl_object_key(cur);
				const char *val = ucl_object_tostring(cur);
				rspamd_protocol_add_mail_esmtp_arg(task,
												   key, strlen(key), val, strlen(val));
			}
		}
	}

	/* rcpt_esmtp_args (array of objects) */
	elt = ucl_object_lookup(metadata, "rcpt_esmtp_args");
	if (elt && ucl_object_type(elt) == UCL_ARRAY) {
		ucl_object_iter_t arr_it = NULL;
		int rcpt_idx = 0;

		while ((cur = ucl_object_iterate(elt, &arr_it, true)) != NULL) {
			if (ucl_object_type(cur) == UCL_OBJECT) {
				ucl_object_iter_t obj_it = NULL;
				const ucl_object_t *kv;

				while ((kv = ucl_object_iterate(cur, &obj_it, true)) != NULL) {
					if (ucl_object_type(kv) == UCL_STRING) {
						const char *key = ucl_object_key(kv);
						const char *val = ucl_object_tostring(kv);
						rspamd_protocol_add_rcpt_esmtp_arg(task, rcpt_idx,
														   key, strlen(key), val, strlen(val));
					}
				}
			}
			else {
				/* Non-object entry: ensure array slot exists as NULL */
				if (!task->rcpt_esmtp_args) {
					task->rcpt_esmtp_args = g_ptr_array_new();
				}
				while ((int) task->rcpt_esmtp_args->len <= rcpt_idx) {
					g_ptr_array_add(task->rcpt_esmtp_args, NULL);
				}
			}
			rcpt_idx++;
		}
	}

	return TRUE;
}

/* Shared memory mapping cleanup for v3 request body */
struct rspamd_v3_shm_map {
	gpointer begin;
	gulong len;
	int fd;
};

static void
rspamd_v3_shm_unmapper(gpointer ud)
{
	struct rspamd_v3_shm_map *m = ud;
	munmap(m->begin, m->len);
	close(m->fd);
}

/*
 * Handle v3 multipart/form-data request.
 */
gboolean
rspamd_protocol_handle_v3_request(struct rspamd_task *task,
								  struct rspamd_http_message *msg,
								  const char *chunk, gsize len)
{
	const char *boundary = NULL;
	gsize boundary_len = 0;
	const char *body_data = chunk;
	gsize body_len = len;

	/*
	 * When the proxy forwards to a local upstream, it uses shared memory
	 * (GET + Shm/Shm-Offset/Shm-Length headers) instead of sending the
	 * body inline.  In that case chunk/len are empty, so we must read
	 * the body from the shared memory segment referenced by the headers.
	 */
	if (body_len == 0 || body_data == NULL) {
		const rspamd_ftok_t *shm_tok = rspamd_http_message_find_header(msg, "Shm");

		if (shm_tok) {
			char filepath[PATH_MAX], *fp;
			int fd;
			struct stat st;
			gulong offset = 0, shmem_size = 0;

			rspamd_strlcpy(filepath, shm_tok->begin,
						   MIN(sizeof(filepath), shm_tok->len + 1));
			rspamd_url_decode(filepath, filepath, strlen(filepath) + 1);

			int flen = strlen(filepath);
			if (filepath[0] == '"' && flen > 2) {
				fp = &filepath[1];
				fp[flen - 2] = '\0';
			}
			else {
				fp = &filepath[0];
			}

#ifdef HAVE_SANE_SHMEM
			fd = shm_open(fp, O_RDONLY, 00600);
#else
			fd = open(fp, O_RDONLY, 00600);
#endif
			if (fd == -1) {
				g_set_error(&task->err, rspamd_protocol_quark(), 500,
							"cannot open shm segment (%s): %s", fp, strerror(errno));
				return FALSE;
			}

			if (fstat(fd, &st) == -1) {
				g_set_error(&task->err, rspamd_protocol_quark(), 500,
							"cannot stat shm segment (%s): %s", fp, strerror(errno));
				close(fd);
				return FALSE;
			}

			gpointer map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
			if (map == MAP_FAILED) {
				g_set_error(&task->err, rspamd_protocol_quark(), 500,
							"cannot mmap shm segment (%s): %s", fp, strerror(errno));
				close(fd);
				return FALSE;
			}

			const rspamd_ftok_t *off_tok = rspamd_http_message_find_header(msg, "Shm-Offset");
			if (off_tok) {
				rspamd_strtoul(off_tok->begin, off_tok->len, &offset);
				if (offset > (gulong) st.st_size) {
					munmap(map, st.st_size);
					close(fd);
					g_set_error(&task->err, rspamd_protocol_quark(), 500,
								"invalid shm offset");
					return FALSE;
				}
			}

			shmem_size = st.st_size;
			const rspamd_ftok_t *len_tok = rspamd_http_message_find_header(msg, "Shm-Length");
			if (len_tok) {
				rspamd_strtoul(len_tok->begin, len_tok->len, &shmem_size);
				if (shmem_size > (gulong) st.st_size) {
					munmap(map, st.st_size);
					close(fd);
					g_set_error(&task->err, rspamd_protocol_quark(), 500,
								"invalid shm length");
					return FALSE;
				}
			}

			body_data = ((const char *) map) + offset;
			body_len = shmem_size;

			/* Register cleanup for the mapping */
			struct rspamd_v3_shm_map *m = rspamd_mempool_alloc(task->task_pool, sizeof(*m));
			m->begin = map;
			m->len = st.st_size;
			m->fd = fd;
			rspamd_mempool_add_destructor(task->task_pool,
										  rspamd_v3_shm_unmapper, m);

			msg_info_task("v3 request: loaded body from shm %s (%ul size, %ul offset)",
						  fp, (unsigned long) shmem_size, (unsigned long) offset);
		}
		else if (msg->body_buf.len > 0) {
			/* Fallback: use the HTTP message body buffer directly */
			body_data = msg->body_buf.begin;
			body_len = msg->body_buf.len;
		}
	}

	/* Extract boundary from HTTP Content-Type header */
	const rspamd_ftok_t *ct_hdr = rspamd_http_message_find_header(msg, "Content-Type");

	if (!ct_hdr) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"missing Content-Type header for v3 request");
		return FALSE;
	}

	struct rspamd_content_type *ct = rspamd_content_type_parse(
		ct_hdr->begin, ct_hdr->len, task->task_pool);

	if (!ct || ct->boundary.len == 0) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"cannot extract boundary from Content-Type");
		return FALSE;
	}

	boundary = ct->boundary.begin;
	boundary_len = ct->boundary.len;

	/* Parse multipart body */
	struct rspamd_multipart_form_c *form = rspamd_multipart_form_parse(
		body_data, body_len, boundary, boundary_len);

	if (!form) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"cannot parse multipart/form-data body");
		return FALSE;
	}

	/* Register destructor for the form */
	rspamd_mempool_add_destructor(task->task_pool,
								  (rspamd_mempool_destruct_t) rspamd_multipart_form_free,
								  form);

	/* Enforce single message per request: expect at most 2 parts (metadata + message) */
	gsize nparts = rspamd_multipart_form_nparts(form);
	if (nparts > 2) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"v3 request must contain at most 2 parts (metadata + message), got %lu",
					(unsigned long) nparts);
		return FALSE;
	}

	/* Find metadata part */
	const struct rspamd_multipart_entry_c *metadata_part =
		rspamd_multipart_form_find(form, "metadata", sizeof("metadata") - 1);

	if (!metadata_part || metadata_part->data_len == 0) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"missing 'metadata' part in v3 request");
		return FALSE;
	}

	/* Parse metadata as UCL (detect JSON vs msgpack from Content-Type) */
	struct ucl_parser *parser;

	if (metadata_part->content_type &&
		metadata_part->content_type_len > 0 &&
		rspamd_substring_search_caseless(metadata_part->content_type,
										 metadata_part->content_type_len,
										 "msgpack",
										 sizeof("msgpack") - 1) != -1) {
		parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
		ucl_parser_add_chunk_full(parser, (const unsigned char *) metadata_part->data,
								  metadata_part->data_len,
								  ucl_parser_get_default_priority(parser),
								  UCL_DUPLICATE_APPEND,
								  UCL_PARSE_MSGPACK);
	}
	else {
		/* Strict mode: disable UCL macros/includes, treat as plain JSON */
		parser = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
		ucl_parser_add_chunk(parser, (const unsigned char *) metadata_part->data,
							 metadata_part->data_len);
	}

	if (ucl_parser_get_error(parser) != NULL) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"cannot parse metadata: %s", ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return FALSE;
	}

	ucl_object_t *metadata_obj = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	if (!metadata_obj) {
		g_set_error(&task->err, rspamd_protocol_quark(), 400,
					"empty metadata object");
		return FALSE;
	}

	rspamd_mempool_add_destructor(task->task_pool,
								  (rspamd_mempool_destruct_t) ucl_object_unref,
								  metadata_obj);

	/* Apply metadata to task */
	if (!rspamd_protocol_handle_metadata(task, metadata_obj)) {
		return FALSE;
	}

	/* Check for file/shm in metadata (zero-copy paths) */
	const ucl_object_t *file_elt = ucl_object_lookup(metadata_obj, "file");
	const ucl_object_t *shm_elt = ucl_object_lookup(metadata_obj, "shm");

	if (file_elt && ucl_object_type(file_elt) == UCL_STRING) {
		/* Set file path and let rspamd_task_load_message handle it via task header */
		const char *fpath = ucl_object_tostring(file_elt);
		task->msg.fpath = rspamd_mempool_strdup(task->task_pool, fpath);

		/* Synthesize a request header so rspamd_task_load_message's file path works */
		rspamd_fstring_t *fhdr = rspamd_fstring_new_init(fpath, strlen(fpath));
		rspamd_ftok_t *name_tok = rspamd_mempool_alloc(task->task_pool, sizeof(*name_tok));
		rspamd_ftok_t *val_tok = rspamd_ftok_map(fhdr);

		RSPAMD_FTOK_ASSIGN(name_tok, "file");
		rspamd_task_add_request_header(task, name_tok, val_tok);

		/* Now load the message from file */
		return rspamd_task_load_message(task, NULL, NULL, 0);
	}
	else if (shm_elt && ucl_object_type(shm_elt) == UCL_STRING) {
		/* Synthesize shm headers */
		const char *shm_name = ucl_object_tostring(shm_elt);
		rspamd_fstring_t *fhdr = rspamd_fstring_new_init(shm_name, strlen(shm_name));
		rspamd_ftok_t *name_tok = rspamd_mempool_alloc(task->task_pool, sizeof(*name_tok));
		rspamd_ftok_t *val_tok = rspamd_ftok_map(fhdr);

		RSPAMD_FTOK_ASSIGN(name_tok, "shm");
		rspamd_task_add_request_header(task, name_tok, val_tok);

		const ucl_object_t *off_elt = ucl_object_lookup(metadata_obj, "shm_offset");
		if (off_elt) {
			char buf[32];
			int blen = rspamd_snprintf(buf, sizeof(buf), "%L",
									   ucl_object_toint(off_elt));
			rspamd_fstring_t *foff = rspamd_fstring_new_init(buf, blen);
			rspamd_ftok_t *off_name = rspamd_mempool_alloc(task->task_pool, sizeof(*off_name));
			rspamd_ftok_t *off_val = rspamd_ftok_map(foff);

			RSPAMD_FTOK_ASSIGN(off_name, "shm-offset");
			rspamd_task_add_request_header(task, off_name, off_val);
		}

		const ucl_object_t *len_elt = ucl_object_lookup(metadata_obj, "shm_length");
		if (len_elt) {
			char buf[32];
			int blen = rspamd_snprintf(buf, sizeof(buf), "%L",
									   ucl_object_toint(len_elt));
			rspamd_fstring_t *flen = rspamd_fstring_new_init(buf, blen);
			rspamd_ftok_t *len_name = rspamd_mempool_alloc(task->task_pool, sizeof(*len_name));
			rspamd_ftok_t *len_val = rspamd_ftok_map(flen);

			RSPAMD_FTOK_ASSIGN(len_name, "shm-length");
			rspamd_task_add_request_header(task, len_name, len_val);
		}

		return rspamd_task_load_message(task, NULL, NULL, 0);
	}
	else {
		/* Use inline message part */
		const struct rspamd_multipart_entry_c *msg_part =
			rspamd_multipart_form_find(form, "message", sizeof("message") - 1);

		if (!msg_part || msg_part->data_len == 0) {
			g_set_error(&task->err, rspamd_protocol_quark(), 400,
						"missing 'message' part in v3 request");
			return FALSE;
		}

		/* Check for per-part zstd compression */
		if (msg_part->content_encoding && msg_part->content_encoding_len > 0 &&
			rspamd_substring_search_caseless(msg_part->content_encoding,
											 msg_part->content_encoding_len,
											 "zstd", 4) != -1) {
			/* Decompress message */
			ZSTD_DStream *zstream;
			ZSTD_inBuffer zin;
			ZSTD_outBuffer zout;
			gsize outlen, r;

			if (!rspamd_libs_reset_decompression(task->cfg->libs_ctx)) {
				g_set_error(&task->err, rspamd_protocol_quark(), 500,
							"cannot init decompressor");
				return FALSE;
			}

			zstream = task->cfg->libs_ctx->in_zstream;
			zin.src = msg_part->data;
			zin.size = msg_part->data_len;
			zin.pos = 0;

			outlen = ZSTD_getDecompressedSize(msg_part->data, msg_part->data_len);
			if (outlen == 0) {
				outlen = ZSTD_DStreamOutSize();
			}

			unsigned char *out = (unsigned char *) g_malloc(outlen);
			zout.dst = out;
			zout.pos = 0;
			zout.size = outlen;

			while (zin.pos < zin.size) {
				r = ZSTD_decompressStream(zstream, &zout, &zin);

				if (ZSTD_isError(r)) {
					g_set_error(&task->err, rspamd_protocol_quark(), 400,
								"message decompression error: %s",
								ZSTD_getErrorName(r));
					g_free(out);
					return FALSE;
				}

				if (zout.pos == zout.size) {
					if (zout.size > task->cfg->max_message) {
						g_set_error(&task->err, rspamd_protocol_quark(), 413,
									"decompressed message exceeds max_message limit: %lu > %lu",
									(unsigned long) zout.size, (unsigned long) task->cfg->max_message);
						g_free(out);
						return FALSE;
					}
					zout.size = zout.size * 2 + 1;
					out = g_realloc(zout.dst, zout.size);
					zout.dst = out;
				}
			}

			rspamd_mempool_add_destructor(task->task_pool, g_free, zout.dst);
			task->msg.begin = (const char *) zout.dst;
			task->msg.len = zout.pos;
			task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED;

			msg_info_protocol("v3: loaded message from zstd compressed part; "
							  "compressed: %ul; uncompressed: %ul",
							  (gulong) zin.size, (gulong) zout.pos);
		}
		else {
			/* Zero-copy: point directly into the multipart buffer */
			task->msg.begin = msg_part->data;
			task->msg.len = msg_part->data_len;
		}

		if (task->msg.len == 0) {
			task->flags |= RSPAMD_TASK_FLAG_EMPTY;
		}

		return TRUE;
	}
}

/*
 * Build a v3 multipart/mixed HTTP reply.
 * Returns the Content-Type string (allocated on task pool) for use as
 * the mime_type parameter in rspamd_http_connection_write_message.
 */
const char *
rspamd_protocol_http_reply_v3(struct rspamd_http_message *msg,
							  struct rspamd_task *task)
{
	int flags = RSPAMD_PROTOCOL_DEFAULT | RSPAMD_PROTOCOL_URLS;
	ucl_object_t *top = rspamd_protocol_write_ucl(task, flags);

	rspamd_protocol_update_history_and_log(task);

	/* Determine output format from metadata part's Content-Type or Accept header */
	const rspamd_ftok_t *accept_hdr = rspamd_task_get_request_header(task, "Accept");
	int out_type = UCL_EMIT_JSON_COMPACT;
	const char *result_ctype = "application/json";

	if (accept_hdr && rspamd_substring_search(accept_hdr->begin, accept_hdr->len,
											  "application/msgpack",
											  sizeof("application/msgpack") - 1) != -1) {
		out_type = UCL_EMIT_MSGPACK;
		result_ctype = "application/msgpack";
	}

	/* Serialize result UCL */
	rspamd_fstring_t *result_data = rspamd_fstring_sized_new(1000);
	rspamd_ucl_emit_fstring(top, out_type, &result_data);

	/* Check if client wants compression */
	gboolean want_compress = FALSE;
	const rspamd_ftok_t *ae_hdr = rspamd_task_get_request_header(task, "Accept-Encoding");
	if (ae_hdr && rspamd_substring_search_caseless(ae_hdr->begin, ae_hdr->len,
												   "zstd", 4) != -1) {
		want_compress = TRUE;
	}

	/* Build multipart response */
	struct rspamd_multipart_response_c *resp = rspamd_multipart_response_new();

	rspamd_multipart_response_add_part(resp, "result", result_ctype,
									   result_data->str, result_data->len,
									   want_compress);

	/* If message was rewritten, add body part */
	if (task->flags & RSPAMD_TASK_FLAG_MESSAGE_REWRITE) {
		const char *body_start;
		gsize body_len;

		rspamd_protocol_get_rewritten_body(task, &body_start, &body_len);
		rspamd_multipart_response_add_part(resp, "body", "application/octet-stream",
										   body_start, body_len, want_compress);
	}

	/* Get compression stream if needed */
	void *zstream = NULL;
	if (want_compress && rspamd_libs_reset_compression(task->cfg->libs_ctx)) {
		zstream = task->cfg->libs_ctx->out_zstream;
	}

	rspamd_multipart_response_prepare_iov(resp, zstream);

	gsize niov, total_len;
	const struct iovec *body_segments =
		rspamd_multipart_response_body_iov(resp, &niov, &total_len);

	/* Copy iov array — message takes ownership of the copy */
	struct iovec *iov_copy = g_new(struct iovec, niov);
	memcpy(iov_copy, body_segments, sizeof(struct iovec) * niov);
	rspamd_http_message_set_body_iov(msg, iov_copy, niov, total_len);

	const char *resp_ctype = rspamd_multipart_response_content_type(resp);
	/* Copy Content-Type to task pool so it survives after response is freed */
	const char *pool_ctype = rspamd_mempool_strdup(task->task_pool, resp_ctype);

	/* Keep data alive until after HTTP write:
	 * - resp owns boundary/header strings and compressed buffers
	 * - result_data fstring owns the UCL result data
	 * Both freed when task_pool is destroyed (after write completes) */
	rspamd_mempool_add_destructor(task->task_pool,
								  (rspamd_mempool_destruct_t) rspamd_multipart_response_free, resp);
	rspamd_mempool_add_destructor(task->task_pool,
								  (rspamd_mempool_destruct_t) rspamd_fstring_free, result_data);

	rspamd_protocol_update_stats(task);

	return pool_ctype;
}

void rspamd_protocol_write_reply(struct rspamd_task *task, ev_tstamp timeout, struct rspamd_main *srv)
{
	struct rspamd_http_message *msg;
	const char *ctype = "application/json";
	rspamd_fstring_t *reply;
	ev_tstamp now = ev_time();

	msg = rspamd_http_new_message(HTTP_RESPONSE);

	if (rspamd_http_connection_is_encrypted(task->http_conn)) {
		msg_info_protocol("<%s> writing encrypted reply",
						  MESSAGE_FIELD_CHECK(task, message_id));
	}

	const rspamd_ftok_t *accept_hdr;
	int out_type = UCL_EMIT_JSON_COMPACT;
	accept_hdr = rspamd_task_get_request_header(task, "Accept");

	if (accept_hdr && rspamd_substring_search(accept_hdr->begin, accept_hdr->len,
											  "application/msgpack", sizeof("application/msgpack") - 1) != -1) {
		ctype = "application/msgpack";
		out_type = UCL_EMIT_MSGPACK;
	}

	/* Compatibility */
	if (task->cmd == CMD_CHECK_RSPAMC) {
		msg->method = HTTP_SYMBOLS;
	}
	else if (task->cmd == CMD_CHECK_SPAMC) {
		msg->method = HTTP_SYMBOLS;
		msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
	}

	if (task->err != NULL) {
		msg_debug_protocol("writing error reply to client");
		ucl_object_t *top = NULL;

		top = ucl_object_typed_new(UCL_OBJECT);
		msg->code = 500 + task->err->code % 100;
		msg->status = rspamd_fstring_new_init(task->err->message,
											  strlen(task->err->message));
		ucl_object_insert_key(top, ucl_object_fromstring(task->err->message),
							  "error", 0, false);
		ucl_object_insert_key(top,
							  ucl_object_fromstring(g_quark_to_string(task->err->domain)),
							  "error_domain", 0, false);
		reply = rspamd_fstring_sized_new(256);
		rspamd_ucl_emit_fstring(top, out_type, &reply);
		ucl_object_unref(top);

		/* We also need to validate utf8 */
		if (out_type != UCL_EMIT_MSGPACK && rspamd_fast_utf8_validate(reply->str, reply->len) != 0) {
			gsize valid_len;
			char *validated;

			/* We copy reply several times here, but it should be a rare case */
			validated = rspamd_str_make_utf_valid(reply->str, reply->len,
												  &valid_len, task->task_pool);
			rspamd_http_message_set_body(msg, validated, valid_len);
			rspamd_fstring_free(reply);
		}
		else {
			rspamd_http_message_set_body_from_fstring_steal(msg, reply);
		}
	}
	else {
		rspamd_fstring_t *output;
		struct rspamd_stat stat_copy;
		msg->status = rspamd_fstring_new_init("OK", 2);

		switch (task->cmd) {
		case CMD_CHECK:
		case CMD_CHECK_RSPAMC:
		case CMD_CHECK_SPAMC:
		case CMD_SKIP:
		case CMD_CHECK_V2:
			rspamd_protocol_http_reply(msg, task, NULL, out_type);
			rspamd_protocol_write_log_pipe(task);
			break;
		case CMD_CHECK_V3:
			ctype = rspamd_protocol_http_reply_v3(msg, task);
			rspamd_protocol_write_log_pipe(task);
			break;
		case CMD_PING:
			msg_debug_protocol("writing pong to client");
			rspamd_http_message_set_body(msg, "pong" CRLF, 6);
			ctype = "text/plain";
			break;
		case CMD_METRICS:
			msg_debug_protocol("writing metrics to client");

			memcpy(&stat_copy, srv->stat, sizeof(stat_copy));
			output = rspamd_metrics_to_prometheus_string(
				rspamd_worker_metrics_object(srv->cfg, &stat_copy, now - srv->start_time));
			rspamd_printf_fstring(&output, "# EOF\n");
			rspamd_http_message_set_body_from_fstring_steal(msg, output);
			ctype = "application/openmetrics-text; version=1.0.0; charset=utf-8";
			break;
		default:
			msg_err_protocol("BROKEN");
			break;
		}
	}

	ev_now_update(task->event_loop);
	msg->date = now;

	rspamd_http_connection_reset(task->http_conn);
	rspamd_http_connection_write_message(task->http_conn, msg, NULL,
										 ctype, task, timeout);

	task->processed_stages |= RSPAMD_TASK_STAGE_REPLIED;
}
