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
#include "contrib/fastutf8/fastutf8.h"
#include "task.h"
#include <math.h>

#ifdef SYS_ZSTD
#  include "zstd.h"
#else
#  include "contrib/zstd/zstd.h"
#endif

INIT_LOG_MODULE(protocol)

#define msg_err_protocol(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "protocol", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_protocol(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "protocol", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_protocol(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "protocol", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_protocol(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_protocol_log_id, "protocol", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

static GQuark
rspamd_protocol_quark (void)
{
	return g_quark_from_static_string ("protocol-error");
}

/*
 * Remove <> from the fixed string and copy it to the pool
 */
static gchar *
rspamd_protocol_escape_braces (struct rspamd_task *task, rspamd_ftok_t *in)
{
	guint nchars = 0;
	const gchar *p;
	rspamd_ftok_t tok;
	gboolean has_obrace = FALSE;

	g_assert (in != NULL);
	g_assert (in->len > 0);

	p = in->begin;

	while ((g_ascii_isspace (*p) || *p == '<') && nchars < in->len) {
		if (*p == '<') {
			has_obrace = TRUE;
		}

		p++;
		nchars ++;
	}

	tok.begin = p;

	p = in->begin + in->len - 1;
	tok.len = in->len - nchars;

	while (g_ascii_isspace (*p) && tok.len > 0) {
		p--;
		tok.len --;
	}

	if (has_obrace && *p == '>') {
		tok.len --;
	}

	return rspamd_mempool_ftokdup (task->task_pool, &tok);
}

#define COMPARE_CMD(str, cmd, len) (sizeof(cmd) - 1 == (len) && rspamd_lc_cmp((str), (cmd), (len)) == 0)

static gboolean
rspamd_protocol_handle_url (struct rspamd_task *task,
	struct rspamd_http_message *msg)
{
	GHashTable *query_args;
	GHashTableIter it;
	struct http_parser_url u;
	const gchar *p;
	gsize pathlen;
	rspamd_ftok_t *key, *value;
	gpointer k, v;

	if (msg->url == NULL || msg->url->len == 0) {
		g_set_error (&task->err, rspamd_protocol_quark(), 400, "missing command");
		return FALSE;
	}

	if (http_parser_parse_url (msg->url->str, msg->url->len, 0, &u) != 0) {
		g_set_error (&task->err, rspamd_protocol_quark(), 400, "bad request URL");

		return FALSE;
	}

	if (!(u.field_set & (1 << UF_PATH))) {
		g_set_error (&task->err, rspamd_protocol_quark(), 400,
				"bad request URL: missing path");

		return FALSE;
	}

	p = msg->url->str + u.field_data[UF_PATH].off;
	pathlen = u.field_data[UF_PATH].len;

	if (*p == '/') {
		p ++;
		pathlen --;
	}

	switch (*p) {
	case 'c':
	case 'C':
		/* check */
		if (COMPARE_CMD (p, MSG_CMD_CHECK_V2, pathlen)) {
			task->cmd = CMD_CHECK_V2;
			msg_debug_protocol ("got checkv2 command");
		}
		else if (COMPARE_CMD (p, MSG_CMD_CHECK, pathlen)) {
			task->cmd = CMD_CHECK;
			msg_debug_protocol ("got check command");
		}
		else {
			goto err;
		}
		break;
	case 's':
	case 'S':
		/* symbols, skip */
		if (COMPARE_CMD (p, MSG_CMD_SYMBOLS, pathlen)) {
			task->cmd = CMD_CHECK;
			msg_debug_protocol ("got symbols -> old check command");
		}
		else if (COMPARE_CMD (p, MSG_CMD_SCAN, pathlen)) {
			task->cmd = CMD_CHECK;
			msg_debug_protocol ("got scan -> old check command");
		}
		else if (COMPARE_CMD (p, MSG_CMD_SKIP, pathlen)) {
			msg_debug_protocol ("got skip command");
			task->cmd = CMD_SKIP;
		}
		else {
			goto err;
		}
		break;
	case 'p':
	case 'P':
		/* ping, process */
		if (COMPARE_CMD (p, MSG_CMD_PING, pathlen)) {
			msg_debug_protocol ("got ping command");
			task->cmd = CMD_PING;
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
			task->processed_stages |= RSPAMD_TASK_STAGE_DONE; /* Skip all */
		}
		else if (COMPARE_CMD (p, MSG_CMD_PROCESS, pathlen)) {
			msg_debug_protocol ("got process -> old check command");
			task->cmd = CMD_CHECK;
		}
		else {
			goto err;
		}
		break;
	case 'r':
	case 'R':
		/* report, report_ifspam */
		if (COMPARE_CMD (p, MSG_CMD_REPORT, pathlen)) {
			msg_debug_protocol ("got report -> old check command");
			task->cmd = CMD_CHECK;
		}
		else if (COMPARE_CMD (p, MSG_CMD_REPORT_IFSPAM, pathlen)) {
			msg_debug_protocol ("got reportifspam -> old check command");
			task->cmd = CMD_CHECK;
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
		query_args = rspamd_http_message_parse_query (msg);

		/* Insert the rest of query params as HTTP headers */
		g_hash_table_iter_init (&it, query_args);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			gchar *key_cpy;
			key = k;
			value = v;

			key_cpy = rspamd_mempool_ftokdup (task->task_pool, key);

			rspamd_http_message_add_header_len (msg, key_cpy,
					value->begin, value->len);
			msg_debug_protocol ("added header \"%T\" -> \"%T\" from HTTP query",
					key, value);
		}

		g_hash_table_unref (query_args);
	}

	return TRUE;

err:
	g_set_error (&task->err, rspamd_protocol_quark(), 400, "invalid command");

	return FALSE;
}

static void
rspamd_protocol_process_recipients (struct rspamd_task *task,
		const rspamd_ftok_t *hdr)
{
	enum {
		skip_spaces,
		quoted_string,
		normal_string,
	} state = skip_spaces;
	const gchar *p, *end, *start_addr;
	struct rspamd_email_address *addr;

	p = hdr->begin;
	end = hdr->begin + hdr->len;
	start_addr = NULL;

	while (p < end) {
		switch (state) {
		case skip_spaces:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else if (*p == '"') {
				start_addr = p;
				p ++;
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
				p ++;
			}
			else if (*p == '\\') {
				/* Quoted pair */
				p += 2;
			}
			else {
				p ++;
			}
			break;
		case normal_string:
			if (*p == '"') {
				state = quoted_string;
				p ++;
			}
			else if (*p == ',' && start_addr != NULL && p > start_addr) {
				/* We have finished address, check what we have */
				addr = rspamd_email_address_from_smtp (start_addr,
						p - start_addr);

				if (addr) {
					if (task->rcpt_envelope == NULL) {
						task->rcpt_envelope = g_ptr_array_sized_new (
								2);
					}

					g_ptr_array_add (task->rcpt_envelope, addr);
				}
				else {
					msg_err_protocol ("bad rcpt address: '%*s'",
							(int)(p - start_addr), start_addr);
					task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
				}
				start_addr = NULL;
				p ++;
				state = skip_spaces;
			}
			else {
				p ++;
			}
			break;
		}
	}

	/* Check remainder */
	if (start_addr && p > start_addr) {
		switch (state) {
		case normal_string:
			addr = rspamd_email_address_from_smtp (start_addr, end - start_addr);

			if (addr) {
				if (task->rcpt_envelope == NULL) {
					task->rcpt_envelope = g_ptr_array_sized_new (
							2);
				}

				g_ptr_array_add (task->rcpt_envelope, addr);
			}
			else {
				msg_err_protocol ("bad rcpt address: '%*s'",
						(int)(end - start_addr), start_addr);
				task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
			}
			break;
		case skip_spaces:
			/* Do nothing */
			break;
		case quoted_string:
		default:
			msg_err_protocol ("bad state when parsing rcpt address: '%*s'",
					(int)(end - start_addr), start_addr);
			task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
		}
	}
}

#define COMPARE_FLAG_LIT(lit) (len == sizeof(lit) - 1 && memcmp ((lit), str, len) == 0)
#define CHECK_PROTOCOL_FLAG(lit, fl) do { \
	if (!known && COMPARE_FLAG_LIT(lit)) { \
		task->protocol_flags |= (fl); \
		known = TRUE; \
		msg_debug_protocol ("add protocol flag %s", lit); \
	} \
} while (0)
#define CHECK_TASK_FLAG(lit, fl) do { \
	if (!known && COMPARE_FLAG_LIT(lit)) { \
		task->flags |= (fl); \
		known = TRUE; \
		msg_debug_protocol ("add task flag %s", lit); \
	} \
} while (0)

static void
rspamd_protocol_handle_flag (struct rspamd_task *task, const gchar *str,
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
		msg_warn_protocol ("unknown flag: %*s", (gint)len, str);
	}
}

#undef COMPARE_FLAG
#undef CHECK_PROTOCOL_FLAG

static void
rspamd_protocol_process_flags (struct rspamd_task *task, const rspamd_ftok_t *hdr)
{
	enum {
		skip_spaces,
		read_flag,
	} state = skip_spaces;
	const gchar *p, *end, *start;

	p = hdr->begin;
	end = hdr->begin + hdr->len;
	start = NULL;

	while (p < end) {
		switch (state) {
		case skip_spaces:
			if (g_ascii_isspace (*p)) {
				p ++;
			}
			else {
				state = read_flag;
				start = p;
			}
			break;
		case read_flag:
			if (*p == ',') {
				if (p > start) {
					rspamd_protocol_handle_flag (task, start, p - start);
				}
				start = NULL;
				state = skip_spaces;
				p ++;
			}
			else {
				p ++;
			}
			break;
		}
	}

	/* Check remainder */
	if (start && end > start && state == read_flag) {
		rspamd_protocol_handle_flag (task, start, end - start);
	}
}

#define IF_HEADER(name) \
	srch.begin = (name); \
	srch.len = sizeof (name) - 1; \
	if (rspamd_ftok_casecmp (hn_tok, &srch) == 0)

gboolean
rspamd_protocol_handle_headers (struct rspamd_task *task,
	struct rspamd_http_message *msg)
{
	rspamd_ftok_t *hn_tok, *hv_tok, srch;
	gboolean has_ip = FALSE, seen_settings_header = FALSE;
	struct rspamd_http_header *header, *h;
	gchar *ntok;

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
				IF_HEADER (DELIVER_TO_HEADER) {
					task->deliver_to = rspamd_protocol_escape_braces (task, hv_tok);
					msg_debug_protocol ("read deliver-to header, value: %s",
							task->deliver_to);
				}
				else {
					msg_debug_protocol ("wrong header: %T", hn_tok);
				}
				break;
			case 'h':
			case 'H':
				IF_HEADER (HELO_HEADER) {
					task->helo = rspamd_mempool_ftokdup (task->task_pool, hv_tok);
					msg_debug_protocol ("read helo header, value: %s", task->helo);
				}
				IF_HEADER (HOSTNAME_HEADER) {
					task->hostname = rspamd_mempool_ftokdup (task->task_pool,
							hv_tok);
					msg_debug_protocol ("read hostname header, value: %s", task->hostname);
				}
				break;
			case 'f':
			case 'F':
				IF_HEADER (FROM_HEADER) {
					if (hv_tok->len == 0) {
						/* Replace '' with '<>' to fix parsing issue */
						RSPAMD_FTOK_ASSIGN(hv_tok, "<>");
					}
					task->from_envelope = rspamd_email_address_from_smtp (
							hv_tok->begin,
							hv_tok->len);
					msg_debug_protocol ("read from header, value: %T", hv_tok);

					if (!task->from_envelope) {
						msg_err_protocol ("bad from header: '%T'", hv_tok);
						task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
					}
				}
				IF_HEADER (FILENAME_HEADER) {
					task->msg.fpath = rspamd_mempool_ftokdup (task->task_pool,
							hv_tok);
					msg_debug_protocol ("read filename header, value: %s", task->msg.fpath);
				}
				IF_HEADER (FLAGS_HEADER) {
					msg_debug_protocol ("read flags header, value: %T", hv_tok);
					rspamd_protocol_process_flags (task, hv_tok);
				}
				break;
			case 'q':
			case 'Q':
				IF_HEADER (QUEUE_ID_HEADER) {
					task->queue_id = rspamd_mempool_ftokdup (task->task_pool,
							hv_tok);
					msg_debug_protocol ("read queue_id header, value: %s", task->queue_id);
				}
				else {
					msg_debug_protocol ("wrong header: %T", hn_tok);
				}
				break;
			case 'r':
			case 'R':
				IF_HEADER (RCPT_HEADER) {
					rspamd_protocol_process_recipients (task, hv_tok);
					msg_debug_protocol ("read rcpt header, value: %T", hv_tok);
				}
				IF_HEADER (RAW_DATA_HEADER) {
					srch.begin = "yes";
					srch.len = 3;

					msg_debug_protocol ("read raw data header, value: %T", hv_tok);

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->flags &= ~RSPAMD_TASK_FLAG_MIME;
						msg_debug_protocol ("disable mime parsing");
					}
				}
				break;
			case 'i':
			case 'I':
				IF_HEADER (IP_ADDR_HEADER) {
					if (!rspamd_parse_inet_address (&task->from_addr,
							hv_tok->begin, hv_tok->len,
							RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
						msg_err_protocol ("bad ip header: '%T'", hv_tok);
					}
					else {
						msg_debug_protocol ("read IP header, value: %T", hv_tok);
						has_ip = TRUE;
					}
				}
				else {
					msg_debug_protocol ("wrong header: %T", hn_tok);
				}
				break;
			case 'p':
			case 'P':
				IF_HEADER (PASS_HEADER) {
					srch.begin = "all";
					srch.len = 3;

					msg_debug_protocol ("read pass header, value: %T", hv_tok);

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->flags |= RSPAMD_TASK_FLAG_PASS_ALL;
						msg_debug_protocol ("pass all filters");
					}
				}
				IF_HEADER (PROFILE_HEADER) {
					msg_debug_protocol ("read profile header, value: %T", hv_tok);
					task->flags |= RSPAMD_TASK_FLAG_PROFILE;
				}
				break;
			case 's':
			case 'S':
				IF_HEADER (SETTINGS_ID_HEADER) {
					msg_debug_protocol ("read settings-id header, value: %T", hv_tok);
					task->settings_elt = rspamd_config_find_settings_name_ref (
							task->cfg, hv_tok->begin, hv_tok->len);

					if (task->settings_elt == NULL) {
						GString *known_ids = g_string_new (NULL);
						struct rspamd_config_settings_elt *cur;

						DL_FOREACH (task->cfg->setting_ids, cur) {
							rspamd_printf_gstring (known_ids, "%s(%ud);",
									cur->name, cur->id);
						}

						msg_warn_protocol ("unknown settings id: %T(%d); known_ids: %v",
								hv_tok,
								rspamd_config_name_to_id (hv_tok->begin, hv_tok->len),
								known_ids);

						g_string_free (known_ids, TRUE);
					}
					else {
						msg_debug_protocol ("applied settings id %T -> %ud", hv_tok,
								task->settings_elt->id);
					}
				}
				IF_HEADER (SETTINGS_HEADER) {
					msg_debug_protocol ("read settings header, value: %T", hv_tok);
					seen_settings_header = TRUE;
				}
				break;
			case 'u':
			case 'U':
				IF_HEADER (USER_HEADER) {
					/*
					 * We must ignore User header in case of spamc, as SA has
					 * different meaning of this header
					 */
					msg_debug_protocol ("read user header, value: %T", hv_tok);
					if (!RSPAMD_TASK_IS_SPAMC (task)) {
						task->user = rspamd_mempool_ftokdup (task->task_pool,
								hv_tok);
					}
					else {
						msg_info_protocol ("ignore user header: legacy SA protocol");
					}
				}
				IF_HEADER (URLS_HEADER) {
					msg_debug_protocol ("read urls header, value: %T", hv_tok);

					srch.begin = "extended";
					srch.len = 8;

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS;
						msg_debug_protocol ("extended urls information");
					}

					/* TODO: add more formats there */
				}
				IF_HEADER (USER_AGENT_HEADER) {
					msg_debug_protocol ("read user-agent header, value: %T", hv_tok);

					if (hv_tok->len == 6 &&
							rspamd_lc_cmp (hv_tok->begin, "rspamc", 6) == 0) {
						task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_LOCAL_CLIENT;
					}
				}
				break;
			case 'l':
			case 'L':
				IF_HEADER (NO_LOG_HEADER) {
					msg_debug_protocol ("read log header, value: %T", hv_tok);
					srch.begin = "no";
					srch.len = 2;

					if (rspamd_ftok_casecmp (hv_tok, &srch) == 0) {
						task->flags |= RSPAMD_TASK_FLAG_NO_LOG;
					}
				}
				break;
			case 'm':
			case 'M':
				IF_HEADER (MLEN_HEADER) {
					msg_debug_protocol ("read message length header, value: %T",
							hv_tok);
					task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_HAS_CONTROL;
				}
				IF_HEADER (MTA_TAG_HEADER) {
					gchar *mta_tag;
					mta_tag = rspamd_mempool_ftokdup (task->task_pool, hv_tok);
					rspamd_mempool_set_variable (task->task_pool,
							RSPAMD_MEMPOOL_MTA_TAG,
							mta_tag, NULL);
					msg_debug_protocol ("read MTA-Tag header, value: %s", mta_tag);
				}
				IF_HEADER (MTA_NAME_HEADER) {
					gchar *mta_name;
					mta_name = rspamd_mempool_ftokdup (task->task_pool, hv_tok);
					rspamd_mempool_set_variable (task->task_pool,
							RSPAMD_MEMPOOL_MTA_NAME,
							mta_name, NULL);
					msg_debug_protocol ("read MTA-Name header, value: %s", mta_name);
				}
				IF_HEADER (MILTER_HEADER) {
					task->protocol_flags |= RSPAMD_TASK_PROTOCOL_FLAG_MILTER;
					msg_debug_protocol ("read Milter header, value: %T", hv_tok);
				}
				break;
			case 't':
			case 'T':
				IF_HEADER (TLS_CIPHER_HEADER) {
					task->flags |= RSPAMD_TASK_FLAG_SSL;
					msg_debug_protocol ("read TLS cipher header, value: %T", hv_tok);
				}
				break;
			default:
				msg_debug_protocol ("generic header: %T", hn_tok);
				break;
			}

			rspamd_task_add_request_header (task, hn_tok, hv_tok);
		}
	}); /* End of kh_foreach_value */

	if (seen_settings_header && task->settings_elt) {
		msg_warn_task ("ignore settings id %s as settings header is also presented",
				task->settings_elt->name);
		REF_RELEASE (task->settings_elt);

		task->settings_elt = NULL;
	}

	if (!has_ip) {
		task->flags |= RSPAMD_TASK_FLAG_NO_IP;
	}

	return TRUE;
}

#define BOOL_TO_FLAG(val, flags, flag) do {									\
	if ((val)) (flags) |= (flag);											\
	else (flags) &= ~(flag);												\
} while(0)

gboolean
rspamd_protocol_parse_task_flags (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	struct rspamd_rcl_struct_parser *pd = ud;
	gint *target;
	const gchar *key;
	gboolean value;

	target = (gint *)(((gchar *)pd->user_struct) + pd->offset);
	key = ucl_object_key (obj);
	value = ucl_object_toboolean (obj);

	if (key != NULL) {
		if (g_ascii_strcasecmp (key, "pass_all") == 0) {
			BOOL_TO_FLAG (value, *target, RSPAMD_TASK_FLAG_PASS_ALL);
		}
		else if (g_ascii_strcasecmp (key, "no_log") == 0) {
			BOOL_TO_FLAG (value, *target, RSPAMD_TASK_FLAG_NO_LOG);
		}
	}

	return TRUE;
}

static struct rspamd_rcl_section *control_parser = NULL;

static void
rspamd_protocol_control_parser_init (void)
{
	struct rspamd_rcl_section *sub;

	if (control_parser == NULL) {
		sub = rspamd_rcl_add_section (&control_parser,
				"*",
				NULL,
				NULL,
				UCL_OBJECT,
				FALSE,
				TRUE);
		/* Default handlers */
		rspamd_rcl_add_default_handler (sub,
				"ip",
				rspamd_rcl_parse_struct_addr,
				G_STRUCT_OFFSET (struct rspamd_task, from_addr),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"from",
				rspamd_rcl_parse_struct_mime_addr,
				G_STRUCT_OFFSET (struct rspamd_task, from_envelope),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"rcpt",
				rspamd_rcl_parse_struct_mime_addr,
				G_STRUCT_OFFSET (struct rspamd_task, rcpt_envelope),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"helo",
				rspamd_rcl_parse_struct_string,
				G_STRUCT_OFFSET (struct rspamd_task, helo),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"user",
				rspamd_rcl_parse_struct_string,
				G_STRUCT_OFFSET (struct rspamd_task, user),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"pass_all",
				rspamd_protocol_parse_task_flags,
				G_STRUCT_OFFSET (struct rspamd_task, flags),
				0,
				NULL);
		rspamd_rcl_add_default_handler (sub,
				"json",
				rspamd_protocol_parse_task_flags,
				G_STRUCT_OFFSET (struct rspamd_task, flags),
				0,
				NULL);
	}
}

gboolean
rspamd_protocol_handle_control (struct rspamd_task *task,
		const ucl_object_t *control)
{
	GError *err = NULL;

	rspamd_protocol_control_parser_init ();

	if (!rspamd_rcl_parse (control_parser, task->cfg, task, task->task_pool,
			control, &err)) {
		msg_warn_protocol ("cannot parse control block: %e", err);
		g_error_free (err);

		return FALSE;
	}

	return TRUE;
}

gboolean
rspamd_protocol_handle_request (struct rspamd_task *task,
	struct rspamd_http_message *msg)
{
	gboolean ret = TRUE;

	if (msg->method == HTTP_SYMBOLS) {
		msg_debug_protocol ("got legacy SYMBOLS method, enable rspamc protocol workaround");
		task->cmd = CMD_CHECK_RSPAMC;
	}
	else if (msg->method == HTTP_CHECK) {
		msg_debug_protocol ("got legacy CHECK method, enable rspamc protocol workaround");
		task->cmd = CMD_CHECK_RSPAMC;
	}
	else {
		ret = rspamd_protocol_handle_url (task, msg);
	}

	if (msg->flags & RSPAMD_HTTP_FLAG_SPAMC) {
		msg_debug_protocol ("got legacy SA input, enable spamc protocol workaround");
		task->cmd = CMD_CHECK_SPAMC;
	}

	return ret;
}

/* Structure for writing tree data */
struct tree_cb_data {
	ucl_object_t *top;
	khash_t (rspamd_url_host_hash) *seen;
	struct rspamd_task *task;
};

static ucl_object_t *
rspamd_protocol_extended_url (struct rspamd_task *task,
		struct rspamd_url *url,
		const gchar *encoded, gsize enclen)
{
	ucl_object_t *obj, *elt;

	obj = ucl_object_typed_new (UCL_OBJECT);

	elt = ucl_object_fromstring_common (encoded, enclen, 0);
	ucl_object_insert_key (obj, elt, "url", 0, false);

	if (url->tldlen > 0) {
		elt = ucl_object_fromstring_common (rspamd_url_tld_unsafe (url),
				url->tldlen, 0);
		ucl_object_insert_key (obj, elt, "tld", 0, false);
	}
	if (url->hostlen > 0) {
		elt = ucl_object_fromstring_common (rspamd_url_host_unsafe (url),
				url->hostlen, 0);
		ucl_object_insert_key (obj, elt, "host", 0, false);
	}

	ucl_object_t *flags = ucl_object_typed_new (UCL_ARRAY);

	for (unsigned int i = 0; i < RSPAMD_URL_MAX_FLAG_SHIFT; i ++) {
		if (url->flags & (1u << i)) {
			ucl_object_t *fl = ucl_object_fromstring (rspamd_url_flag_to_string (1u << i));
			ucl_array_append (flags, fl);
		}
	}

	ucl_object_insert_key (obj, flags, "flags", 0, false);

	if (url->linked_url) {
		encoded = rspamd_url_encode (url->linked_url, &enclen, task->task_pool);
		elt = rspamd_protocol_extended_url (task, url->linked_url, encoded,
				enclen);
		ucl_object_insert_key (obj, elt, "linked_url", 0, false);
	}

	return obj;
}

/*
 * Callback for writing urls
 */
static void
urls_protocol_cb (struct rspamd_url *url, struct tree_cb_data *cb)
{
	ucl_object_t *obj;
	struct rspamd_task *task = cb->task;
	const gchar *user_field = "unknown", *encoded = NULL;
	gboolean has_user = FALSE;
	guint len = 0;
	gsize enclen = 0;

	if (!(task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS)) {
		if (url->hostlen > 0) {
			if (rspamd_url_host_set_has (cb->seen, url)) {
				return;
			}

			goffset err_offset;

			if ((err_offset = rspamd_fast_utf8_validate (rspamd_url_host_unsafe (url),
					url->hostlen)) == 0) {
				obj = ucl_object_fromstring_common (rspamd_url_host_unsafe (url),
						url->hostlen, 0);
			}
			else {
				obj = ucl_object_fromstring_common (rspamd_url_host_unsafe (url),
						err_offset - 1, 0);
			}
		}
		else {
			return;
		}

		rspamd_url_host_set_add (cb->seen, url);
	}
	else {
		encoded = rspamd_url_encode (url, &enclen, task->task_pool);
		obj = rspamd_protocol_extended_url (task, url, encoded, enclen);
	}

	ucl_array_append (cb->top, obj);

	if (cb->task->cfg->log_urls) {
		if (task->user) {
			user_field = task->user;
			len = strlen (task->user);
			has_user = TRUE;
		}
		else if (task->from_envelope) {
			user_field = task->from_envelope->addr;
			len = task->from_envelope->addr_len;
		}

		if (!encoded) {
			encoded = rspamd_url_encode (url, &enclen, task->task_pool);
		}

		msg_notice_task_encrypted ("<%s> %s: %*s; ip: %s; URL: %*s",
			MESSAGE_FIELD_CHECK (task, message_id),
			has_user ? "user" : "from",
			len, user_field,
			rspamd_inet_address_to_string (task->from_addr),
			(gint)enclen, encoded);
	}
}

static ucl_object_t *
rspamd_urls_tree_ucl (khash_t (rspamd_url_hash) *set,
		struct rspamd_task *task)
{
	struct tree_cb_data cb;
	ucl_object_t *obj;
	struct rspamd_url *u;

	obj = ucl_object_typed_new (UCL_ARRAY);
	cb.top = obj;
	cb.task = task;
	cb.seen = kh_init (rspamd_url_host_hash);

	kh_foreach_key (set, u, {
		if (!(u->protocol & PROTOCOL_MAILTO)) {
			urls_protocol_cb (u, &cb);
		}
	});

	kh_destroy (rspamd_url_host_hash, cb.seen);

	return obj;
}

static void
emails_protocol_cb (struct rspamd_url *url, struct tree_cb_data *cb)
{
	ucl_object_t *obj;

	if (url->userlen > 0 && url->hostlen > 0) {
		obj = ucl_object_fromlstring (rspamd_url_user_unsafe (url),
				url->userlen + url->hostlen + 1);
		ucl_array_append (cb->top, obj);
	}
}

static ucl_object_t *
rspamd_emails_tree_ucl (khash_t (rspamd_url_hash) *set,
						struct rspamd_task *task)
{
	struct tree_cb_data cb;
	ucl_object_t *obj;
	struct rspamd_url *u;

	obj = ucl_object_typed_new (UCL_ARRAY);
	cb.top = obj;
	cb.task = task;

	kh_foreach_key (set, u, {
		if ((u->protocol & PROTOCOL_MAILTO)) {
			emails_protocol_cb (u, &cb);
		}
	});


	return obj;
}


/* Write new subject */
static const gchar *
rspamd_protocol_rewrite_subject (struct rspamd_task *task)
{
	GString *subj_buf;
	gchar *res;
	const gchar *s, *c, *p;
	gsize slen = 0;

	c = rspamd_mempool_get_variable (task->task_pool, "metric_subject");

	if (c == NULL) {
		c = task->cfg->subject;
	}

	if (c == NULL) {
		c = SPAM_SUBJECT;
	}

	p = c;
	s = MESSAGE_FIELD_CHECK (task, subject);

	if (s) {
		slen = strlen (s);
	}

	subj_buf = g_string_sized_new (strlen (c) + slen);

	while (*p) {
		if (*p == '%') {
			switch (p[1]) {
			case 's':
				g_string_append_len (subj_buf, c, p - c);

				if (s) {
					g_string_append_len (subj_buf, s, slen);
				}
				c = p + 2;
				p += 2;
				break;
			case 'd':
				g_string_append_len (subj_buf, c, p - c);
				rspamd_printf_gstring (subj_buf, "%.2f", task->result->score);
				c = p + 2;
				p += 2;
				break;
			case '%':
				g_string_append_len (subj_buf, c, p - c);
				g_string_append_c (subj_buf, '%');
				c = p + 2;
				p += 2;
				break;
			default:
				p ++; /* Just % something unknown */
				break;
			}
		}
		else {
			p++;
		}
	}

	if (p > c) {
		g_string_append_len (subj_buf, c, p - c);
	}

	res = rspamd_mime_header_encode (subj_buf->str, subj_buf->len);

	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)g_free,
		res);
	g_string_free (subj_buf, TRUE);

	return res;
}

static ucl_object_t *
rspamd_metric_symbol_ucl (struct rspamd_task *task, struct rspamd_symbol_result *sym)
{
	ucl_object_t *obj = NULL, *ar;
	const gchar *description = NULL;
	struct rspamd_symbol_option *opt;

	if (sym->sym != NULL) {
		description = sym->sym->description;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (
			sym->name),	 "name",  0, false);
	ucl_object_insert_key (obj, ucl_object_fromdouble (
			sym->score), "score", 0, false);

	if (task->cmd == CMD_CHECK_V2) {
		if (sym->sym) {
			ucl_object_insert_key (obj, ucl_object_fromdouble (
					sym->sym->score), "metric_score", 0, false);
		}
		else {
			ucl_object_insert_key (obj, ucl_object_fromdouble (0.0),
					"metric_score", 0, false);
		}
	}

	if (description) {
		ucl_object_insert_key (obj, ucl_object_fromstring (description),
				"description", 0, false);
	}

	if (sym->options != NULL) {
		ar = ucl_object_typed_new (UCL_ARRAY);

		DL_FOREACH (sym->opts_head, opt) {
			ucl_array_append (ar, ucl_object_fromstring_common (opt->option,
					opt->optlen, 0));
		}

		ucl_object_insert_key (obj, ar, "options", 0, false);
	}

	return obj;
}

static ucl_object_t *
rspamd_metric_group_ucl (struct rspamd_task *task,
		struct rspamd_symbols_group *gr, gdouble score)
{
	ucl_object_t *obj = NULL;

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromdouble (score),
			"score", 0, false);

	if (gr->description) {
		ucl_object_insert_key (obj, ucl_object_fromstring (gr->description),
				"description", 0, false);
	}

	return obj;
}

static ucl_object_t *
rspamd_scan_result_ucl (struct rspamd_task *task,
						struct rspamd_scan_result *mres, ucl_object_t *top)
{
	struct rspamd_symbol_result *sym;
	gboolean is_spam;
	struct rspamd_action *action;
	ucl_object_t *obj = NULL, *sobj;
	const gchar *subject;
	struct rspamd_passthrough_result *pr = NULL;

	action = rspamd_check_action_metric (task, &pr, NULL);
	is_spam = !(action->flags & RSPAMD_ACTION_HAM);

	if (task->cmd == CMD_CHECK) {
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj,
				ucl_object_frombool (is_spam),
				"is_spam", 0, false);
	}
	else {
		obj = top;
	}

	if (pr && pr->message && !(pr->flags & RSPAMD_PASSTHROUGH_NO_SMTP_MESSAGE)) {
		/* Add smtp message if it does not exists: see #3269 for details */
		if (ucl_object_lookup (task->messages, "smtp_message") == NULL) {
			ucl_object_insert_key (task->messages,
					ucl_object_fromstring_common (pr->message, 0, UCL_STRING_RAW),
					"smtp_message", 0,
					false);
		}
	}

	ucl_object_insert_key (obj,
			ucl_object_frombool (RSPAMD_TASK_IS_SKIPPED (task)),
			"is_skipped", 0, false);

	if (!isnan (mres->score)) {
		ucl_object_insert_key (obj, ucl_object_fromdouble (mres->score),
			"score", 0, false);
	} else {
		ucl_object_insert_key (obj,
			ucl_object_fromdouble (0.0), "score", 0, false);
	}

	ucl_object_insert_key (obj,
			ucl_object_fromdouble (rspamd_task_get_required_score (task, mres)),
			"required_score", 0, false);
	ucl_object_insert_key (obj,
			ucl_object_fromstring (action->name),
			"action", 0, false);

	if (action->action_type == METRIC_ACTION_REWRITE_SUBJECT) {
		subject = rspamd_protocol_rewrite_subject (task);

		if (subject) {
			ucl_object_insert_key (obj, ucl_object_fromstring (subject),
				"subject", 0, false);
		}
	}
	if (action->flags & RSPAMD_ACTION_MILTER) {
		/* Treat milter action specially */
		if (action->action_type == METRIC_ACTION_DISCARD) {
			ucl_object_insert_key (obj, ucl_object_fromstring ("discard"),
					"reject", 0, false);
		}
		else if (action->action_type == METRIC_ACTION_QUARANTINE) {
			ucl_object_insert_key (obj, ucl_object_fromstring ("quarantine"),
					"reject", 0, false);
		}
	}

	/* Now handle symbols */
	if (task->cmd != CMD_CHECK) {
		/* For checkv2 we insert symbols as a separate object */
		obj = ucl_object_typed_new (UCL_OBJECT);
	}

	kh_foreach_value (mres->symbols, sym, {
		if (!(sym->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
			sobj = rspamd_metric_symbol_ucl (task, sym);
			ucl_object_insert_key (obj, sobj, sym->name, 0, false);
		}
	})

	if (task->cmd != CMD_CHECK) {
		/* For checkv2 we insert symbols as a separate object */
		ucl_object_insert_key (top, obj, "symbols", 0, false);
	}
	else {
		/* For legacy check we just insert it as "default" all together */
		ucl_object_insert_key (top, obj, DEFAULT_METRIC, 0, false);
	}

	/* Handle groups if needed */
	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_GROUPS) {
		struct rspamd_symbols_group *gr;
		gdouble gr_score;

		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_reserve (obj, kh_size (mres->sym_groups));

		kh_foreach (mres->sym_groups, gr, gr_score,{
			if (task->cfg->public_groups_only &&
				!(gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)) {
				continue;
			}
			sobj = rspamd_metric_group_ucl (task, gr, gr_score);
			ucl_object_insert_key (obj, sobj, gr->name, 0, false);
		});

		ucl_object_insert_key (top, obj, "groups", 0, false);
	}

	return obj;
}

void
rspamd_ucl_torspamc_output (const ucl_object_t *top,
	rspamd_fstring_t **out)
{
	const ucl_object_t *symbols, *score,
	*required_score, *is_spam, *elt, *cur;
	ucl_object_iter_t iter = NULL;

	score = ucl_object_lookup (top, "score");
	required_score = ucl_object_lookup (top, "required_score");
	is_spam = ucl_object_lookup (top, "is_spam");
	rspamd_printf_fstring (out,
			"Metric: default; %s; %.2f / %.2f / 0.0\r\n",
			ucl_object_toboolean (is_spam) ? "True" : "False",
			ucl_object_todouble (score),
			ucl_object_todouble (required_score));
	elt = ucl_object_lookup (top, "action");
	if (elt != NULL) {
		rspamd_printf_fstring (out, "Action: %s\r\n",
				ucl_object_tostring (elt));
	}

	elt = ucl_object_lookup (top, "subject");
	if (elt != NULL) {
		rspamd_printf_fstring (out, "Subject: %s\r\n",
				ucl_object_tostring (elt));
	}

	symbols = ucl_object_lookup (top, "symbols");

	if (symbols != NULL) {
		iter = NULL;
		while ((elt = ucl_object_iterate (symbols, &iter, true)) != NULL) {
			if (elt->type == UCL_OBJECT) {
				const ucl_object_t *sym_score;
				sym_score = ucl_object_lookup (elt, "score");
				rspamd_printf_fstring (out, "Symbol: %s(%.2f)\r\n",
					ucl_object_key (elt),
					ucl_object_todouble (sym_score));
			}
		}
	}

	elt = ucl_object_lookup (top, "messages");
	if (elt != NULL) {
		iter = NULL;
		while ((cur = ucl_object_iterate (elt, &iter, true)) != NULL) {
			if (cur->type == UCL_STRING) {
				rspamd_printf_fstring (out, "Message: %s\r\n",
						ucl_object_tostring (cur));
			}
		}
	}

	elt = ucl_object_lookup (top, "message-id");
	if (elt != NULL) {
		rspamd_printf_fstring (out, "Message-ID: %s\r\n",
				ucl_object_tostring (elt));
	}
}

void
rspamd_ucl_tospamc_output (const ucl_object_t *top,
	rspamd_fstring_t **out)
{
	const ucl_object_t *symbols, *score,
		*required_score, *is_spam, *elt;
	ucl_object_iter_t iter = NULL;
	rspamd_fstring_t *f;

	score = ucl_object_lookup (top, "score");
	required_score = ucl_object_lookup (top, "required_score");
	is_spam = ucl_object_lookup (top, "is_spam");
	rspamd_printf_fstring (out,
			"Spam: %s ; %.2f / %.2f\r\n\r\n",
			ucl_object_toboolean (is_spam) ? "True" : "False",
			ucl_object_todouble (score),
			ucl_object_todouble (required_score));

	symbols = ucl_object_lookup (top, "symbols");

	if (symbols != NULL) {
		while ((elt = ucl_object_iterate (symbols, &iter, true)) != NULL) {
			if (elt->type == UCL_OBJECT) {
				rspamd_printf_fstring (out, "%s,",
					ucl_object_key (elt));
			}
		}
		/* Ugly hack, but the whole spamc is ugly */
		f = *out;
		if (f->str[f->len - 1] == ',') {
			f->len --;

			*out = rspamd_fstring_append (*out, CRLF, 2);
		}
	}
}

static void
rspamd_protocol_output_profiling (struct rspamd_task *task,
		ucl_object_t *top)
{
	GHashTable *tbl;
	GHashTableIter it;
	gpointer k, v;
	ucl_object_t *prof;
	gdouble val;

	prof = ucl_object_typed_new (UCL_OBJECT);
	tbl = rspamd_mempool_get_variable (task->task_pool, "profile");

	if (tbl) {
		g_hash_table_iter_init (&it, tbl);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			val = *(gdouble *)v;
			ucl_object_insert_key (prof, ucl_object_fromdouble (val),
					(const char *)k, 0, false);
		}
	}

	ucl_object_insert_key (top, prof, "profile", 0, false);
}

ucl_object_t *
rspamd_protocol_write_ucl (struct rspamd_task *task,
		enum rspamd_protocol_flags flags)
{
	ucl_object_t *top = NULL;
	GString *dkim_sig;
	GList *dkim_sigs;
	const ucl_object_t *milter_reply;

	rspamd_task_set_finish_time (task);
	top = ucl_object_typed_new (UCL_OBJECT);

	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)ucl_object_unref, top);

	if (flags & RSPAMD_PROTOCOL_METRICS) {
		rspamd_scan_result_ucl (task, task->result, top);
	}

	if (flags & RSPAMD_PROTOCOL_MESSAGES) {
		if (G_UNLIKELY (task->cfg->compat_messages)) {
			const ucl_object_t *cur;
			ucl_object_t *msg_object;
			ucl_object_iter_t iter = NULL;

			msg_object = ucl_object_typed_new (UCL_ARRAY);

			while ((cur = ucl_object_iterate (task->messages, &iter, true)) != NULL) {
				if (cur->type == UCL_STRING) {
					ucl_array_append (msg_object, ucl_object_ref (cur));
				}
			}

			ucl_object_insert_key (top, msg_object, "messages", 0, false);
		}
		else {
			ucl_object_insert_key (top, ucl_object_ref (task->messages),
					"messages", 0, false);
		}
	}

	if (flags & RSPAMD_PROTOCOL_URLS && task->message) {
		if (kh_size (MESSAGE_FIELD (task, urls)) > 0) {
			ucl_object_insert_key (top,
					rspamd_urls_tree_ucl (MESSAGE_FIELD (task, urls), task),
					"urls", 0, false);
			ucl_object_insert_key (top,
					rspamd_emails_tree_ucl (MESSAGE_FIELD (task, urls), task),
					"emails", 0, false);
		}
	}

	if (flags & RSPAMD_PROTOCOL_EXTRA) {
		if (G_UNLIKELY (RSPAMD_TASK_IS_PROFILING (task))) {
			rspamd_protocol_output_profiling (task, top);
		}
	}

	if (flags & RSPAMD_PROTOCOL_BASIC) {
		ucl_object_insert_key (top,
				ucl_object_fromstring (MESSAGE_FIELD_CHECK (task, message_id)),
				"message-id", 0, false);
		ucl_object_insert_key (top,
				ucl_object_fromdouble (task->time_real_finish - task->task_timestamp),
				"time_real", 0, false);
	}

	if (flags & RSPAMD_PROTOCOL_DKIM) {
		dkim_sigs = rspamd_mempool_get_variable (task->task_pool,
				RSPAMD_MEMPOOL_DKIM_SIGNATURE);

		if (dkim_sigs) {
			if (dkim_sigs->next) {
				/* Multiple DKIM signatures */
				ucl_object_t *ar = ucl_object_typed_new (UCL_ARRAY);

				for (; dkim_sigs != NULL; dkim_sigs = dkim_sigs->next) {
					GString *folded_header;
					dkim_sig = (GString *) dkim_sigs->data;

					if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER ||
						!task->message) {

						folded_header = rspamd_header_value_fold ("DKIM-Signature",
								dkim_sig->str, 80, RSPAMD_TASK_NEWLINES_LF, NULL);
					}
					else {
						folded_header = rspamd_header_value_fold ("DKIM-Signature",
								dkim_sig->str, 80,
								MESSAGE_FIELD (task, nlines_type),
								NULL);
					}

					ucl_array_append (ar,
							ucl_object_fromstring_common (folded_header->str,
									folded_header->len, UCL_STRING_RAW));
					g_string_free (folded_header, TRUE);
				}

				ucl_object_insert_key (top,
						ar,
						"dkim-signature", 0,
						false);
			}
			else {
				/* Single DKIM signature */
				GString *folded_header;
				dkim_sig = (GString *) dkim_sigs->data;

				if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) {
					folded_header = rspamd_header_value_fold ("DKIM-Signature",
							dkim_sig->str, 80, RSPAMD_TASK_NEWLINES_LF, NULL);
				}
				else {
					folded_header = rspamd_header_value_fold ("DKIM-Signature",
							dkim_sig->str, 80, MESSAGE_FIELD (task, nlines_type),
							NULL);
				}

				ucl_object_insert_key (top,
						ucl_object_fromstring_common (folded_header->str,
								folded_header->len, UCL_STRING_RAW),
						"dkim-signature", 0, false);
				g_string_free (folded_header, TRUE);
			}
		}
	}

	if (flags & RSPAMD_PROTOCOL_RMILTER) {
		milter_reply = rspamd_mempool_get_variable (task->task_pool,
				RSPAMD_MEMPOOL_MILTER_REPLY);

		if (milter_reply) {
			if (task->cmd != CMD_CHECK) {
				ucl_object_insert_key (top, ucl_object_ref (milter_reply),
						"milter", 0, false);
			}
			else {
				ucl_object_insert_key (top, ucl_object_ref (milter_reply),
						"rmilter", 0, false);
			}
		}
	}

	return top;
}

void
rspamd_protocol_http_reply (struct rspamd_http_message *msg,
		struct rspamd_task *task, ucl_object_t **pobj)
{
	struct rspamd_scan_result *metric_res;
	const struct rspamd_re_cache_stat *restat;

	ucl_object_t *top = NULL;
	rspamd_fstring_t *reply;
	gint flags = RSPAMD_PROTOCOL_DEFAULT;
	struct rspamd_action *action;

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

	top = rspamd_protocol_write_ucl (task, flags);

	if (pobj) {
		*pobj = top;
	}

	if (!(task->flags & RSPAMD_TASK_FLAG_NO_LOG)) {
		rspamd_roll_history_update (task->worker->srv->history, task);
	}
	else {
		msg_debug_protocol ("skip history update due to no log flag");
	}

	rspamd_task_write_log (task);

	if (task->cfg->log_flags & RSPAMD_LOG_FLAG_RE_CACHE) {
		restat = rspamd_re_cache_get_stat (task->re_rt);
		g_assert (restat != NULL);
		msg_notice_task (
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

	reply = rspamd_fstring_sized_new (1000);

	if (msg->method < HTTP_SYMBOLS && !RSPAMD_TASK_IS_SPAMC (task)) {
		msg_debug_protocol ("writing json reply");
		rspamd_ucl_emit_fstring (top, UCL_EMIT_JSON_COMPACT, &reply);
	}
	else {
		if (RSPAMD_TASK_IS_SPAMC (task)) {
			msg_debug_protocol ("writing spamc legacy reply to client");
			rspamd_ucl_tospamc_output (top, &reply);
		}
		else {
			msg_debug_protocol ("writing rspamc legacy reply to client");
			rspamd_ucl_torspamc_output (top, &reply);
		}
	}

	if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_BODY_BLOCK) {
		/* Check if we need to insert a body block */
		if (task->flags & RSPAMD_TASK_FLAG_MESSAGE_REWRITE) {
			GString *hdr_offset = g_string_sized_new (30);

			rspamd_printf_gstring (hdr_offset, "%z", RSPAMD_FSTRING_LEN (reply));
			rspamd_http_message_add_header (msg, MESSAGE_OFFSET_HEADER,
					hdr_offset->str);
			msg_debug_protocol ("write body block at position %s",
					hdr_offset->str);
			g_string_free (hdr_offset, TRUE);

			/* In case of milter, we append just body, otherwise - full message */
			if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) {
				const gchar *start;
				goffset len, hdr_off;

				start = task->msg.begin;
				len = task->msg.len;

				hdr_off = MESSAGE_FIELD (task, raw_headers_content).len;

				if (hdr_off < len) {
					start += hdr_off;
					len -= hdr_off;

					/* The problem here is that we need not end of headers, we need
					 * start of body.
					 *
					 * Hence, we need to skip one \r\n till there is anything else in
					 * a line.
					 */

					if (*start == '\r' && len > 0) {
						start ++;
						len --;
					}

					if (*start == '\n' && len > 0) {
						start ++;
						len --;
					}

					msg_debug_protocol ("milter version of body block size %d",
							(int)len);
					reply = rspamd_fstring_append (reply, start, len);
				}
			}
			else {
				msg_debug_protocol ("general version of body block size %d",
						(int)task->msg.len);
				reply = rspamd_fstring_append (reply,
						task->msg.begin, task->msg.len);
			}
		}
	}

	if ((task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED) &&
			rspamd_libs_reset_compression (task->cfg->libs_ctx)) {
		/* We can compress output */
		ZSTD_inBuffer zin;
		ZSTD_outBuffer zout;
		ZSTD_CStream *zstream;
		rspamd_fstring_t *compressed_reply;
		gsize r;

		zstream = task->cfg->libs_ctx->out_zstream;
		compressed_reply = rspamd_fstring_sized_new (ZSTD_compressBound (reply->len));
		zin.pos = 0;
		zin.src = reply->str;
		zin.size = reply->len;
		zout.pos = 0;
		zout.dst = compressed_reply->str;
		zout.size = compressed_reply->allocated;

		while (zin.pos < zin.size) {
			r = ZSTD_compressStream (zstream, &zout, &zin);

			if (ZSTD_isError (r)) {
				msg_err_protocol ("cannot compress: %s", ZSTD_getErrorName (r));
				rspamd_fstring_free (compressed_reply);
				rspamd_http_message_set_body_from_fstring_steal (msg, reply);

				goto end;
			}
		}

		ZSTD_flushStream (zstream, &zout);
		r = ZSTD_endStream (zstream, &zout);

		if (ZSTD_isError (r)) {
			msg_err_protocol ("cannot finalize compress: %s", ZSTD_getErrorName (r));
			rspamd_fstring_free (compressed_reply);
			rspamd_http_message_set_body_from_fstring_steal (msg, reply);

			goto end;
		}

		msg_info_protocol ("writing compressed results: %z bytes before "
				"%z bytes after", zin.pos, zout.pos);
		compressed_reply->len = zout.pos;
		rspamd_fstring_free (reply);
		rspamd_http_message_set_body_from_fstring_steal (msg, compressed_reply);
		rspamd_http_message_add_header (msg, COMPRESSION_HEADER, "zstd");

		if (task->cfg->libs_ctx->out_dict &&
				task->cfg->libs_ctx->out_dict->id != 0) {
			gchar dict_str[32];

			rspamd_snprintf (dict_str, sizeof (dict_str), "%ud",
					task->cfg->libs_ctx->out_dict->id);
			rspamd_http_message_add_header (msg, "Dictionary", dict_str);
		}
	}
	else {
		rspamd_http_message_set_body_from_fstring_steal (msg, reply);
	}

end:
	if (!(task->flags & RSPAMD_TASK_FLAG_NO_STAT)) {
		/* Update stat for default metric */

		msg_debug_protocol ("skip stats update due to no_stat flag");
		metric_res = task->result;

		if (metric_res != NULL) {

			action = rspamd_check_action_metric (task, NULL, NULL);
			/* TODO: handle custom actions in stats */
			if (action->action_type == METRIC_ACTION_SOFT_REJECT &&
					(task->flags & RSPAMD_TASK_FLAG_GREYLISTED)) {
				/* Set stat action to greylist to display greylisted messages */
#ifndef HAVE_ATOMIC_BUILTINS
				task->worker->srv->stat->actions_stat[METRIC_ACTION_GREYLIST]++;
#else
				__atomic_add_fetch (&task->worker->srv->stat->actions_stat[METRIC_ACTION_GREYLIST],
						1, __ATOMIC_RELEASE);
#endif
			}
			else if (action->action_type < METRIC_ACTION_MAX) {
#ifndef HAVE_ATOMIC_BUILTINS
				task->worker->srv->stat->actions_stat[action->action_type]++;
#else
				__atomic_add_fetch (&task->worker->srv->stat->actions_stat[action->action_type],
						1, __ATOMIC_RELEASE);
#endif
			}
		}

		/* Increase counters */
#ifndef HAVE_ATOMIC_BUILTINS
		task->worker->srv->stat->messages_scanned++;
#else
		__atomic_add_fetch (&task->worker->srv->stat->messages_scanned,
				1, __ATOMIC_RELEASE);
#endif
	}
}

void
rspamd_protocol_write_log_pipe (struct rspamd_task *task)
{
	struct rspamd_worker_log_pipe *lp;
	struct rspamd_protocol_log_message_sum *ls;
	lua_State *L = task->cfg->lua_state;
	struct rspamd_scan_result *mres;
	struct rspamd_symbol_result *sym;
	gint id, i;
	guint32 n = 0, nextra = 0;
	gsize sz;
	GArray *extra;
	struct rspamd_protocol_log_symbol_result er;
	struct rspamd_task **ptask;

	/* Get extra results from lua plugins */
	extra = g_array_new (FALSE, FALSE, sizeof (er));

	lua_getglobal (L, "rspamd_plugins");
	if (lua_istable (L, -1)) {
		lua_pushnil (L);

		while (lua_next (L, -2)) {
			if (lua_istable (L, -1)) {
				lua_pushvalue (L, -2);
				/* stack:
				 * -1: copy of key
				 * -2: value (module table)
				 * -3: key (module name)
				 * -4: global
				 */
				lua_pushstring (L, "log_callback");
				lua_gettable (L, -3);
				/* stack:
				 * -1: func
				 * -2: copy of key
				 * -3: value (module table)
				 * -3: key (module name)
				 * -4: global
				 */
				if (lua_isfunction (L, -1)) {
					ptask = lua_newuserdata (L, sizeof (*ptask));
					*ptask = task;
					rspamd_lua_setclass (L, "rspamd{task}", -1);
					/* stack:
					 * -1: task
					 * -2: func
					 * -3: key copy
					 * -4: value (module table)
					 * -5: key (module name)
					 * -6: global
					 */
					msg_debug_protocol ("calling for %s", lua_tostring (L, -3));
					if (lua_pcall (L, 1, 1, 0) != 0) {
						msg_info_protocol ("call to log callback %s failed: %s",
								lua_tostring (L, -2), lua_tostring (L, -1));
						lua_pop (L, 1);
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
						if (lua_istable (L, -1)) {
							/* Another iteration */
							lua_pushnil (L);

							while (lua_next (L, -2)) {
								/* stack:
								 * -1: value
								 * -2: key
								 * -3: result table (pcall)
								 * -4: key copy (parent)
								 * -5: value (parent)
								 * -6: key (parent)
								 */
								if (lua_istable (L, -1)) {
									er.id = 0;
									er.score = 0.0;

									lua_rawgeti (L, -1, 1);
									if (lua_isnumber (L, -1)) {
										er.id = lua_tonumber (L, -1);
									}
									lua_rawgeti (L, -2, 2);
									if (lua_isnumber (L, -1)) {
										er.score = lua_tonumber (L, -1);
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
									lua_pop (L, 2); /* Values */
									g_array_append_val (extra, er);
								}

								lua_pop (L, 1); /* Value for lua_next */
							}

							lua_pop (L, 1); /* Table result of pcall */
						}
						else {
							msg_info_protocol ("call to log callback %s returned "
									"wrong type: %s",
									lua_tostring (L, -2),
									lua_typename (L, lua_type (L, -1)));
							lua_pop (L, 1); /* Returned error */
						}
					}
				}
				else {
					lua_pop (L, 1);
					/* stack:
					 * -1: key copy
					 * -2: value
					 * -3: key
					 */
				}
			}

			lua_pop (L, 2); /* Top table + key copy */
		}

		lua_pop (L, 1); /* rspamd_plugins global */
	}
	else {
		lua_pop (L, 1);
	}

	nextra = extra->len;

	LL_FOREACH (task->cfg->log_pipes, lp) {
		if (lp->fd != -1) {
			switch (lp->type) {
			case RSPAMD_LOG_PIPE_SYMBOLS:
				mres = task->result;

				if (mres) {
					n = kh_size (mres->symbols);
					sz = sizeof (*ls) +
							sizeof (struct rspamd_protocol_log_symbol_result) *
							(n + nextra);
					ls = g_malloc0 (sz);

					/* Handle settings id */

					if (task->settings_elt) {
						ls->settings_id = task->settings_elt->id;
					}
					else {
						ls->settings_id = 0;
					}

					ls->score = mres->score;
					ls->required_score = rspamd_task_get_required_score (task,
							mres);
					ls->nresults = n;
					ls->nextra = nextra;

					i = 0;

					kh_foreach_value (mres->symbols, sym, {
						id = rspamd_symcache_find_symbol (task->cfg->cache,
								sym->name);

						if (id >= 0) {
							ls->results[i].id = id;
							ls->results[i].score = sym->score;
						}
						else {
							ls->results[i].id = -1;
							ls->results[i].score = 0.0;
						}

						i ++;
					});

					memcpy (&ls->results[n], extra->data, nextra * sizeof (er));
				}
				else {
					sz = sizeof (*ls);
					ls = g_malloc0 (sz);
					ls->nresults = 0;
				}

				/* We don't really care about return value here */
				if (write (lp->fd, ls, sz) == -1) {
					msg_info_protocol ("cannot write to log pipe: %s",
							strerror (errno));
				}

				g_free (ls);
				break;
			default:
				msg_err_protocol ("unknown log format %d", lp->type);
				break;
			}
		}
	}

	g_array_free (extra, TRUE);
}

void
rspamd_protocol_write_reply (struct rspamd_task *task, ev_tstamp timeout)
{
	struct rspamd_http_message *msg;
	const gchar *ctype = "application/json";
	rspamd_fstring_t *reply;

	msg = rspamd_http_new_message (HTTP_RESPONSE);

	if (rspamd_http_connection_is_encrypted (task->http_conn)) {
		msg_info_protocol ("<%s> writing encrypted reply",
				MESSAGE_FIELD_CHECK (task, message_id));
	}

	/* Compatibility */
	if (task->cmd == CMD_CHECK_RSPAMC) {
		msg->method = HTTP_SYMBOLS;
	}
	else if (task->cmd == CMD_CHECK_SPAMC)  {
		msg->method = HTTP_SYMBOLS;
		msg->flags |= RSPAMD_HTTP_FLAG_SPAMC;
	}

	if (task->err != NULL) {
		msg_debug_protocol ("writing error reply to client");
		ucl_object_t *top = NULL;

		top = ucl_object_typed_new (UCL_OBJECT);
		msg->code = 500 + task->err->code % 100;
		msg->status = rspamd_fstring_new_init (task->err->message,
				strlen (task->err->message));
		ucl_object_insert_key (top, ucl_object_fromstring (task->err->message),
			"error", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromstring (g_quark_to_string (task->err->domain)),
			"error_domain", 0, false);
		reply = rspamd_fstring_sized_new (256);
		rspamd_ucl_emit_fstring (top, UCL_EMIT_JSON_COMPACT, &reply);
		ucl_object_unref (top);

		/* We also need to validate utf8 */
		if (rspamd_fast_utf8_validate (reply->str, reply->len) != 0) {
			gsize valid_len;
			gchar *validated;

			/* We copy reply several times here but it should be a rare case */
			validated = rspamd_str_make_utf_valid (reply->str, reply->len,
					&valid_len, task->task_pool);
			rspamd_http_message_set_body (msg, validated, valid_len);
			rspamd_fstring_free (reply);
		}
		else {
			rspamd_http_message_set_body_from_fstring_steal (msg, reply);
		}
	}
	else {
		msg->status = rspamd_fstring_new_init ("OK", 2);

		switch (task->cmd) {
		case CMD_CHECK:
		case CMD_CHECK_RSPAMC:
		case CMD_CHECK_SPAMC:
		case CMD_SKIP:
		case CMD_CHECK_V2:
			rspamd_protocol_http_reply (msg, task, NULL);
			rspamd_protocol_write_log_pipe (task);
			break;
		case CMD_PING:
			msg_debug_protocol ("writing pong to client");
			rspamd_http_message_set_body (msg, "pong" CRLF, 6);
			ctype = "text/plain";
			break;
		default:
			msg_err_protocol ("BROKEN");
			break;
		}
	}

	ev_now_update (task->event_loop);
	msg->date = ev_time ();

	rspamd_http_connection_reset (task->http_conn);
	rspamd_http_connection_write_message (task->http_conn, msg, NULL,
		ctype, task, timeout);

	task->processed_stages |= RSPAMD_TASK_STAGE_REPLIED;
}
