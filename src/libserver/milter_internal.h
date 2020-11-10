/*-
 * Copyright 2017 Vsevolod Stakhov
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

#ifndef RSPAMD_MILTER_INTERNAL_H
#define RSPAMD_MILTER_INTERNAL_H

#include "config.h"
#include "libutil/mem_pool.h"
#include "contrib/libev/ev.h"
#include "khash.h"
#include "libutil/str_util.h"
#include "libutil/libev_helper.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum rspamd_milter_state {
	st_len_1 = 0,
	st_len_2,
	st_len_3,
	st_len_4,
	st_read_cmd,
	st_read_data
};

struct rspamd_milter_parser {
	rspamd_fstring_t *buf;
	goffset pos;
	goffset cmd_start;
	gsize datalen;
	enum rspamd_milter_state state;
	gchar cur_cmd;
};

struct rspamd_milter_outbuf {
	rspamd_fstring_t *buf;
	goffset pos;
	struct rspamd_milter_outbuf *next, *prev;
};

enum rspamd_milter_io_state {
	RSPAMD_MILTER_READ_MORE,
	RSPAMD_MILTER_WRITE_REPLY,
	RSPAMD_MILTER_WANNA_DIE,
	RSPAMD_MILTER_WRITE_AND_DIE,
	RSPAMD_MILTER_PONG_AND_DIE,
};

KHASH_INIT (milter_headers_hash_t, char *, GArray *, true,
		rspamd_strcase_hash, rspamd_strcase_equal);

struct rspamd_milter_private {
	struct rspamd_milter_parser parser;
	struct rspamd_io_ev ev;
	struct rspamd_milter_outbuf *out_chain;
	struct ev_loop *event_loop;
	rspamd_mempool_t *pool;
	khash_t(milter_headers_hash_t) *headers;
	gint cur_hdr;
	rspamd_milter_finish fin_cb;
	rspamd_milter_error err_cb;
	void *ud;
	enum rspamd_milter_io_state state;
	int fd;
	gboolean discard_on_reject;
	gboolean quarantine_on_reject;
	gboolean no_action;
};

enum rspamd_milter_io_cmd {
	RSPAMD_MILTER_CMD_ABORT = 'A', /* Abort */
	RSPAMD_MILTER_CMD_BODY = 'B', /* Body chunk */
	RSPAMD_MILTER_CMD_CONNECT = 'C', /* Connection information */
	RSPAMD_MILTER_CMD_MACRO = 'D', /* Define macro */
	RSPAMD_MILTER_CMD_BODYEOB = 'E', /* final body chunk (end of message) */
	RSPAMD_MILTER_CMD_HELO = 'H', /* HELO/EHLO */
	RSPAMD_MILTER_CMD_QUIT_NC = 'K', /* QUIT but new connection follows */
	RSPAMD_MILTER_CMD_HEADER = 'L', /* Header */
	RSPAMD_MILTER_CMD_MAIL = 'M', /* MAIL from */
	RSPAMD_MILTER_CMD_EOH = 'N', /* EOH */
	RSPAMD_MILTER_CMD_OPTNEG = 'O', /* Option negotiation */
	RSPAMD_MILTER_CMD_QUIT = 'Q', /* QUIT */
	RSPAMD_MILTER_CMD_RCPT = 'R', /* RCPT to */
	RSPAMD_MILTER_CMD_DATA = 'T', /* DATA */
	RSPAMD_MILTER_CMD_UNKNOWN = 'U' /* Any unknown command */
};

/*
 * Protocol flags
 */
#define RSPAMD_MILTER_FLAG_NOUNKNOWN    (1L<<8)    /* filter does not want unknown cmd */
#define RSPAMD_MILTER_FLAG_NODATA        (1L<<9)    /* filter does not want DATA */
#define RSPAMD_MILTER_FLAG_NR_HDR        (1L<<7)    /* filter won't reply for header */
#define RSPAMD_MILTER_FLAG_SKIP        (1L<<10)/* MTA supports SMFIR_SKIP */
#define RSPAMD_MILTER_FLAG_RCPT_REJ    (1L<<11)/* filter wants rejected RCPTs */
#define RSPAMD_MILTER_FLAG_NR_CONN    (1L<<12)/* filter won't reply for connect */
#define RSPAMD_MILTER_FLAG_NR_HELO    (1L<<13)/* filter won't reply for HELO */
#define RSPAMD_MILTER_FLAG_NR_MAIL    (1L<<14)/* filter won't reply for MAIL */
#define RSPAMD_MILTER_FLAG_NR_RCPT    (1L<<15)/* filter won't reply for RCPT */
#define RSPAMD_MILTER_FLAG_NR_DATA    (1L<<16)/* filter won't reply for DATA */
#define RSPAMD_MILTER_FLAG_NR_UNKN    (1L<<17)/* filter won't reply for UNKNOWN */
#define RSPAMD_MILTER_FLAG_NR_EOH    (1L<<18)/* filter won't reply for eoh */
#define RSPAMD_MILTER_FLAG_NR_BODY    (1L<<19)/* filter won't reply for body chunk */

/*
 * For now, we specify that we want to reply just after EOM
 */
#define RSPAMD_MILTER_FLAG_NOREPLY_MASK \
    (RSPAMD_MILTER_FLAG_NR_CONN | RSPAMD_MILTER_FLAG_NR_HELO | \
    RSPAMD_MILTER_FLAG_NR_MAIL | RSPAMD_MILTER_FLAG_NR_RCPT | \
    RSPAMD_MILTER_FLAG_NR_DATA | RSPAMD_MILTER_FLAG_NR_UNKN | \
    RSPAMD_MILTER_FLAG_NR_HDR | RSPAMD_MILTER_FLAG_NR_EOH | \
    RSPAMD_MILTER_FLAG_NR_BODY)

/*
 * Options that the filter may send at initial handshake time, and message
 * modifications that the filter may request at the end of the message body.
 */
#define RSPAMD_MILTER_FLAG_ADDHDRS    (1L<<0)    /* filter may add headers */
#define RSPAMD_MILTER_FLAG_CHGBODY    (1L<<1)    /* filter may replace body */
#define RSPAMD_MILTER_FLAG_ADDRCPT    (1L<<2)    /* filter may add recipients */
#define RSPAMD_MILTER_FLAG_DELRCPT    (1L<<3)    /* filter may delete recipients */
#define RSPAMD_MILTER_FLAG_CHGHDRS    (1L<<4)    /* filter may change/delete headers */
#define RSPAMD_MILTER_FLAG_QUARANTINE    (1L<<5)    /* filter may request quarantine */

#define RSPAMD_MILTER_ACTIONS_MASK \
    (RSPAMD_MILTER_FLAG_ADDHDRS | RSPAMD_MILTER_FLAG_ADDRCPT | \
    RSPAMD_MILTER_FLAG_DELRCPT | RSPAMD_MILTER_FLAG_CHGHDRS | \
    RSPAMD_MILTER_FLAG_CHGBODY | RSPAMD_MILTER_FLAG_QUARANTINE)

enum rspamd_milter_connect_proto {
	RSPAMD_MILTER_CONN_UNKNOWN = 'U',
	RSPAMD_MILTER_CONN_UNIX = 'L',
	RSPAMD_MILTER_CONN_INET = '4',
	RSPAMD_MILTER_CONN_INET6 = '6',
};

/*
 * Rspamd supports just version 6 of the protocol, failing all versions below
 * this one
 */
#define RSPAMD_MILTER_PROTO_VER 6

#define RSPAMD_MILTER_MESSAGE_CHUNK 65536

#define RSPAMD_MILTER_RCODE_REJECT "554"
#define RSPAMD_MILTER_RCODE_TEMPFAIL "451"
#define RSPAMD_MILTER_RCODE_LATER "452"
#define RSPAMD_MILTER_XCODE_REJECT "5.7.1"
#define RSPAMD_MILTER_XCODE_TEMPFAIL "4.7.1"
#define RSPAMD_MILTER_REJECT_MESSAGE "Spam message rejected"
#define RSPAMD_MILTER_QUARANTINE_MESSAGE "Spam message quarantined"
#define RSPAMD_MILTER_TEMPFAIL_MESSAGE "Try again later"
#define RSPAMD_MILTER_SPAM_HEADER "X-Spam"
#define RSPAMD_MILTER_DKIM_HEADER "DKIM-Signature"
#define RSPAMD_MILTER_ACTION_HEADER "X-Rspamd-Action"

#ifdef  __cplusplus
}
#endif

#endif