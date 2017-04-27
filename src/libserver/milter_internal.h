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
#include <event.h>

enum rspamd_milter_state {
	st_read_cmd,
	st_len_1,
	st_len_2,
	st_len_3,
	st_len_4,
	st_read_data
};

struct rspamd_milter_parser {
	rspamd_fstring_t *buf;
	goffset pos;
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
	RSPAMD_MILTER_PROCESS_DATA,
	RSPAMD_MILTER_WRITE_REPLY,
	RSPAMD_MILTER_WANNA_DIE
};

struct rspamd_milter_private {
	struct rspamd_milter_parser parser;
	struct rspamd_milter_outbuf *out_chain;
	struct event ev;
	struct timeval tv;
	struct timeval *ptv;
	struct event_base *ev_base;
	rspamd_milter_finish fin_cb;
	rspamd_milter_error err_cb;
	void *ud;
	enum rspamd_milter_io_state state;
	int fd;
};

#endif
