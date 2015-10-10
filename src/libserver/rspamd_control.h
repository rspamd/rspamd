/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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

#ifndef RSPAMD_RSPAMD_CONTROL_H
#define RSPAMD_RSPAMD_CONTROL_H

#include "config.h"

struct rspamd_main;
struct rspamd_worker;

enum rspamd_control_type {
	RSPAMD_CONTROL_STAT = 0,
	RSPAMD_CONTROL_RELOAD,
	RSPAMD_CONTROL_MAX
};

struct rspamd_control_command {
	enum rspamd_control_type type;
	union {
		struct {
			guint unused;
		} stat;
		struct {
			guint unused;
		} reload;
	} cmd;
};

struct rspamd_control_reply {
	enum rspamd_control_type type;
	union {
		struct {
			guint conns;
			guint64 uptime;
		} stat;
		struct {
			guint status;
		} reload;
	} reply;
};

typedef gboolean (*rspamd_worker_control_handler) (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		struct rspamd_control_command *cmd,
		gpointer ud);

/**
 * Process client socket connection
 */
void rspamd_control_process_client_socket (struct rspamd_main *rspamd_main,
		gint fd);

/**
 * Register default handlers for a worker
 */
void rspamd_control_worker_add_default_handler (struct rspamd_worker *worker);

/**
 * Register custom handler for a specific control command for this worker
 */
void rspamd_control_worker_add_cmd_handler (struct rspamd_worker *worker,
		enum rspamd_control_type type,
		rspamd_worker_control_handler handler,
		gpointer ud);

#endif
