/* Copyright (c) 2010-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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


#ifndef ROLL_HISTORY_H_
#define ROLL_HISTORY_H_

#include "config.h"
#include "mem_pool.h"

/*
 * Roll history is a special cycled buffer for checked messages, it is designed for writing history messages
 * and displaying them in webui
 */

#define HISTORY_MAX_ID 100
#define HISTORY_MAX_SYMBOLS 200
#define HISTORY_MAX_USER 20
#define HISTORY_MAX_ROWS 200

struct worker_task;

struct roll_history_row {
	struct timeval tv;
	gchar message_id[HISTORY_MAX_ID];
	gchar symbols[HISTORY_MAX_SYMBOLS];
	gchar user[HISTORY_MAX_USER];
#ifdef HAVE_INET_PTON
	struct {
		union {
			struct in_addr in4;
			struct in6_addr in6;
		} d;
		gboolean ipv6;
		gboolean has_addr;
	} from_addr;
#else
	struct in_addr from_addr;
#endif
	gsize len;
	guint scan_time;
	gint action;
	gdouble score;
	gdouble required_score;
	guint8 completed;
};

struct roll_history {
	struct roll_history_row rows[HISTORY_MAX_ROWS];
	gint cur_row;
	memory_pool_t *pool;
	gboolean need_lock;
	memory_pool_mutex_t *mtx;
};

/**
 * Returns new roll history
 * @param pool pool for shared memory
 * @return new structure
 */
struct roll_history* rspamd_roll_history_new (memory_pool_t *pool);

/**
 * Update roll history with data from task
 * @param history roll history object
 * @param task task object
 */
void rspamd_roll_history_update (struct roll_history *history, struct worker_task *task);

/**
 * Load previously saved history from file
 * @param history roll history object
 * @param filename filename to load from
 * @return TRUE if history has been loaded
 */
gboolean rspamd_roll_history_load (struct roll_history *history, const gchar *filename);

/**
 * Save history to file
 * @param history roll history object
 * @param filename filename to load from
 * @return TRUE if history has been saved
 */
gboolean rspamd_roll_history_save (struct roll_history *history, const gchar *filename);

#endif /* ROLL_HISTORY_H_ */
