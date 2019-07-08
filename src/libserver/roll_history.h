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
#ifndef ROLL_HISTORY_H_
#define ROLL_HISTORY_H_

#include "config.h"
#include "mem_pool.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Roll history is a special cycled buffer for checked messages, it is designed for writing history messages
 * and displaying them in webui
 */

#define HISTORY_MAX_ID 256
#define HISTORY_MAX_SYMBOLS 256
#define HISTORY_MAX_USER 32
#define HISTORY_MAX_ADDR 32

struct rspamd_task;
struct rspamd_config;

struct roll_history_row {
	ev_tstamp timestamp;
	gchar message_id[HISTORY_MAX_ID];
	gchar symbols[HISTORY_MAX_SYMBOLS];
	gchar user[HISTORY_MAX_USER];
	gchar from_addr[HISTORY_MAX_ADDR];
	gsize len;
	gdouble scan_time;
	gdouble score;
	gdouble required_score;
	gint action;
	guint completed;
};

struct roll_history {
	struct roll_history_row *rows;
	gboolean disabled;
	guint nrows;
	guint cur_row;
};

/**
 * Returns new roll history
 * @param pool pool for shared memory
 * @return new structure
 */
struct roll_history *rspamd_roll_history_new (rspamd_mempool_t *pool,
											  guint max_rows, struct rspamd_config *cfg);

/**
 * Update roll history with data from task
 * @param history roll history object
 * @param task task object
 */
void rspamd_roll_history_update (struct roll_history *history,
								 struct rspamd_task *task);

/**
 * Load previously saved history from file
 * @param history roll history object
 * @param filename filename to load from
 * @return TRUE if history has been loaded
 */
gboolean rspamd_roll_history_load (struct roll_history *history,
								   const gchar *filename);

/**
 * Save history to file
 * @param history roll history object
 * @param filename filename to load from
 * @return TRUE if history has been saved
 */
gboolean rspamd_roll_history_save (struct roll_history *history,
								   const gchar *filename);

#ifdef  __cplusplus
}
#endif

#endif /* ROLL_HISTORY_H_ */
