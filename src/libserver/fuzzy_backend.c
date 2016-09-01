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
#include "fuzzy_backend.h"
#include "fuzzy_backend_sqlite.h"

enum rspamd_fuzzy_backend_type {
	RSPAMD_FUZZY_BACKEND_SQLITE = 0,
	// RSPAMD_FUZZY_BACKEND_REDIS
};

void* rspamd_fuzzy_backend_init_sqlite (struct rspamd_fuzzy_backend *bk,
		const ucl_object_t *obj, GError **err);
void rspamd_fuzzy_backend_check_sqlite (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud,
		void *subr_ud);
void rspamd_fuzzy_backend_update_sqlite (struct rspamd_fuzzy_backend *bk,
		GQueue *updates, const gchar *src,
		rspamd_fuzzy_update_cb cb, void *ud,
		void *subr_ud);
void rspamd_fuzzy_backend_count_sqlite (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud,
		void *subr_ud);
void rspamd_fuzzy_backend_version_sqlite (struct rspamd_fuzzy_backend *bk,
		const gchar *version,
		rspamd_fuzzy_version_cb cb, void *ud,
		void *subr_ud);

struct rspamd_fuzzy_backend_subr {
	void* (*init) (struct rspamd_fuzzy_backend *bk, const ucl_object_t *obj,
			GError **err);
	void (*check) (struct rspamd_fuzzy_backend *bk,
			const struct rspamd_fuzzy_cmd *cmd,
			rspamd_fuzzy_check_cb cb, void *ud,
			void *subr_ud);
	void (*update) (struct rspamd_fuzzy_backend *bk,
			GQueue *updates, const gchar *src,
			rspamd_fuzzy_update_cb cb, void *ud,
			void *subr_ud);
	void (*count) (struct rspamd_fuzzy_backend *bk,
			rspamd_fuzzy_count_cb cb, void *ud,
			void *subr_ud);
	void (*version) (struct rspamd_fuzzy_backend *bk,
			const gchar *version,
			rspamd_fuzzy_version_cb cb, void *ud,
			void *subr_ud);
};

static struct rspamd_fuzzy_backend_subr fuzzy_subrs[] = {
	[RSPAMD_FUZZY_BACKEND_SQLITE] = {
		.init = rspamd_fuzzy_backend_init_sqlite,
		.check = rspamd_fuzzy_backend_check_sqlite,
		.update = rspamd_fuzzy_backend_update_sqlite,
		.count = rspamd_fuzzy_backend_count_sqlite,
		.version = rspamd_fuzzy_backend_version_sqlite
	}
};

struct rspamd_fuzzy_backend {
	enum rspamd_fuzzy_backend_type type;
	gdouble expire;
	struct event_base *ev_base;
	const struct rspamd_fuzzy_backend_subr *subr;
	void *subr_ud;
};

struct rspamd_fuzzy_backend *
rspamd_fuzzy_backend_create (struct event_base *ev_base,
		const ucl_object_t *config, GError **err)
{

}


void
rspamd_fuzzy_backend_check (struct rspamd_fuzzy_backend *bk,
		const struct rspamd_fuzzy_cmd *cmd,
		rspamd_fuzzy_check_cb cb, void *ud);

void
rspamd_fuzzy_backend_process_updates (struct rspamd_fuzzy_backend *bk,
		GQueue *updates, const gchar *src, rspamd_fuzzy_update_cb cb,
		void *ud);


void
rspamd_fuzzy_backend_count (struct rspamd_fuzzy_backend *bk,
		rspamd_fuzzy_count_cb cb, void *ud);

void
rspamd_fuzzy_backend_version (struct rspamd_fuzzy_backend *bk,
		const gchar *src,
		rspamd_fuzzy_version_cb cb, void *ud);
