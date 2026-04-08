/*
 * Copyright 2025 Vsevolod Stakhov
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


#include "fuzzy_backend_noop.h"

/*
 * No operations backend (useful for scripts only stuff)
 */

void *rspamd_fuzzy_backend_init_noop(struct rspamd_fuzzy_backend *bk,
									 const ucl_object_t *obj,
									 struct rspamd_config *cfg,
									 GError **err)
{
	/* Return non-NULL to distinguish from error */
	return (void *) (uintptr_t) (-1);
}

void rspamd_fuzzy_backend_check_noop(struct rspamd_fuzzy_backend *bk,
									 const struct rspamd_fuzzy_cmd *cmd,
									 rspamd_fuzzy_check_cb cb, void *ud,
									 void *subr_ud)
{
	struct rspamd_fuzzy_multiflag_result mf_result;

	if (cb) {
		memset(&mf_result, 0, sizeof(mf_result));
		cb(&mf_result, ud);
	}

	return;
}

void rspamd_fuzzy_backend_update_noop(struct rspamd_fuzzy_backend *bk,
									  GArray *updates, const char *src,
									  rspamd_fuzzy_update_cb cb, void *ud,
									  void *subr_ud)
{
	if (cb) {
		cb(TRUE, 0, 0, 0, 0, ud);
	}

	return;
}

void rspamd_fuzzy_backend_count_noop(struct rspamd_fuzzy_backend *bk,
									 rspamd_fuzzy_count_cb cb, void *ud,
									 void *subr_ud)
{
	if (cb) {
		cb(0, ud);
	}

	return;
}

void rspamd_fuzzy_backend_version_noop(struct rspamd_fuzzy_backend *bk,
									   const char *src,
									   rspamd_fuzzy_version_cb cb, void *ud,
									   void *subr_ud)
{
	if (cb) {
		cb(0, ud);
	}

	return;
}

const char *rspamd_fuzzy_backend_id_noop(struct rspamd_fuzzy_backend *bk,
										 void *subr_ud)
{
	return NULL;
}

void rspamd_fuzzy_backend_expire_noop(struct rspamd_fuzzy_backend *bk,
									  void *subr_ud)
{
}

void rspamd_fuzzy_backend_close_noop(struct rspamd_fuzzy_backend *bk,
									 void *subr_ud)
{
}
