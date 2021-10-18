/*-
 * Copyright 2021 Vsevolod Stakhov
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

/*
 * CDB read only statistics backend
 */

#include "config.h"
#include "stat_internal.h"
#include "contrib/cdb/cdb.h"

namespace rspamd::stat::cdb {

}

/* C exports */
gpointer
rspamd_cdb_init(struct rspamd_stat_ctx* ctx,
						 struct rspamd_config* cfg,
						 struct rspamd_statfile* st)
{
	return nullptr;
}
gpointer
rspamd_cdb_runtime(struct rspamd_task* task,
							struct rspamd_statfile_config* stcf,
							gboolean learn,
							gpointer ctx)
{
	return nullptr;
}
gboolean
rspamd_cdb_process_tokens(struct rspamd_task* task,
								   GPtrArray* tokens,
								   gint id,
								   gpointer ctx)
{
	return false;
}
gboolean
rspamd_cdb_finalize_process(struct rspamd_task* task,
									 gpointer runtime,
									 gpointer ctx)
{
	return false;
}
gboolean
rspamd_cdb_learn_tokens(struct rspamd_task* task,
								 GPtrArray* tokens,
								 gint id,
								 gpointer ctx)
{
	return false;
}
gboolean
rspamd_cdb_finalize_learn(struct rspamd_task* task,
								   gpointer runtime,
								   gpointer ctx,
								   GError** err)
{
	return false;
}

gulong rspamd_cdb_total_learns(struct rspamd_task* task,
							   gpointer runtime,
							   gpointer ctx)
{
	return 0;
}
gulong
rspamd_cdb_inc_learns(struct rspamd_task* task,
							 gpointer runtime,
							 gpointer ctx)
{
	return (gulong)-1;
}
gulong
rspamd_cdb_dec_learns(struct rspamd_task* task,
							 gpointer runtime,
							 gpointer ctx)
{
	return (gulong)-1;
}
gulong
rspamd_cdb_learns(struct rspamd_task* task,
						 gpointer runtime,
						 gpointer ctx)
{
	return 0;
}
ucl_object_t*
rspamd_cdb_get_stat(gpointer runtime, gpointer ctx)
{
	return nullptr;
}
gpointer
rspamd_cdb_load_tokenizer_config(gpointer runtime, gsize* len)
{
	return nullptr;
}
void
rspamd_cdb_close(gpointer ctx)
{

}