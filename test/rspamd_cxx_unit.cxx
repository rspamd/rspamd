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

#include "config.h"
#include "rspamd.h"
#include <memory>
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

int
main(int argc, char** argv)
{
	std::unique_ptr<struct rspamd_main> rspamd_main{new struct rspamd_main};
	struct rspamd_config *cfg;

	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);
	cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_DEFAULT);
	cfg->libs_ctx = rspamd_init_libs ();
	rspamd_main->cfg = cfg;
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);

	rspamd_main->logger = rspamd_log_open_emergency (rspamd_main->server_pool,
			RSPAMD_LOG_FLAG_RSPAMADM);
	rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_MESSAGE);

	doctest::Context context(argc, argv);
	int res = context.run();

	if(context.shouldExit()) {
		return res;
	}

	return res;
}