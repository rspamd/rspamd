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

#include "rspamd_cxx_unit_utils.hxx"
#include "rspamd_cxx_local_ptr.hxx"
#include "rspamd_cxx_unit_dkim.hxx"

static gboolean verbose = false;
static const GOptionEntry entries[] =
		{
				{"verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
						"Enable verbose logging",                  NULL},
				{NULL,      0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
		};


int
main(int argc, char **argv) {
	struct rspamd_main *rspamd_main;
	rspamd_mempool_t *pool;
	struct rspamd_config *cfg;
	GOptionContext *options_context;

	pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), NULL, 0);
	rspamd_main = (struct rspamd_main *) rspamd_mempool_alloc0(pool, sizeof(*rspamd_main));
	rspamd_main->server_pool = pool;
	cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
	cfg->libs_ctx = rspamd_init_libs();
	rspamd_main->cfg = cfg;
	cfg->cfg_pool = pool;

	options_context = g_option_context_new("- run rspamd cxx test");
	g_option_context_add_main_entries(options_context, entries, NULL);
	g_option_context_set_ignore_unknown_options(options_context, true);
	g_option_context_set_help_enabled(options_context, false);

	GError *error = NULL;

	if (!g_option_context_parse(options_context, &argc, &argv, &error)) {
		fprintf(stderr, "option parsing failed: %s\n", error->message);
		g_option_context_free(options_context);
		exit(1);
	}

	if (verbose) {
		rspamd_main->logger = rspamd_log_open_emergency(rspamd_main->server_pool,
				RSPAMD_LOG_FLAG_USEC | RSPAMD_LOG_FLAG_ENFORCED | RSPAMD_LOG_FLAG_RSPAMADM);

		rspamd_log_set_log_level(rspamd_main->logger, G_LOG_LEVEL_DEBUG);
	}
	else {
		rspamd_main->logger = rspamd_log_open_emergency(rspamd_main->server_pool,
				RSPAMD_LOG_FLAG_RSPAMADM);
		rspamd_log_set_log_level(rspamd_main->logger, G_LOG_LEVEL_MESSAGE);
	}

	doctest::Context context(argc, argv);
	int res = context.run();

	if (context.shouldExit()) {
		return res;
	}

	rspamd_mempool_delete(pool);

	return res;
}