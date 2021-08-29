#include "config.h"
#include "rspamd.h"
#include "libstat/stat_api.h"
#include "lua/lua_common.h"
#include "tests.h"
#include "contrib/libev/ev.h"

struct rspamd_main             *rspamd_main = NULL;
struct ev_loop              *event_loop = NULL;
worker_t *workers[] = { NULL };

gchar *lua_test = NULL;
gchar *lua_test_case = NULL;
gboolean verbose = FALSE;
gchar *argv0_dirname = NULL;

static GOptionEntry entries[] =
{
	{ "test", 't', 0, G_OPTION_ARG_STRING, &lua_test,
	  "Lua test to run (i.e. selectors.lua)", NULL },
	{ "test-case", 'c', 0, G_OPTION_ARG_STRING, &lua_test_case,
	  "Lua test to run, lua pattern i.e. \"case .* rcpts\"", NULL },
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

int
main (int argc, char **argv)
{
	struct rspamd_config *cfg;
	GOptionContext *context;
	GError *error = NULL;

	rspamd_main = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	memset (rspamd_main, 0, sizeof (struct rspamd_main));
	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);
	cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_DEFAULT);
	cfg->libs_ctx = rspamd_init_libs ();
	rspamd_main->cfg = cfg;
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL, 0);

	g_test_init (&argc, &argv, NULL);

	argv0_dirname = g_path_get_dirname (argv[0]);

	context = g_option_context_new ("- run rspamd test");
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	/* Setup logger */

	/* Setup logger */
	if (verbose || g_test_verbose ()) {
		rspamd_main->logger = rspamd_log_open_emergency (rspamd_main->server_pool,
				RSPAMD_LOG_FLAG_USEC|RSPAMD_LOG_FLAG_ENFORCED|RSPAMD_LOG_FLAG_RSPAMADM);

		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_DEBUG);
	}
	else {
		rspamd_main->logger = rspamd_log_open_emergency (rspamd_main->server_pool,
				RSPAMD_LOG_FLAG_RSPAMADM);
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_MESSAGE);
	}

	rspamd_lua_set_path ((lua_State *)cfg->lua_state, NULL, NULL);
	event_loop = ev_default_loop (EVFLAG_SIGNALFD|EVBACKEND_ALL);
	rspamd_stat_init (cfg, event_loop);
	rspamd_url_init (NULL);

	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);

	g_test_add_func ("/rspamd/mem_pool", rspamd_mem_pool_test_func);
	g_test_add_func ("/rspamd/radix", rspamd_radix_test_func);
	g_test_add_func ("/rspamd/dns", rspamd_dns_test_func);
	g_test_add_func ("/rspamd/dkim", rspamd_dkim_test_func);
	g_test_add_func ("/rspamd/rrd", rspamd_rrd_test_func);
	g_test_add_func ("/rspamd/upstream", rspamd_upstream_test_func);
	g_test_add_func ("/rspamd/shingles", rspamd_shingles_test_func);
	g_test_add_func ("/rspamd/lua", rspamd_lua_test_func);
	g_test_add_func ("/rspamd/cryptobox", rspamd_cryptobox_test_func);
	g_test_add_func ("/rspamd/heap", rspamd_heap_test_func);
	g_test_add_func ("/rspamd/lua_pcall", rspamd_lua_lua_pcall_vs_resume_test_func);

#if 0
	g_test_add_func ("/rspamd/http", rspamd_http_test_func);
	g_test_add_func ("/rspamd/url", rspamd_url_test_func);
	g_test_add_func ("/rspamd/statfile", rspamd_statfile_test_func);
	g_test_add_func ("/rspamd/aio", rspamd_async_test_func);
#endif
	g_test_run ();

	return 0;
}
