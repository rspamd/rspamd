#include "config.h"
#include "rspamd.h"
#include "libstat/stat_api.h"
#include "tests.h"

struct rspamd_main             *rspamd_main = NULL;
struct event_base              *base = NULL;
worker_t *workers[] = { NULL };

int
main (int argc, char **argv)
{
	struct rspamd_config            *cfg;

	rspamd_main = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));
	memset (rspamd_main, 0, sizeof (struct rspamd_main));
	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	cfg = rspamd_config_new ();
	rspamd_main->cfg = cfg;
	cfg->cfg_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	cfg->log_type = RSPAMD_LOG_CONSOLE;
	cfg->log_level = G_LOG_LEVEL_INFO;

	rspamd_set_logger (cfg, g_quark_from_static_string("rspamd-test"),
			&rspamd_main->logger, rspamd_main->server_pool);
	(void)rspamd_log_open (rspamd_main->logger);

	g_test_init (&argc, &argv, NULL);

	cfg->libs_ctx = rspamd_init_libs ();

	base = event_init ();
	rspamd_stat_init (cfg, base);

	if (g_test_verbose ()) {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
		rspamd_set_logger (cfg, g_quark_from_static_string("rspamd-test"),
				&rspamd_main->logger, rspamd_main->server_pool);
		(void)rspamd_log_reopen (rspamd_main->logger);
	}

	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);

	g_test_add_func ("/rspamd/mem_pool", rspamd_mem_pool_test_func);
	g_test_add_func ("/rspamd/radix", rspamd_radix_test_func);
	g_test_add_func ("/rspamd/dns", rspamd_dns_test_func);
	g_test_add_func ("/rspamd/dkim", rspamd_dkim_test_func);
	g_test_add_func ("/rspamd/rrd", rspamd_rrd_test_func);
	g_test_add_func ("/rspamd/upstream", rspamd_upstream_test_func);
	g_test_add_func ("/rspamd/shingles", rspamd_shingles_test_func);
	g_test_add_func ("/rspamd/http", rspamd_http_test_func);
	g_test_add_func ("/rspamd/lua", rspamd_lua_test_func);
	g_test_add_func ("/rspamd/cryptobox", rspamd_cryptobox_test_func);
	g_test_add_func ("/rspamd/heap", rspamd_heap_test_func);

#if 0
	g_test_add_func ("/rspamd/url", rspamd_url_test_func);
	g_test_add_func ("/rspamd/statfile", rspamd_statfile_test_func);
	g_test_add_func ("/rspamd/aio", rspamd_async_test_func);
#endif
	g_test_run ();
	rspamd_regexp_library_finalize ();

	return 0;
}
