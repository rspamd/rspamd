#include "../src/config.h"
#include "../src/main.h"
#include "../src/cfg_file.h"
#include "tests.h"

struct rspamd_main             *rspamd_main = NULL;
struct event_base              *base = NULL;
worker_t *workers[] = { NULL };


int
main (int argc, char **argv)
{
	struct config_file            *cfg;

	g_test_init (&argc, &argv, NULL);

	g_mem_set_vtable (glib_mem_profiler_table);

	rspamd_main = (struct rspamd_main *)g_malloc (sizeof (struct rspamd_main));

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
	g_thread_init (NULL);
#endif

	memset (rspamd_main, 0, sizeof (struct rspamd_main));
	rspamd_main->server_pool = memory_pool_new (memory_pool_get_size ());
	rspamd_main->cfg = (struct config_file *)g_malloc (sizeof (struct config_file));
	cfg = rspamd_main->cfg;
	bzero (cfg, sizeof (struct config_file));
	cfg->cfg_pool = memory_pool_new (memory_pool_get_size ());

	base = event_init ();

	if (g_test_verbose ()) {
		cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		cfg->log_level = G_LOG_LEVEL_INFO;
	}
	/* First set logger to console logger */
	rspamd_set_logger (RSPAMD_LOG_CONSOLE, g_quark_from_static_string("rspamd-test"), rspamd_main);
	(void)open_log (rspamd_main->logger);
	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);

#if 0
	g_test_add_func ("/rspamd/memcached", rspamd_memcached_test_func);
#endif
	g_test_add_func ("/rspamd/rcl", rspamd_rcl_test_func);
	g_test_add_func ("/rspamd/mem_pool", rspamd_mem_pool_test_func);
	g_test_add_func ("/rspamd/fuzzy", rspamd_fuzzy_test_func);
	g_test_add_func ("/rspamd/url", rspamd_url_test_func);
	g_test_add_func ("/rspamd/expression", rspamd_expression_test_func);
	g_test_add_func ("/rspamd/statfile", rspamd_statfile_test_func);
	g_test_add_func ("/rspamd/dns", rspamd_dns_test_func);
	g_test_add_func ("/rspamd/aio", rspamd_async_test_func);
	g_test_add_func ("/rspamd/dkim", rspamd_dkim_test_func);
	g_test_add_func ("/rspamd/rrd", rspamd_rrd_test_func);

	g_test_run ();

	return 0;
}
