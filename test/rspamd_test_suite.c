#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../src/config.h"
#include "../src/main.h"
#include "../src/cfg_file.h"
#include "tests.h"

int
main (int argc, char **argv)
{
	g_mem_set_vtable(glib_mem_profiler_table);

	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/rspamd/memcached", rspamd_memcached_test_func);
	g_test_add_func ("/rspamd/mem_pool", rspamd_mem_pool_test_func);
	g_test_add_func ("/rspamd/url", rspamd_url_test_func);
	g_test_add_func ("/rspamd/expression", rspamd_expression_test_func);
	g_test_add_func ("/rspamd/statfile", rspamd_statfile_test_func);

	g_test_run ();
}
