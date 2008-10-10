#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../config.h"
#include "../main.h"
#include "../cfg_file.h"
#include "tests.h"

#ifdef HAVE_STRLCPY_H
#include "../strlcpy.c"
#endif

int
main (int argc, char **argv)
{
	g_mem_set_vtable(glib_mem_profiler_table);

	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/rspamd/memcached", rspamd_memcached_test_func);
	g_test_add_func ("/rspamd/mem_pool", rspamd_mem_pool_test_func);
	g_test_add_func ("/rspamd/url", rspamd_url_test_func);

	g_test_run ();
}
