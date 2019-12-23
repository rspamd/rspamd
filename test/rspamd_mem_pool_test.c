#include "config.h"
#include "mem_pool.h"
#include "tests.h"
#include "unix-std.h"
#include <math.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#define TEST_BUF "test bufffer"
#define TEST2_BUF "test bufffertest bufffer"

void
rspamd_mem_pool_test_func ()
{
	rspamd_mempool_t *pool;
	rspamd_mempool_stat_t st;
	char *tmp, *tmp2, *tmp3;
	pid_t pid;
	int ret;

	pool = rspamd_mempool_new (sizeof (TEST_BUF), NULL, 0);
	tmp = rspamd_mempool_alloc (pool, sizeof (TEST_BUF));
	tmp2 = rspamd_mempool_alloc (pool, sizeof (TEST_BUF) * 2);
	tmp3 = rspamd_mempool_alloc_shared (pool, sizeof (TEST_BUF));

	snprintf (tmp, sizeof (TEST_BUF), "%s", TEST_BUF);
	snprintf (tmp2, sizeof (TEST_BUF) * 2, "%s", TEST2_BUF);
	snprintf (tmp3, sizeof (TEST_BUF), "%s", TEST_BUF);

	g_assert (strncmp (tmp, TEST_BUF, sizeof (TEST_BUF)) == 0);
	g_assert (strncmp (tmp2, TEST2_BUF, sizeof (TEST2_BUF)) == 0);
	g_assert (strncmp (tmp3, TEST_BUF, sizeof (TEST_BUF)) == 0);

	rspamd_mempool_delete (pool);
	rspamd_mempool_stat (&st);

}
