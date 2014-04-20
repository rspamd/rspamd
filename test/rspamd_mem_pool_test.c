

#include "../src/config.h"
#include "../src/mem_pool.h"
#include "tests.h"

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

	pool = rspamd_mempool_new (sizeof (TEST_BUF));
	tmp = rspamd_mempool_alloc (pool, sizeof (TEST_BUF));
	tmp2 = rspamd_mempool_alloc (pool, sizeof (TEST_BUF) * 2);
	tmp3 = rspamd_mempool_alloc_shared (pool, sizeof (TEST_BUF));

	snprintf (tmp, sizeof (TEST_BUF), "%s", TEST_BUF);
	snprintf (tmp2, sizeof (TEST_BUF) * 2, "%s", TEST2_BUF);
	snprintf (tmp3, sizeof (TEST_BUF), "%s", TEST_BUF);

	g_assert (strncmp (tmp, TEST_BUF, sizeof (TEST_BUF)) == 0);
	g_assert (strncmp (tmp2, TEST2_BUF, sizeof (TEST2_BUF)) == 0);
	g_assert (strncmp (tmp3, TEST_BUF, sizeof (TEST_BUF)) == 0);
	rspamd_mempool_lock_shared (pool, tmp3);
	if ((pid = fork ()) == 0) {
		rspamd_mempool_lock_shared (pool, tmp3);
		g_assert (*tmp3 == 's');
		*tmp3 = 't';
		rspamd_mempool_unlock_shared (pool, tmp3);
		exit (EXIT_SUCCESS);
	}
	else {
		*tmp3 = 's';
		rspamd_mempool_unlock_shared (pool, tmp3);
	}
	wait (&ret);
	g_assert (*tmp3 == 't');
	
	rspamd_mempool_delete (pool);
	rspamd_mempool_stat (&st);
	
}
