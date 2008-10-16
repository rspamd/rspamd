#include "../mem_pool.h"
#include "tests.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>

#define TEST_BUF "test bufffer"
#define TEST2_BUF "test bufffertest bufffer"

void
rspamd_mem_pool_test_func ()
{
	memory_pool_t *pool;
	memory_pool_stat_t st;
	char *tmp, *tmp2, *tmp3;
	pid_t pid;
	int ret;

	pool = memory_pool_new (sizeof (TEST_BUF));
	tmp = memory_pool_alloc (pool, sizeof (TEST_BUF));
	tmp2 = memory_pool_alloc (pool, sizeof (TEST_BUF) * 2);
	tmp3 = memory_pool_alloc_shared (pool, sizeof (TEST_BUF));

	snprintf (tmp, sizeof (TEST_BUF), "%s", TEST_BUF);
	snprintf (tmp2, sizeof (TEST_BUF) * 2, "%s", TEST2_BUF);
	snprintf (tmp3, sizeof (TEST_BUF), "%s", TEST_BUF);

	g_assert (strncmp (tmp, TEST_BUF, sizeof (TEST_BUF)) == 0);
	g_assert (strncmp (tmp2, TEST2_BUF, sizeof (TEST2_BUF)) == 0);
	g_assert (strncmp (tmp3, TEST_BUF, sizeof (TEST_BUF)) == 0);
	memory_pool_lock_shared (pool, tmp3);
	if ((pid = fork ()) == 0) {
		memory_pool_lock_shared (pool, tmp3);
		g_assert (*tmp3 == 's');
		*tmp3 = 't';
		memory_pool_unlock_shared (pool, tmp3);
		exit (EXIT_SUCCESS);
	}
	else {
		*tmp3 = 's';
		memory_pool_unlock_shared (pool, tmp3);
	}
	wait (&ret);
	g_assert (*tmp3 == 't');
	
	memory_pool_delete (pool);
	memory_pool_stat (&st);
	
	/* Check allocator stat */
	g_assert (st.bytes_allocated == sizeof (TEST_BUF) * 4);
	g_assert (st.chunks_allocated == 2);
	g_assert (st.shared_chunks_allocated == 1);
	g_assert (st.chunks_freed == 3);
}
