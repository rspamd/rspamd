#include "../mem_pool.h"
#include "tests.h"

#include <stdio.h>
#include <glib.h>

#define TEST_BUF "test bufffer"
#define TEST2_BUF "test bufffertest bufffer"

void
rspamd_mem_pool_test_func ()
{
	memory_pool_t *pool;
	memory_pool_stat_t st;
	char *tmp, *tmp2;

	pool = memory_pool_new (sizeof (TEST_BUF));
	tmp = memory_pool_alloc (pool, sizeof (TEST_BUF));
	tmp2 = memory_pool_alloc (pool, sizeof (TEST_BUF) * 2);

	snprintf (tmp, sizeof (TEST_BUF), "%s", TEST_BUF);
	snprintf (tmp2, sizeof (TEST_BUF) * 2, "%s", TEST2_BUF);

	g_assert (strncmp (tmp, TEST_BUF, sizeof (TEST_BUF)) == 0);
	g_assert (strncmp (tmp2, TEST2_BUF, sizeof (TEST2_BUF)) == 0);
	
	memory_pool_delete (pool);
	memory_pool_stat (&st);
	
	/* Check allocator stat */
	g_assert (st.bytes_allocated == sizeof (TEST_BUF) * 3);
	g_assert (st.chunks_allocated == 2);
	g_assert (st.chunks_freed == 2);
}
