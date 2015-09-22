#include "config.h"
#include "rspamd.h"
#include "tests.h"
#include "ottery.h"

#define TEST_FILENAME "/tmp/rspamd_test.stat"
#define HASHES_NUM 256

void 
rspamd_statfile_test_func ()
{
	/*
	 * XXX: broken, old, need to be rewritten
	 */
#if 0
	statfile_pool_t *pool;
	rspamd_mempool_t *p;
	stat_file_t *st;
	uint32_t random_hashes[HASHES_NUM], i, v;
	time_t now = time (NULL);
	
	p = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	umask (S_IWGRP | S_IWOTH);
	pool = statfile_pool_new (p, TRUE);

	for (i = 0; i < HASHES_NUM; i ++) {
		random_hashes[i] = ottery_rand_uint32 ();
	}

	/* Create new file */
	g_assert (rspamd_mmaped_file_create (pool, TEST_FILENAME, 65535) != -1);
	g_assert ((st = rspamd_mmaped_file_open (pool, TEST_FILENAME, 65535, FALSE)) != NULL);
	
	/* Get and set random blocks */
	rspamd_mmaped_file_lock_file (pool, st);
	for (i = 0; i < HASHES_NUM; i ++) {
		rspamd_mmaped_file_set_block (pool, st, random_hashes[i], random_hashes[i], now, 1.0);
	}
	rspamd_mmaped_file_unlock_file (pool, st);

	for (i = 0; i < HASHES_NUM; i ++) {
		v = rspamd_mmaped_file_get_block (pool, st, random_hashes[i], random_hashes[i], now);
		g_assert(v == 1.0);
	}

	rspamd_mmaped_file_destroy (pool);
#endif
}
