#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../src/config.h"
#include "../src/main.h"
#include "../src/statfile.h"
#include "tests.h"

#define TEST_FILENAME "/tmp/rspamd_test.stat"
#define HASHES_NUM 1024

void 
rspamd_statfile_test_func ()
{
	statfile_pool_t *pool;
	uint32_t random_hashes[HASHES_NUM], i, v;
	time_t now;
	
	umask (S_IWGRP | S_IWOTH);
	pool = statfile_pool_new (10 * 1024 * 1024);

	now = time (NULL);
	/* Fill random array */
	srand (now);
	for (i = 0; i < HASHES_NUM; i ++) {
		random_hashes[i] = rand ();
	}

	/* Create new file */
	g_assert (statfile_pool_create (pool, TEST_FILENAME, 65535) != -1);
	g_assert (statfile_pool_open (pool, TEST_FILENAME) != -1);
	
	/* Get and set random blocks */
	statfile_pool_lock_file (pool, TEST_FILENAME);
	for (i = 0; i < HASHES_NUM; i ++) {
		statfile_pool_set_block (pool, TEST_FILENAME, random_hashes[i], random_hashes[i], now, 1.0);
	}
	statfile_pool_unlock_file (pool, TEST_FILENAME);

	for (i = 0; i < HASHES_NUM; i ++) {
		v = statfile_pool_get_block (pool, TEST_FILENAME, random_hashes[i], random_hashes[i], now);
		g_assert(v == 1.0);
	}

	statfile_pool_delete (pool);
	
}
