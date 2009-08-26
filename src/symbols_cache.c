/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "message.h"
#include "symbols_cache.h"
#include "view.h"
#include "cfg_file.h"

#define WEIGHT_MULT 2.0
#define FREQUENCY_MULT 100.0
#define TIME_MULT -1.0

/* After which number of messages try to resort cache */
#define MAX_USES 100
/*
 * Symbols cache utility functions
 */

#define MIN_CACHE 17

uint64_t total_frequency;

int
cache_cmp (const void *p1, const void *p2)
{
	const struct cache_item *i1 = p1, *i2 = p2;
	
	return strcmp (i1->s->symbol, i2->s->symbol);
}

int
cache_logic_cmp (const void *p1, const void *p2)
{
	const struct cache_item *i1 = p1, *i2 = p2;
	double w1, w2;
	int f1 = 0, f2 = 0;
	
	if (total_frequency > 0) {
		f1 = i1->s->frequency / total_frequency;
		f2 = i2->s->frequency / total_frequency;
	}
	w1 = abs (i1->s->weight) * WEIGHT_MULT +
		 f1 * FREQUENCY_MULT + 
		 i1->s->avg_time * TIME_MULT;
	w2 = abs (i2->s->weight) * WEIGHT_MULT +
		 f2 * FREQUENCY_MULT + 
		 i2->s->avg_time * TIME_MULT;
	
	return (int)w2 - w1;
}

static void
grow_cache (struct symbols_cache *cache)
{
	guint old = cache->cur_items, i;
	void *new;

	cache->cur_items = cache->cur_items * 2;
	new = g_new0 (struct cache_item, cache->cur_items);
	memcpy (new, cache->items, old * sizeof (struct cache_item));
	g_free (cache->items);
	cache->items = new;

	/* Create new saved_cache_items */
	for (i = old; i < cache->cur_items; i ++) {
		cache->items[i].s = g_new0 (struct saved_cache_item, 1);
	}
}

static GChecksum *
get_mem_cksum (struct symbols_cache *cache)
{
	int i;
	GChecksum *result;
	
	result = g_checksum_new (G_CHECKSUM_SHA1);

	for (i = 0; i < cache->used_items; i ++) {
		if (cache->items[i].s->symbol[0] != '\0') {
			g_checksum_update (result, cache->items[i].s->symbol, strlen (cache->items[i].s->symbol));
		}
	}

	return result;
}

/* Sort items in logical order */
static void
post_cache_init (struct symbols_cache *cache)
{
	int i;
	
	total_frequency = 0;
	for (i = 0; i < cache->used_items; i ++) {
		total_frequency += cache->items[i].s->frequency;
	}

	qsort (cache->items, cache->used_items, sizeof (struct cache_item), cache_logic_cmp);
}

static gboolean
mmap_cache_file (struct symbols_cache *cache, int fd)
{
	void *map;
	int i;

	map = mmap (NULL, cache->used_items * sizeof (struct saved_cache_item), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		msg_err ("mmap_cache_file: cannot mmap cache file: %d, %s", errno, strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Close descriptor as it would never be used */
	close (fd);
	/* Now free old values for saved cache items and fill them with mmapped ones */
	for (i = 0; i < cache->used_items; i ++) {
		g_free (cache->items[i].s);
		cache->items[i].s = ((struct saved_cache_item *)map) + i;
	}

	post_cache_init (cache);
	return TRUE;
}

/* Fd must be opened for writing, after creating file is mmapped */
static gboolean
create_cache_file (struct symbols_cache *cache, const char *filename, int fd)
{
	int i;
	GChecksum *cksum;
	u_char *digest;
	gsize cklen;

	/* Calculate checksum */
	cksum = get_mem_cksum (cache);
	if (cksum == NULL) {
		msg_err ("load_symbols_cache: cannot calculate checksum for symbols");
		close (fd);
		return FALSE;
	}

	cklen = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	digest = g_malloc (cklen);

	g_checksum_get_digest (cksum, digest, &cklen);
	/* Now write data to file */
	for (i = 0; i < cache->used_items; i ++) {
		if (write (fd, cache->items[i].s, sizeof (struct saved_cache_item)) == -1) {
			msg_err ("create_cache_file: cannot write to file %d, %s", errno, strerror (errno));
			close (fd);
			g_checksum_free (cksum);
			g_free (digest);
			return FALSE;
		}
	}
	/* Write checksum */
	if (write (fd, digest, cklen) == -1) {
		msg_err ("create_cache_file: cannot write to file %d, %s", errno, strerror (errno));
		close (fd);
		g_checksum_free (cksum);
		g_free (digest);
		return FALSE;
	}

	close (fd);
	g_checksum_free (cksum);
	g_free (digest);
	/* Reopen for reading */
	if ((fd = open (filename, O_RDWR)) == -1) {
		msg_info ("create_cache_file: cannot open file %s, error %d, %s", errno, strerror (errno));
		return FALSE;
	}

	return mmap_cache_file (cache, fd);
}

void 
register_symbol (struct symbols_cache **cache, const char *name, double weight, symbol_func_t func, gpointer user_data)
{
	struct cache_item *item = NULL;
	int i;
	
	if (*cache == NULL) {
		*cache = g_new0 (struct symbols_cache, 1);
	}
	if ((*cache)->items == NULL) {
		(*cache)->cur_items = MIN_CACHE;
		(*cache)->used_items = 0;
		(*cache)->items = g_new0 (struct cache_item, (*cache)->cur_items);
		for (i = 0; i < (*cache)->cur_items; i ++) {
			(*cache)->items[i].s = g_new0 (struct saved_cache_item, 1);
		}
	}
	
	if ((*cache)->used_items >= (*cache)->cur_items) {
		grow_cache (*cache);
		/* Call once more */
		register_symbol (cache, name, weight, func, user_data);
		return;
	}

	item = &(*cache)->items[(*cache)->used_items];
	
	g_strlcpy (item->s->symbol, name, sizeof (item->s->symbol));
	item->func = func;
	item->user_data = user_data;
	item->s->weight = weight;
	(*cache)->used_items ++;
	set_counter (item->s->symbol, 0);
}

gboolean 
init_symbols_cache (memory_pool_t *pool, struct symbols_cache *cache, const char *filename)
{
	struct stat st;
	int fd;
	GChecksum *cksum;
	u_char *mem_sum, *file_sum;
	gsize cklen;

	if (cache == NULL || cache->items == NULL) {
		return FALSE;
	}
	
	/* Sort items in cache */
	qsort (cache->items, cache->used_items, sizeof (struct cache_item), cache_cmp);

	/* Init locking */
	cache->lock = memory_pool_get_rwlock (pool);
	
	/* Just in-memory cache */
	if (filename == NULL) {
		post_cache_init (cache);
		return TRUE;
	}

	/* First of all try to stat file */
	if (stat (filename, &st) == -1) {
		/* Check errno */
		if (errno == ENOENT) {
			/* Try to create file */
			if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1 ) {
				msg_info ("load_symbols_cache: cannot create file %s, error %d, %s", filename, errno, strerror (errno));
				return FALSE;
			}
			else {
				return create_cache_file (cache, filename, fd);
			}
		}
		else {
			msg_info ("load_symbols_cache: cannot stat file %s, error %d, %s", filename, errno, strerror (errno));
			return FALSE;
		}
	}
	else {
		if ((fd = open (filename, O_RDWR)) == -1) {
			msg_info ("load_symbols_cache: cannot open file %s, error %d, %s", filename, errno, strerror (errno));
			return FALSE;
		}
	}

	/* Calculate checksum */
	cksum = get_mem_cksum (cache);
	if (cksum == NULL) {
		msg_err ("load_symbols_cache: cannot calculate checksum for symbols");
		close (fd);
		return FALSE;
	}

	cklen = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	mem_sum = g_malloc (cklen);

	g_checksum_get_digest (cksum, mem_sum, &cklen);
	/* Now try to read file sum */
	if (lseek (fd, -(cklen), SEEK_END) == -1) {
		close (fd);
		g_free (mem_sum);
		g_checksum_free (cksum);
		msg_err ("load_symbols_cache: cannot seek to read checksum, %d, %s", errno, strerror (errno));
		return FALSE;
	}
	file_sum = g_malloc (cklen);
	if (read (fd, file_sum, cklen) == -1) {
		close (fd);
		g_free (mem_sum);
		g_free (file_sum);
		g_checksum_free (cksum);
		msg_err ("load_symbols_cache: cannot read checksum, %d, %s", errno, strerror (errno));
		return FALSE;
	}

	if (memcmp (file_sum, mem_sum, cklen) != 0) {
		close (fd);
		g_free (mem_sum);
		g_free (file_sum);
		g_checksum_free (cksum);
		msg_info ("load_symbols_cache: checksum mismatch, recreating file");
		/* Reopen with rw permissions */
		if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1 ) {
			msg_info ("load_symbols_cache: cannot create file %s, error %d, %s", filename, errno, strerror (errno));
			return FALSE;
		}
		else {
			return create_cache_file (cache, filename, fd);
		}
	}

	g_free (mem_sum);
	g_free (file_sum);
	g_checksum_free (cksum);
	/* MMap cache file and copy saved_cache structures */
	return mmap_cache_file (cache, fd);
}

gboolean
call_symbol_callback (struct worker_task *task, struct symbols_cache *cache, struct cache_item **saved_item)
{
	struct timespec ts1, ts2;
	uint64_t diff;
	struct cache_item *item;

	if (*saved_item == NULL) {
		if (cache == NULL) {
			return FALSE;
		}
		if (cache->uses ++ >= MAX_USES) {
			msg_info ("call_symbols_callback: resort symbols cache");
			memory_pool_wlock_rwlock (cache->lock);
			cache->uses = 0;
			/* Resort while having write lock */
			post_cache_init (cache);
			memory_pool_wunlock_rwlock (cache->lock);
		}
		item = &cache->items[0];
	}
	else {
		/* Next pointer */
		if (*saved_item - cache->items >= cache->used_items - 1) {
			/* No more items in cache */
			return FALSE;
		}
		memory_pool_rlock_rwlock (cache->lock);
		item = *saved_item + 1;
		memory_pool_runlock_rwlock (cache->lock);
	}
	if (check_view (task->cfg->views, item->s->symbol, task)) {
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
		clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts1);
#elif defined(HAVE_CLOCK_VIRTUAL)
		clock_gettime (CLOCK_VIRTUAL, &ts1);
#else
		clock_gettime (CLOCK_REALTIME, &ts1);
#endif
		item->func (task, item->user_data);

#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
		clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts2);
#elif defined(HAVE_CLOCK_VIRTUAL)
		clock_gettime (CLOCK_VIRTUAL, &ts2);
#else
		clock_gettime (CLOCK_REALTIME, &ts2);
#endif

		diff = (ts2.tv_sec - ts1.tv_sec) * 1000000 + (ts2.tv_nsec - ts1.tv_nsec) / 1000;
		item->s->avg_time = set_counter (item->s->symbol, diff);
	}

	*saved_item = item;

	return TRUE;

}
