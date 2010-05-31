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

static uint64_t                 total_frequency;
static uint32_t                 nsymbols;

int
cache_cmp (const void *p1, const void *p2)
{
	const struct cache_item        *i1 = p1, *i2 = p2;

	return strcmp (i1->s->symbol, i2->s->symbol);
}

int
cache_logic_cmp (const void *p1, const void *p2)
{
	const struct cache_item        *i1 = p1, *i2 = p2;
	double                          w1, w2;
	double                          f1 = 0, f2 = 0;

	if (total_frequency > 0) {
		f1 = ((double)i1->s->frequency * nsymbols) / (double)total_frequency;
		f2 = ((double)i2->s->frequency * nsymbols) / (double)total_frequency;
	}
	w1 = abs (i1->s->weight) * WEIGHT_MULT + f1 * FREQUENCY_MULT + i1->s->avg_time * TIME_MULT;
	w2 = abs (i2->s->weight) * WEIGHT_MULT + f2 * FREQUENCY_MULT + i2->s->avg_time * TIME_MULT;

	return (int)w2 - w1;
}

static GChecksum               *
get_mem_cksum (struct symbols_cache *cache)
{
	GChecksum                      *result;
	GList                          *cur;
	struct cache_item              *item;

	result = g_checksum_new (G_CHECKSUM_SHA1);

	cur = g_list_first (cache->negative_items);
	while (cur) {
		item = cur->data;
		if (item->s->symbol[0] != '\0') {
			g_checksum_update (result, item->s->symbol, strlen (item->s->symbol));
		}
		cur = g_list_next (cur);
	}
	cur = g_list_first (cache->static_items);
	while (cur) {
		item = cur->data;
		if (item->s->symbol[0] != '\0') {
			g_checksum_update (result, item->s->symbol, strlen (item->s->symbol));
		}
		total_frequency += item->s->frequency;
		cur = g_list_next (cur);
	}

	return result;
}

/* Sort items in logical order */
static void
post_cache_init (struct symbols_cache *cache)
{
	GList                          *cur;
	struct cache_item              *item;

	total_frequency = 0;
	nsymbols = cache->used_items;
	cur = g_list_first (cache->negative_items);
	while (cur) {
		item = cur->data;
		total_frequency += item->s->frequency;
		cur = g_list_next (cur);
	}
	cur = g_list_first (cache->static_items);
	while (cur) {
		item = cur->data;
		total_frequency += item->s->frequency;
		cur = g_list_next (cur);
	}

	cache->negative_items = g_list_sort (cache->negative_items, cache_logic_cmp);
	cache->static_items = g_list_sort (cache->static_items, cache_logic_cmp);
}

/* Unmap cache file */
static void
unmap_cache_file (gpointer arg)
{
	struct symbols_cache           *cache = arg;
	
	/* A bit ugly usage */
	munmap (cache->map, cache->used_items * sizeof (struct saved_cache_item));
}

static                          gboolean
mmap_cache_file (struct symbols_cache *cache, int fd, memory_pool_t *pool)
{
	void                           *map;
	int                             i;
	GList                          *cur;
	struct cache_item              *item;

	map = mmap (NULL, cache->used_items * sizeof (struct saved_cache_item), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		msg_err ("cannot mmap cache file: %d, %s", errno, strerror (errno));
		close (fd);
		return FALSE;
	}
	/* Close descriptor as it would never be used */
	close (fd);
	cache->map = map;
	/* Now free old values for saved cache items and fill them with mmapped ones */
	i = 0;
	cur = g_list_first (cache->negative_items);
	while (cur) {
		item = cur->data;
		item->s = ((struct saved_cache_item *)map) + i;
		cur = g_list_next (cur);
		i ++;
	}
	cur = g_list_first (cache->static_items);
	while (cur) {
		item = cur->data;
		item->s = ((struct saved_cache_item *)map) + i;
		cur = g_list_next (cur);
		i ++;
	}

	post_cache_init (cache);

	return TRUE;
}

/* Fd must be opened for writing, after creating file is mmapped */
static                          gboolean
create_cache_file (struct symbols_cache *cache, const char *filename, int fd, memory_pool_t *pool)
{
	GChecksum                      *cksum;
	u_char                         *digest;
	gsize                           cklen;
	GList                          *cur;
	struct cache_item              *item;

	/* Calculate checksum */
	cksum = get_mem_cksum (cache);
	if (cksum == NULL) {
		msg_err ("cannot calculate checksum for symbols");
		close (fd);
		return FALSE;
	}

	cklen = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	digest = g_malloc (cklen);

	g_checksum_get_digest (cksum, digest, &cklen);
	/* Now write data to file */
	cur = g_list_first (cache->negative_items);
	while (cur) {
		item = cur->data;
		if (write (fd, &item->s, sizeof (struct saved_cache_item)) == -1) {
			msg_err ("cannot write to file %d, %s", errno, strerror (errno));
			close (fd);
			g_checksum_free (cksum);
			g_free (digest);
			return FALSE;
		}
		cur = g_list_next (cur);
	}
	cur = g_list_first (cache->static_items);
	while (cur) {
		item = cur->data;
		if (write (fd, &item->s, sizeof (struct saved_cache_item)) == -1) {
			msg_err ("cannot write to file %d, %s", errno, strerror (errno));
			close (fd);
			g_checksum_free (cksum);
			g_free (digest);
			return FALSE;
		}
		cur = g_list_next (cur);
	}
	/* Write checksum */
	if (write (fd, digest, cklen) == -1) {
		msg_err ("cannot write to file %d, %s", errno, strerror (errno));
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
		msg_info ("cannot open file %s, error %d, %s", errno, strerror (errno));
		return FALSE;
	}

	return mmap_cache_file (cache, fd, pool);
}

void
register_symbol (struct symbols_cache **cache, const char *name, double weight, symbol_func_t func, gpointer user_data)
{
	struct cache_item              *item = NULL;
	struct symbols_cache           *pcache = *cache;
	GList                          **target;

	if (*cache == NULL) {
		pcache = g_new0 (struct symbols_cache, 1);
		*cache = pcache;
		pcache->static_pool = memory_pool_new (memory_pool_get_size ());
	}

	
	if (weight > 0) {
		target = &(*cache)->static_items;
	}
	else {
		target = &(*cache)->negative_items;
	}
	
	item = memory_pool_alloc0 (pcache->static_pool, sizeof (struct cache_item));
	item->s = memory_pool_alloc (pcache->static_pool, sizeof (struct saved_cache_item));
	g_strlcpy (item->s->symbol, name, sizeof (item->s->symbol));
	item->func = func;
	item->user_data = user_data;
	item->s->weight = weight;
	pcache->used_items++;
	msg_debug ("used items: %d, added symbol: %s", (*cache)->used_items, name);
	set_counter (item->s->symbol, 0);

	*target = g_list_prepend (*target, item);
}

void
register_dynamic_symbol (struct symbols_cache **cache, const char *name, double weight, symbol_func_t func, 
		gpointer user_data, struct dynamic_map_item *networks, gsize network_count)
{
	struct cache_item              *item = NULL;
	struct symbols_cache           *pcache = *cache;
	GList                         **target, *t;
	gsize                           i;
	uintptr_t                       r;
	uint32_t                        mask = 0xFFFFFFFF;

	if (*cache == NULL) {
		pcache = g_new0 (struct symbols_cache, 1);
		*cache = pcache;
		pcache->static_pool = memory_pool_new (memory_pool_get_size ());
	}
	
	if (pcache->dynamic_pool == NULL) {
		pcache->dynamic_pool = memory_pool_new (memory_pool_get_size ());
	}
	item = memory_pool_alloc0 (pcache->dynamic_pool, sizeof (struct cache_item));
	item->s = memory_pool_alloc (pcache->dynamic_pool, sizeof (struct saved_cache_item));
	g_strlcpy (item->s->symbol, name, sizeof (item->s->symbol));
	item->func = func;
	item->user_data = user_data;
	item->s->weight = weight;
	item->is_dynamic = TRUE;

	pcache->used_items++;
	msg_debug ("used items: %d, added symbol: %s", (*cache)->used_items, name);
	set_counter (item->s->symbol, 0);
	
	if (network_count == 0 || networks == NULL) {
		target = &pcache->dynamic_items;
	}
	else {
		if (pcache->dynamic_map == NULL) {
			pcache->dynamic_map = radix_tree_create ();
		}
		for (i = 0; i < network_count; i ++) {
			mask = mask << (32 - networks[i].mask);
			r = ntohl (networks[i].addr.s_addr & mask);
			if ((r = radix32tree_find (pcache->dynamic_map, r)) != RADIX_NO_VALUE) {
				t = (GList *)((gpointer)r);
				target = &t;
			}
			else {
				t = g_list_prepend (NULL, item);
				memory_pool_add_destructor (pcache->dynamic_pool, (pool_destruct_func)g_list_free, t);
				r = radix32tree_insert (pcache->dynamic_map, ntohl (networks[i].addr.s_addr), mask, (uintptr_t)t);
				if (r == -1) {
					msg_warn ("cannot insert ip to tree: %s, mask %X", inet_ntoa (networks[i].addr), mask);
				}
				else if (r == 1) {
					msg_warn ("ip %s, mask %X, value already exists", inet_ntoa (networks[i].addr), mask);
				}
				return;
			}
		}
	}
	*target = g_list_prepend (*target, item);
}

void
remove_dynamic_items (struct symbols_cache *cache)
{
	if (cache->dynamic_items) {
		g_list_free (cache->dynamic_items);
		cache->dynamic_items = NULL;
	}

	if (cache->dynamic_map) {
		radix_tree_free (cache->dynamic_map);
	}

	/* Do magic */
	memory_pool_delete (cache->dynamic_pool);
	cache->dynamic_pool = NULL;
}

static void
free_cache (gpointer arg)
{
	struct symbols_cache           *cache = arg;
	
	if (cache->map != NULL) {
		unmap_cache_file (cache);
	}

	if (cache->static_items) {
		g_list_free (cache->static_items);
	}
	if (cache->negative_items) {
		g_list_free (cache->negative_items);
	}
	if (cache->dynamic_items) {
		g_list_free (cache->dynamic_items);
	}
	if (cache->dynamic_map) {
		radix_tree_free (cache->dynamic_map);
	}

	memory_pool_delete (cache->static_pool);
	if (cache->dynamic_pool) {
		memory_pool_delete (cache->dynamic_pool);
	}

	g_free (cache);
}

gboolean
init_symbols_cache (memory_pool_t * pool, struct symbols_cache *cache, const char *filename)
{
	struct stat                     st;
	int                             fd;
	GChecksum                      *cksum;
	u_char                         *mem_sum, *file_sum;
	gsize                           cklen;
	gboolean                        res;

	if (cache == NULL) {
		return FALSE;
	}

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
			if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
				msg_info ("cannot create file %s, error %d, %s", filename, errno, strerror (errno));
				return FALSE;
			}
			else {
				return create_cache_file (cache, filename, fd, pool);
			}
		}
		else {
			msg_info ("cannot stat file %s, error %d, %s", filename, errno, strerror (errno));
			return FALSE;
		}
	}
	else {
		if ((fd = open (filename, O_RDWR)) == -1) {
			msg_info ("cannot open file %s, error %d, %s", filename, errno, strerror (errno));
			return FALSE;
		}
	}

	/* Calculate checksum */
	cksum = get_mem_cksum (cache);
	if (cksum == NULL) {
		msg_err ("cannot calculate checksum for symbols");
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
		msg_err ("cannot seek to read checksum, %d, %s", errno, strerror (errno));
		return FALSE;
	}
	file_sum = g_malloc (cklen);
	if (read (fd, file_sum, cklen) == -1) {
		close (fd);
		g_free (mem_sum);
		g_free (file_sum);
		g_checksum_free (cksum);
		msg_err ("cannot read checksum, %d, %s", errno, strerror (errno));
		return FALSE;
	}

	if (memcmp (file_sum, mem_sum, cklen) != 0) {
		close (fd);
		g_free (mem_sum);
		g_free (file_sum);
		g_checksum_free (cksum);
		msg_info ("checksum mismatch, recreating file");
		/* Reopen with rw permissions */
		if ((fd = open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR)) == -1) {
			msg_info ("cannot create file %s, error %d, %s", filename, errno, strerror (errno));
			return FALSE;
		}
		else {
			return create_cache_file (cache, filename, fd, pool);
		}
	}

	g_free (mem_sum);
	g_free (file_sum);
	g_checksum_free (cksum);
	/* MMap cache file and copy saved_cache structures */
	res = mmap_cache_file (cache, fd, pool);
	memory_pool_add_destructor (pool, (pool_destruct_func)free_cache, cache);
	return res;
}

static GList *
check_dynamic_item (struct worker_task *task, struct symbols_cache *cache)
{
	GList                          *res = NULL;
	uintptr_t                       r;

	if (cache->dynamic_map != NULL && task->from_addr.s_addr != INADDR_NONE) {
		if ((r = radix32tree_find (cache->dynamic_map, ntohl (task->from_addr.s_addr))) != RADIX_NO_VALUE) {
			res = (GList *)((gpointer)r);
			return res;
		}
		else {
			return NULL;
		}
	}

	return res;
}

struct symbol_callback_data {
	enum {
		CACHE_STATE_NEGATIVE,
		CACHE_STATE_DYNAMIC_MAP,
		CACHE_STATE_DYNAMIC,
		CACHE_STATE_STATIC
	} state;
	struct cache_item *saved_item;
	GList *list_pointer;
};

gboolean
call_symbol_callback (struct worker_task * task, struct symbols_cache * cache, gpointer *save)
{
	struct timespec                 ts1, ts2;
	uint64_t                        diff;
	struct cache_item              *item = NULL;
	struct symbol_callback_data    *s = *save;

	if (s == NULL) {
		if (cache == NULL) {
			return FALSE;
		}
		if (cache->uses++ >= MAX_USES) {
			msg_info ("resort symbols cache");
			memory_pool_wlock_rwlock (cache->lock);
			cache->uses = 0;
			/* Resort while having write lock */
			post_cache_init (cache);
			memory_pool_wunlock_rwlock (cache->lock);
		}
		s = memory_pool_alloc0 (task->task_pool, sizeof (struct symbol_callback_data));
		*save = s;
		if (cache->negative_items != NULL) {
			s->list_pointer = g_list_first (cache->negative_items);
			s->saved_item = s->list_pointer->data;
			s->state = CACHE_STATE_NEGATIVE;
		}
		else if ((s->list_pointer = check_dynamic_item (task, cache)) || cache->dynamic_items != NULL) {
			if (s->list_pointer == NULL) {
				s->list_pointer = g_list_first (cache->dynamic_items);
				s->saved_item = s->list_pointer->data;
				s->state = CACHE_STATE_DYNAMIC;
			}
			else {
				s->saved_item = s->list_pointer->data;
				s->state = CACHE_STATE_DYNAMIC_MAP;
			}
		}
		else {
			s->state = CACHE_STATE_STATIC;
			s->list_pointer = g_list_first (cache->static_items);
			if (s->list_pointer) {
				s->saved_item = s->list_pointer->data;
			}
			else {
				return FALSE;
			}
		}
		item = s->saved_item;
	}
	else {
		if (cache == NULL) {
			return FALSE;
		}
		switch (s->state) {
			case CACHE_STATE_NEGATIVE:
				s->list_pointer = g_list_next (s->list_pointer);
				if (s->list_pointer == NULL) {
					if ((s->list_pointer = check_dynamic_item (task, cache)) || cache->dynamic_items != NULL) {
						if (s->list_pointer == NULL) {
							s->list_pointer = g_list_first (cache->dynamic_items);
							s->saved_item = s->list_pointer->data;
							s->state = CACHE_STATE_DYNAMIC;
						}
						else {
							s->saved_item = s->list_pointer->data;
							s->state = CACHE_STATE_DYNAMIC_MAP;
						}
					}
					else {
						s->state = CACHE_STATE_STATIC;
						s->list_pointer = g_list_first (cache->static_items);
						if (s->list_pointer) {
							s->saved_item = s->list_pointer->data;
						}
						else {
							return FALSE;
						}
					}
				}
				else {
					s->saved_item = s->list_pointer->data;
				}
				item = s->saved_item;
				break;
			case CACHE_STATE_DYNAMIC_MAP:
				s->list_pointer = g_list_next (s->list_pointer);
				if (s->list_pointer == NULL) {
					s->list_pointer = g_list_first (cache->dynamic_items);
					if (s->list_pointer) {
						s->saved_item = s->list_pointer->data;
						s->state = CACHE_STATE_DYNAMIC;
					}
					else {
						s->state = CACHE_STATE_STATIC;
						s->list_pointer = g_list_first (cache->static_items);
						if (s->list_pointer) {
							s->saved_item = s->list_pointer->data;
						}
						else {
							return FALSE;
						}
					}
				}
				else {
					s->saved_item = s->list_pointer->data;
				}
				item = s->saved_item;
				break;
			case CACHE_STATE_DYNAMIC:
				s->list_pointer = g_list_next (s->list_pointer);
				if (s->list_pointer == NULL) {
					s->state = CACHE_STATE_STATIC;
					s->list_pointer = g_list_first (cache->static_items);
					if (s->list_pointer) {
						s->saved_item = s->list_pointer->data;
					}
					else {
						return FALSE;
					}
				}
				else {
					s->saved_item = s->list_pointer->data;
				}
				item = s->saved_item;
				break;
			case CACHE_STATE_STATIC:
				/* Next pointer */
				s->list_pointer = g_list_next (s->list_pointer);
				if (s->list_pointer) {
					s->saved_item = s->list_pointer->data;
				}
				else {
					return FALSE;
				}
				item = s->saved_item;
				break;
		}
	}
	if (!item) {
		return FALSE;
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

	s->saved_item = item;

	return TRUE;

}
