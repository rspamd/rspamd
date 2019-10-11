/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "hash.h"
#include "util.h"
#include "khash.h"

/**
 * LRU hashing
 */

static const guint log_base = 10;
static const guint eviction_candidates = 16;
static const gdouble lfu_base_value = 5.0;

struct rspamd_lru_volatile_element_s;

struct rspamd_lru_hash_s {
	guint maxsize;
	guint eviction_min_prio;
	guint eviction_used;
	struct rspamd_lru_element_s **eviction_pool;

	GDestroyNotify value_destroy;
	GDestroyNotify key_destroy;
	GHashFunc hfunc;
	GEqualFunc eqfunc;

	khint_t n_buckets, size, n_occupied, upper_bound;
	khint32_t *flags;
	gpointer *keys;
	struct rspamd_lru_volatile_element_s *vals;
};

enum rspamd_lru_element_flags {
	RSPAMD_LRU_ELEMENT_NORMAL = 0,
	RSPAMD_LRU_ELEMENT_VOLATILE = (1 << 0),
	RSPAMD_LRU_ELEMENT_IMMORTAL = (1 << 1),
};

struct rspamd_lru_element_s {
	guint16 last;
	guint8 lg_usages;
	guint8 eviction_pos;
	guint8 flags;
	gpointer data;
};

struct rspamd_lru_volatile_element_s {
	struct rspamd_lru_element_s e;
	time_t creation_time;
	time_t ttl;
};
typedef struct rspamd_lru_volatile_element_s rspamd_lru_vol_element_t;

#define TIME_TO_TS(t) ((guint16)(((t) / 60) & 0xFFFFU))

static rspamd_lru_vol_element_t *
rspamd_lru_hash_get (const rspamd_lru_hash_t *h, gconstpointer key)
{
	if (h->n_buckets) {
		khint_t k, i, last, mask, step = 0;
		mask = h->n_buckets - 1;
		k = h->hfunc (key);
		i = k & mask;
		last = i;

		while (!__ac_isempty(h->flags, i) &&
			(__ac_isdel(h->flags, i) || !h->eqfunc(h->keys[i], key))) {
			i = (i + (++step)) & mask;
			if (i == last) {
				return NULL;
			}
		}

		return __ac_iseither(h->flags, i) ? NULL : &h->vals[i];
	}

	return NULL;
}

static int
rspamd_lru_hash_resize (rspamd_lru_hash_t *h,
						khint_t new_n_buckets)
{
	/* This function uses 0.25*n_buckets bytes of working space instead of [sizeof(key_t+val_t)+.25]*n_buckets. */
	khint32_t *new_flags = 0;
	khint_t j = 1;

	kroundup32(new_n_buckets);
	if (new_n_buckets < 4) {
		new_n_buckets = 4;
	}

	if (h->size >= (khint_t) (new_n_buckets * __ac_HASH_UPPER + 0.5)) {
		j = 0;
		/* requested size is too small */
	}
	else {
		/* hash table size to be changed (shrink or expand); rehash */
		new_flags = (khint32_t *) g_malloc(__ac_fsize (new_n_buckets) * sizeof (khint32_t));

		if (!new_flags) {
			return -1;
		}

		memset(new_flags, 0xaa, __ac_fsize (new_n_buckets) * sizeof (khint32_t));
		if (h->n_buckets < new_n_buckets) {
			/* expand */
			gpointer *new_keys = (gpointer *) g_realloc((void *) h->keys,
					new_n_buckets * sizeof (gpointer));

			if (!new_keys) {
				g_free(new_flags);
				return -1;
			}

			h->keys = new_keys;
			rspamd_lru_vol_element_t *new_vals =
					(rspamd_lru_vol_element_t *) g_realloc((void *) h->vals,
							new_n_buckets * sizeof (rspamd_lru_vol_element_t));
			if (!new_vals) {
				g_free(new_flags);
				return -1;
			}

			h->vals = new_vals;
		}
		/* Shrink */
	}

	if (j) {
		/* rehashing is needed */
		h->eviction_used = 0;

		for (j = 0; j != h->n_buckets; ++j) {
			if (__ac_iseither(h->flags, j) == 0) {
				gpointer key = h->keys[j];
				rspamd_lru_vol_element_t val;
				khint_t new_mask;
				new_mask = new_n_buckets - 1;
				val = h->vals[j];
				val.e.eviction_pos = (guint8)-1;
				__ac_set_isdel_true(h->flags, j);

				while (1) { /* kick-out process; sort of like in Cuckoo hashing */
					khint_t k, i, step = 0;
					k = h->hfunc(key);
					i = k & new_mask;

					while (!__ac_isempty(new_flags, i)) {
						i = (i + (++step)) & new_mask;
					}

					__ac_set_isempty_false(new_flags, i);

					if (i < h->n_buckets && __ac_iseither(h->flags, i) == 0) {
						/* kick out the existing element */
						{
							gpointer tmp = h->keys[i];
							h->keys[i] = key;
							key = tmp;
						}
						{
							rspamd_lru_vol_element_t tmp = h->vals[i];
							h->vals[i] = val;
							val = tmp;
							val.e.eviction_pos = (guint8)-1;
						}
						__ac_set_isdel_true(h->flags, i);
						/* mark it as deleted in the old hash table */
					} else { /* write the element and jump out of the loop */
						h->keys[i] = key;
						h->vals[i] = val;
						break;
					}
				}
			}
		}

		if (h->n_buckets > new_n_buckets) {
			/* shrink the hash table */
			h->keys = (gpointer *) g_realloc((void *) h->keys,
					new_n_buckets * sizeof (gpointer));
			h->vals = (rspamd_lru_vol_element_t *) g_realloc((void *) h->vals,
					new_n_buckets * sizeof (rspamd_lru_vol_element_t));
		}

		g_free(h->flags); /* free the working space */
		h->flags = new_flags;
		h->n_buckets = new_n_buckets;
		h->n_occupied = h->size;
		h->upper_bound = (khint_t) (h->n_buckets * __ac_HASH_UPPER + 0.5);
	}

	return 0;
}

static rspamd_lru_vol_element_t *
rspamd_lru_hash_put (rspamd_lru_hash_t *h, gpointer key, int *ret)
{
	khint_t x;

	if (h->n_occupied >= h->upper_bound) {
		/* update the hash table */
		if (h->n_buckets > (h->size << 1)) {
			if (rspamd_lru_hash_resize (h, h->n_buckets - 1) < 0) {
				/* clear "deleted" elements */
				*ret = -1;
				return NULL;
			}
		}
		else if (rspamd_lru_hash_resize (h, h->n_buckets + 1) < 0) {
			/* expand the hash table */
			*ret = -1;
			return NULL;
		}
	}

	khint_t k, i, site, last, mask = h->n_buckets - 1, step = 0;
	x = site = h->n_buckets;
	k = h->hfunc(key);
	i = k & mask;

	if (__ac_isempty(h->flags, i)) {
		x = i; /* for speed up */
	}
	else {
		last = i;
		while (!__ac_isempty(h->flags, i) &&
			   (__ac_isdel(h->flags, i) ||
			   !h->eqfunc (h->keys[i], key))) {
			if (__ac_isdel(h->flags, i)) {
				site = i;
			}

			i = (i + (++step)) & mask;

			if (i == last) {
				x = site;
				break;
			}
		}

		if (x == h->n_buckets) {
			if (__ac_isempty(h->flags, i) && site != h->n_buckets) {
				x = site;
			}
			else {
				x = i;
			}
		}
	}

	if (__ac_isempty(h->flags, x)) { /* not present at all */
		h->keys[x] = key;
		__ac_set_isboth_false(h->flags, x);
		++h->size;
		++h->n_occupied;
		*ret = 1;
	}
	else if (__ac_isdel(h->flags, x)) { /* deleted */
		h->keys[x] = key;
		__ac_set_isboth_false(h->flags, x);
		++h->size;
		*ret = 2;
	}
	else {
		/* Don't touch h->keys[x] if present and not deleted */
		*ret = 0;
	}

	return &h->vals[x];
}

static void
rspamd_lru_hash_del (rspamd_lru_hash_t *h, rspamd_lru_vol_element_t *elt)
{
	khint_t x = elt - h->vals;

	if (x != h->n_buckets && !__ac_iseither(h->flags, x)) {
		__ac_set_isdel_true(h->flags, x);
		--h->size;

		if (h->key_destroy) {
			h->key_destroy (h->keys[x]);
		}

		if (h->value_destroy) {
			h->value_destroy (elt->e.data);
		}
	}
}

static void
rspamd_lru_hash_remove_evicted (rspamd_lru_hash_t *hash,
		rspamd_lru_element_t *elt)
{
	guint i;
	rspamd_lru_element_t *cur;

	g_assert (hash->eviction_used > 0);
	g_assert (elt->eviction_pos < hash->eviction_used);

	memmove (&hash->eviction_pool[elt->eviction_pos],
			&hash->eviction_pool[elt->eviction_pos + 1],
			sizeof (rspamd_lru_element_t *) *
					(eviction_candidates - elt->eviction_pos - 1));

	hash->eviction_used--;

	if (hash->eviction_used > 0) {
		/* We also need to update min_prio and renumber eviction list */
		hash->eviction_min_prio = G_MAXUINT;

		for (i = 0; i < hash->eviction_used; i ++) {
			cur = hash->eviction_pool[i];

			if (hash->eviction_min_prio > cur->lg_usages) {
				hash->eviction_min_prio = cur->lg_usages;
			}

			cur->eviction_pos = i;
		}
	}
	else {
		hash->eviction_min_prio = G_MAXUINT;
	}


}

static void
rspamd_lru_hash_update_counter (rspamd_lru_element_t *elt)
{
	guint8 counter = elt->lg_usages;

	if (counter != 255) {
		double r, baseval, p;

		r = rspamd_random_double_fast ();
		baseval = counter - lfu_base_value;

		if (baseval < 0) {
			baseval = 0;
		}

		p = 1.0 / (baseval * log_base + 1);

		if (r < p) {
			elt->lg_usages ++;
		}
	}
}

static inline void
rspamd_lru_hash_decrease_counter (rspamd_lru_element_t *elt, time_t now)
{
	if (now - elt->last > lfu_base_value) {
		/* Penalise counters for outdated records */
		elt->lg_usages /= 2;
	}
}

static gboolean
rspamd_lru_hash_maybe_evict (rspamd_lru_hash_t *hash,
		rspamd_lru_element_t *elt)
{
	guint i;
	rspamd_lru_element_t *cur;

	if (elt->eviction_pos == (guint8)-1) {
		if (hash->eviction_used < eviction_candidates) {
			/* There are free places in eviction pool */
			hash->eviction_pool[hash->eviction_used] = elt;
			elt->eviction_pos = hash->eviction_used;
			hash->eviction_used ++;

			if (hash->eviction_min_prio > elt->lg_usages) {
				hash->eviction_min_prio = elt->lg_usages;
			}

			return TRUE;
		}
		else {
			/* Find any candidate that has higher usage count */
			for (i = 0; i < hash->eviction_used; i ++) {
				cur = hash->eviction_pool[i];

				if (cur->lg_usages > elt->lg_usages) {
					cur->eviction_pos = -1;
					elt->eviction_pos = i;
					hash->eviction_pool[i] = elt;

					if (hash->eviction_min_prio > elt->lg_usages) {
						hash->eviction_min_prio = elt->lg_usages;
					}

					return TRUE;
				}
			}
		}
	}
	else {
		/* Already in the eviction list */
		return TRUE;
	}

	return FALSE;
}

static void
rspamd_lru_hash_remove_node (rspamd_lru_hash_t *hash, rspamd_lru_element_t *elt)
{
	if (elt->eviction_pos != (guint8)-1) {
		rspamd_lru_hash_remove_evicted (hash, elt);
	}

	rspamd_lru_hash_del (hash, (rspamd_lru_vol_element_t *)elt);
}

static void
rspamd_lru_hash_evict (rspamd_lru_hash_t *hash, time_t now)
{
	double r;
	guint i;
	rspamd_lru_element_t *elt = NULL;
	guint nexpired = 0;

	/*
	 * We either evict one node from the eviction list
	 * or, at some probability scan all table and update eviction
	 * list first
	 */
	r = rspamd_random_double_fast ();

	if (r < ((double)eviction_candidates) / hash->maxsize) {
		/* Full hash scan */
		rspamd_lru_vol_element_t *cur;
		rspamd_lru_element_t *selected = NULL;

		kh_foreach_value_ptr (hash, cur, {
			rspamd_lru_element_t *node = &cur->e;

			if (node->flags & RSPAMD_LRU_ELEMENT_IMMORTAL) {
				continue;
			}

			if (node->flags & RSPAMD_LRU_ELEMENT_VOLATILE) {
				/* If element is expired, just remove it */
				if (now - cur->creation_time > cur->ttl) {
					rspamd_lru_hash_remove_node (hash, node);

					nexpired ++;
					continue;
				}
			}
			else {
				rspamd_lru_hash_decrease_counter (node, now);

				if (rspamd_lru_hash_maybe_evict (hash, node)) {
					if (selected && node->lg_usages < selected->lg_usages) {
						selected = node;
					}
					else if (selected == NULL) {
						selected = node;
					}
				}
			}
		});

		if (selected) {
			elt = selected;
		}
	}
	else {
		/* Fast random eviction */
		for (i = 0; i < hash->eviction_used; i ++) {
			elt = hash->eviction_pool[i];

			if (elt->lg_usages <= hash->eviction_min_prio) {
				break;
			}
		}
	}

	/* Evict if nothing else has been cleaned */
	if (elt && nexpired == 0) {
		rspamd_lru_hash_remove_node (hash, elt);
	}
}

rspamd_lru_hash_t *
rspamd_lru_hash_new_full (gint maxsize,
						  GDestroyNotify key_destroy,
						  GDestroyNotify value_destroy,
						  GHashFunc hf,
						  GEqualFunc cmpf)
{
	rspamd_lru_hash_t *h;

	if (maxsize < eviction_candidates * 2) {
		maxsize = eviction_candidates * 2;
	}

	h = g_malloc0 (sizeof (rspamd_lru_hash_t));
	h->hfunc = hf;
	h->eqfunc = cmpf;
	h->eviction_pool = g_malloc0 (sizeof (rspamd_lru_element_t *) *
			eviction_candidates);
	h->maxsize = maxsize;
	h->value_destroy = value_destroy;
	h->key_destroy = key_destroy;
	h->eviction_min_prio = G_MAXUINT;

	/* Preallocate some elements */
	rspamd_lru_hash_resize (h, MIN (h->maxsize, 128));

	return h;
}

rspamd_lru_hash_t *
rspamd_lru_hash_new (gint maxsize,
					 GDestroyNotify key_destroy,
					 GDestroyNotify value_destroy)
{
	return rspamd_lru_hash_new_full (maxsize,
			key_destroy, value_destroy,
			rspamd_strcase_hash, rspamd_strcase_equal);
}

gpointer
rspamd_lru_hash_lookup (rspamd_lru_hash_t *hash, gconstpointer key, time_t now)
{
	rspamd_lru_element_t *res;
	rspamd_lru_vol_element_t *vnode;

	vnode = rspamd_lru_hash_get (hash, (gpointer)key);
	if (vnode != NULL) {
		res = &vnode->e;

		if (res->flags & RSPAMD_LRU_ELEMENT_VOLATILE) {
			/* Check ttl */

			if (now - vnode->creation_time > vnode->ttl) {
				rspamd_lru_hash_remove_node (hash, res);

				return NULL;
			}
		}

		now = TIME_TO_TS(now);
		res->last = MAX (res->last, now);
		rspamd_lru_hash_update_counter (res);
		rspamd_lru_hash_maybe_evict (hash, res);

		return res->data;
	}

	return NULL;
}

gboolean
rspamd_lru_hash_remove (rspamd_lru_hash_t *hash,
		gconstpointer key)
{
	rspamd_lru_vol_element_t *res;

	res = rspamd_lru_hash_get (hash, key);

	if (res != NULL) {
		rspamd_lru_hash_remove_node (hash, &res->e);

		return TRUE;
	}

	return FALSE;
}

void
rspamd_lru_hash_insert (rspamd_lru_hash_t *hash,
						gpointer key,
						gpointer value,
						time_t now,
						guint ttl)
{
	rspamd_lru_element_t *node;
	rspamd_lru_vol_element_t *vnode;
	gint ret;

	vnode = rspamd_lru_hash_put (hash, key, &ret);
	node = &vnode->e;

	if (ret == 0) {
		/* Existing element, be careful about destructors */
		if (hash->value_destroy) {
			/* Remove old data */
			hash->value_destroy (vnode->e.data);
		}

		if (hash->key_destroy) {
			/* Here are dragons! */
			goffset off = vnode - hash->vals;

			hash->key_destroy (hash->keys[off]);
			hash->keys[off] = key;
		}
	}


	if (ttl == 0) {
		node->flags = RSPAMD_LRU_ELEMENT_NORMAL;
	}
	else {
		vnode->creation_time = now;
		vnode->ttl = ttl;
		node->flags = RSPAMD_LRU_ELEMENT_VOLATILE;
	}

	node->data = value;
	node->lg_usages = (guint8)lfu_base_value;
	node->last = TIME_TO_TS (now);
	node->eviction_pos = (guint8)-1;

	if (ret != 0) {
		/* Also need to check maxsize */
		if (kh_size (hash) >= hash->maxsize) {
			node->flags |= RSPAMD_LRU_ELEMENT_IMMORTAL;
			rspamd_lru_hash_evict (hash, now);
			node->flags &= ~RSPAMD_LRU_ELEMENT_IMMORTAL;
		}
	}

	rspamd_lru_hash_maybe_evict (hash, node);
}

void
rspamd_lru_hash_destroy (rspamd_lru_hash_t *hash)
{
	if (hash) {
		if (hash->key_destroy || hash->value_destroy) {
			gpointer k;
			rspamd_lru_vol_element_t cur;

			kh_foreach (hash, k, cur, {
				if (hash->key_destroy) {
					hash->key_destroy (k);
				}
				if (hash->value_destroy) {
					hash->value_destroy (cur.e.data);
				}
			});
		}

		g_free (hash->keys);
		g_free (hash->vals);
		g_free (hash->flags);
		g_free (hash->eviction_pool);
		g_free (hash);
	}
}

gpointer
rspamd_lru_hash_element_data (rspamd_lru_element_t *elt)
{
	return elt->data;
}

int
rspamd_lru_hash_foreach (rspamd_lru_hash_t *h, int it, gpointer *k,
						 gpointer *v)
{
	gint i;
	g_assert (it >= 0);

	for (i = it; i != kh_end (h); ++i) {
		if (!kh_exist (h, i)) {
			continue;
		}

		*k = h->keys[i];
		*v = h->vals[i].e.data;

		break;
	}

	if (i == kh_end (h)) {
		return -1;
	}

	return i + 1;
}


guint
rspamd_lru_hash_size (rspamd_lru_hash_t *hash)
{
	return kh_size (hash);
}

/**
 * Returns hash capacity
 * @param hash hash object
 */
guint
rspamd_lru_hash_capacity (rspamd_lru_hash_t *hash)
{
	return hash->maxsize;
}