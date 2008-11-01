#ifdef _THREAD_SAFE
#include <pthread.h>
#endif

#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <limits.h>
#ifdef WITH_DEBUG
#include <syslog.h>
#endif
#include "upstream.h"

#ifdef WITH_DEBUG
#define msg_debug(args...) syslog(LOG_DEBUG, ##args)
#else
#define msg_debug(args...) do {} while(0)
#endif

#ifdef _THREAD_SAFE
pthread_rwlock_t upstream_mtx = PTHREAD_RWLOCK_INITIALIZER;
#define U_RLOCK() do { pthread_rwlock_rdlock (&upstream_mtx); } while (0)
#define U_WLOCK() do { pthread_rwlock_wrlock (&upstream_mtx); } while (0)
#define U_UNLOCK() do { pthread_rwlock_unlock (&upstream_mtx); } while (0)
#else
#define U_RLOCK() do {} while (0)
#define U_WLOCK() do {} while (0)
#define U_UNLOCK() do {} while (0)
#endif

#define MAX_TRIES 20

/*
 * Poly: 0xedb88320
 * Init: 0x0
 */

static const uint32_t crc32lookup[256] = {
  0x00000000U, 0x77073096U, 0xee0e612cU, 0x990951baU, 0x076dc419U, 0x706af48fU,
  0xe963a535U, 0x9e6495a3U, 0x0edb8832U, 0x79dcb8a4U, 0xe0d5e91eU, 0x97d2d988U,
  0x09b64c2bU, 0x7eb17cbdU, 0xe7b82d07U, 0x90bf1d91U, 0x1db71064U, 0x6ab020f2U,
  0xf3b97148U, 0x84be41deU, 0x1adad47dU, 0x6ddde4ebU, 0xf4d4b551U, 0x83d385c7U,
  0x136c9856U, 0x646ba8c0U, 0xfd62f97aU, 0x8a65c9ecU, 0x14015c4fU, 0x63066cd9U,
  0xfa0f3d63U, 0x8d080df5U, 0x3b6e20c8U, 0x4c69105eU, 0xd56041e4U, 0xa2677172U,
  0x3c03e4d1U, 0x4b04d447U, 0xd20d85fdU, 0xa50ab56bU, 0x35b5a8faU, 0x42b2986cU,
  0xdbbbc9d6U, 0xacbcf940U, 0x32d86ce3U, 0x45df5c75U, 0xdcd60dcfU, 0xabd13d59U,
  0x26d930acU, 0x51de003aU, 0xc8d75180U, 0xbfd06116U, 0x21b4f4b5U, 0x56b3c423U,
  0xcfba9599U, 0xb8bda50fU, 0x2802b89eU, 0x5f058808U, 0xc60cd9b2U, 0xb10be924U,
  0x2f6f7c87U, 0x58684c11U, 0xc1611dabU, 0xb6662d3dU, 0x76dc4190U, 0x01db7106U,
  0x98d220bcU, 0xefd5102aU, 0x71b18589U, 0x06b6b51fU, 0x9fbfe4a5U, 0xe8b8d433U,
  0x7807c9a2U, 0x0f00f934U, 0x9609a88eU, 0xe10e9818U, 0x7f6a0dbbU, 0x086d3d2dU,
  0x91646c97U, 0xe6635c01U, 0x6b6b51f4U, 0x1c6c6162U, 0x856530d8U, 0xf262004eU,
  0x6c0695edU, 0x1b01a57bU, 0x8208f4c1U, 0xf50fc457U, 0x65b0d9c6U, 0x12b7e950U,
  0x8bbeb8eaU, 0xfcb9887cU, 0x62dd1ddfU, 0x15da2d49U, 0x8cd37cf3U, 0xfbd44c65U,
  0x4db26158U, 0x3ab551ceU, 0xa3bc0074U, 0xd4bb30e2U, 0x4adfa541U, 0x3dd895d7U,
  0xa4d1c46dU, 0xd3d6f4fbU, 0x4369e96aU, 0x346ed9fcU, 0xad678846U, 0xda60b8d0U,
  0x44042d73U, 0x33031de5U, 0xaa0a4c5fU, 0xdd0d7cc9U, 0x5005713cU, 0x270241aaU,
  0xbe0b1010U, 0xc90c2086U, 0x5768b525U, 0x206f85b3U, 0xb966d409U, 0xce61e49fU,
  0x5edef90eU, 0x29d9c998U, 0xb0d09822U, 0xc7d7a8b4U, 0x59b33d17U, 0x2eb40d81U,
  0xb7bd5c3bU, 0xc0ba6cadU, 0xedb88320U, 0x9abfb3b6U, 0x03b6e20cU, 0x74b1d29aU,
  0xead54739U, 0x9dd277afU, 0x04db2615U, 0x73dc1683U, 0xe3630b12U, 0x94643b84U,
  0x0d6d6a3eU, 0x7a6a5aa8U, 0xe40ecf0bU, 0x9309ff9dU, 0x0a00ae27U, 0x7d079eb1U,
  0xf00f9344U, 0x8708a3d2U, 0x1e01f268U, 0x6906c2feU, 0xf762575dU, 0x806567cbU,
  0x196c3671U, 0x6e6b06e7U, 0xfed41b76U, 0x89d32be0U, 0x10da7a5aU, 0x67dd4accU,
  0xf9b9df6fU, 0x8ebeeff9U, 0x17b7be43U, 0x60b08ed5U, 0xd6d6a3e8U, 0xa1d1937eU,
  0x38d8c2c4U, 0x4fdff252U, 0xd1bb67f1U, 0xa6bc5767U, 0x3fb506ddU, 0x48b2364bU,
  0xd80d2bdaU, 0xaf0a1b4cU, 0x36034af6U, 0x41047a60U, 0xdf60efc3U, 0xa867df55U,
  0x316e8eefU, 0x4669be79U, 0xcb61b38cU, 0xbc66831aU, 0x256fd2a0U, 0x5268e236U,
  0xcc0c7795U, 0xbb0b4703U, 0x220216b9U, 0x5505262fU, 0xc5ba3bbeU, 0xb2bd0b28U,
  0x2bb45a92U, 0x5cb36a04U, 0xc2d7ffa7U, 0xb5d0cf31U, 0x2cd99e8bU, 0x5bdeae1dU,
  0x9b64c2b0U, 0xec63f226U, 0x756aa39cU, 0x026d930aU, 0x9c0906a9U, 0xeb0e363fU,
  0x72076785U, 0x05005713U, 0x95bf4a82U, 0xe2b87a14U, 0x7bb12baeU, 0x0cb61b38U,
  0x92d28e9bU, 0xe5d5be0dU, 0x7cdcefb7U, 0x0bdbdf21U, 0x86d3d2d4U, 0xf1d4e242U,
  0x68ddb3f8U, 0x1fda836eU, 0x81be16cdU, 0xf6b9265bU, 0x6fb077e1U, 0x18b74777U,
  0x88085ae6U, 0xff0f6a70U, 0x66063bcaU, 0x11010b5cU, 0x8f659effU, 0xf862ae69U,
  0x616bffd3U, 0x166ccf45U, 0xa00ae278U, 0xd70dd2eeU, 0x4e048354U, 0x3903b3c2U,
  0xa7672661U, 0xd06016f7U, 0x4969474dU, 0x3e6e77dbU, 0xaed16a4aU, 0xd9d65adcU,
  0x40df0b66U, 0x37d83bf0U, 0xa9bcae53U, 0xdebb9ec5U, 0x47b2cf7fU, 0x30b5ffe9U,
  0xbdbdf21cU, 0xcabac28aU, 0x53b39330U, 0x24b4a3a6U, 0xbad03605U, 0xcdd70693U,
  0x54de5729U, 0x23d967bfU, 0xb3667a2eU, 0xc4614ab8U, 0x5d681b02U, 0x2a6f2b94U,
  0xb40bbe37U, 0xc30c8ea1U, 0x5a05df1bU, 0x2d02ef8dU
};

/*
 * Check upstream parameters and mark it whether valid or dead
 */
static void
check_upstream (struct upstream *up, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	if (up->dead) {
		if (now - up->time >= revive_timeout) {
			msg_debug ("check_upstream: reviving upstream after %ld seconds", (long int) now - up->time);
			U_WLOCK ();
			up->dead = 0;
			up->errors = 0;
			up->time = 0;
			up->weight = up->priority;
			U_UNLOCK ();
		}
	}
	else {
		if (now - up->time >= error_timeout && up->errors >= max_errors) {
			msg_debug ("check_upstream: marking upstreams as dead after %ld errors", (long int) up->errors);
			U_WLOCK ();
			up->dead = 1;
			up->time = now;
			up->weight = 0;
			U_UNLOCK ();
		}
	}
}

/* 
 * Call this function after failed upstream request
 */
void
upstream_fail (struct upstream *up, time_t now)
{
	if (up->time != 0) {
		up->errors ++;
	}
	else {
		U_WLOCK ();
		up->time = now;
		up->errors ++;
		U_UNLOCK ();
	}
}
/* 
 * Call this function after successfull upstream request
 */
void
upstream_ok (struct upstream *up, time_t now)
{
	if (up->errors != 0) {
		U_WLOCK ();
		up->errors = 0;
		up->time = 0;
		U_UNLOCK ();
	}

	up->weight --;
}
/* 
 * Mark all upstreams as active. This function is used when all upstreams are marked as inactive
 */
void
revive_all_upstreams (void *ups, size_t members, size_t msize) 
{
	int i;
	struct upstream *cur;
	u_char *p;

	U_WLOCK ();
	msg_debug ("revive_all_upstreams: starting reviving all upstreams");
	p = ups;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		cur->time = 0;
		cur->errors = 0;
		cur->dead = 0;
		cur->weight = cur->priority;
		p += msize;
	}
	U_UNLOCK ();
}

/* 
 * Scan all upstreams for errors and mark upstreams dead or alive depends on conditions,
 * return number of alive upstreams 
 */
static int
rescan_upstreams (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{	
	int i, alive;
	struct upstream *cur;
	u_char *p;
	
	/* Recheck all upstreams */
	p = ups;
	alive = members;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		check_upstream (cur, now, error_timeout, revive_timeout, max_errors);
		alive -= cur->dead;
		p += msize;
	}
	
	/* All upstreams are dead */
	if (alive == 0) {
		revive_all_upstreams (ups, members, msize);
		alive = members;
	}

	msg_debug ("rescan_upstreams: %d upstreams alive", alive);
	
	return alive;

}

/* Return alive upstream by its number */
static struct upstream *
get_upstream_by_number (void *ups, size_t members, size_t msize, int selected)
{
	int i;
	u_char *p, *c;
	struct upstream *cur;

	i = 0;
	p = ups;
	c = ups;
	U_RLOCK ();
	for (;;) {
		/* Out of range, return NULL */
		if (p > c + members * msize) {
			break;
		}

		cur = (struct upstream *)p;
		p += msize;

		if (cur->dead) {
			/* Skip inactive upstreams */
			continue;
		}
		/* Return selected upstream */
		if (i == selected) {
			U_UNLOCK ();
			return cur;
		}
		i++;
	}
	U_UNLOCK ();

	/* Error */
	return NULL;

}

/*
 * Get hash key for specified key (perl hash)
 */
static uint32_t
get_hash_for_key (uint32_t hash, char *key, size_t keylen)
{
	uint32_t h, index;
	const char *end = key + keylen;

	h = ~hash;

	while (key < end) {
		index = (h ^ (u_char) *key) & 0x000000ffU;
		h = (h >> 8) ^ crc32lookup[index];
		++key;
	}

	return (~h);
}

/*
 * Recheck all upstreams and return random active upstream
 */
struct upstream *
get_random_upstream (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int alive, selected;
	
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);
	selected = rand () % alive;
	msg_debug ("get_random_upstream: return upstream with number %d of %d", selected, alive);
	
	return get_upstream_by_number (ups, members, msize, selected); 
}

/*
 * Return upstream by hash, that is calculated from active upstreams number
 */
struct upstream *
get_upstream_by_hash (void *ups, size_t members, size_t msize, time_t now, 
						time_t error_timeout, time_t revive_timeout, size_t max_errors,
						char *key, size_t keylen)
{
	int alive, tries = 0, r;
	uint32_t h = 0, ht;
	char *p, numbuf[4];
	struct upstream *cur;
	
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	if (alive == 0) {
		return NULL;
	}

	h = get_hash_for_key (0, key, keylen);
#ifdef HASH_COMPAT
	h = (h >> 16) & 0x7fff;
#endif
	h %= members;
	msg_debug ("get_upstream_by_hash: try to select upstream number %d of %zd", h, members);

	for (;;) {
		p = (char *)ups + msize * h;
		cur = (struct upstream *)p;
		if (!cur->dead) {
			break;
		}
		r = snprintf (numbuf, sizeof (numbuf), "%d", tries);
		ht = get_hash_for_key (0, numbuf, r);
		ht = get_hash_for_key (ht, key, keylen);
#ifdef HASH_COMPAT
		h += (ht >> 16) & 0x7fff;
#else
		h += ht;
#endif
		h %= members;
		msg_debug ("get_upstream_by_hash: try to select upstream number %d of %zd, tries: %d", h, members, tries);
		tries ++;
		if (tries > MAX_TRIES) {
			msg_debug ("get_upstream_by_hash: max tries exceed, returning NULL");
			return NULL;
		}
	}
	
	U_RLOCK ();
	p = ups;
	U_UNLOCK ();
	return cur;
}

/*
 * Recheck all upstreams and return upstream in round-robin order according to weight and priority
 */
struct upstream *
get_upstream_round_robin (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int alive, max_weight, i;
	struct upstream *cur, *selected = NULL;
	u_char *p;
	
	/* Recheck all upstreams */
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	p = ups;
	max_weight = 0;
	selected = (struct upstream *)p;
	U_RLOCK ();
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		if (!cur->dead) {
			if (max_weight < cur->weight) {
				max_weight = cur->weight;
				selected = cur;
			}
		}
		p += msize;
	}
	U_UNLOCK ();

	if (max_weight == 0) {
		p = ups;
		U_WLOCK ();
		for (i = 0; i < members; i++) {
			cur =  (struct upstream *)p;
			cur->weight = cur->priority;
			if (!cur->dead) {
				if (max_weight < cur->priority) {
					max_weight = cur->priority;
					selected = cur;
				}
			}
			p += msize;
		}
		U_UNLOCK ();
	}
	msg_debug ("get_upstream_round_robin: selecting upstream with weight %d", max_weight);

	return selected;
}

/*
 * Recheck all upstreams and return upstream in round-robin order according to only priority (master-slaves)
 */
struct upstream *
get_upstream_master_slave (void *ups, size_t members, size_t msize, time_t now, time_t error_timeout, time_t revive_timeout, size_t max_errors)
{
	int alive, max_weight, i;
	struct upstream *cur, *selected = NULL;
	u_char *p;
	
	/* Recheck all upstreams */
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	p = ups;
	max_weight = 0;
	selected = (struct upstream *)p;
	U_RLOCK ();
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		if (!cur->dead) {
			if (max_weight < cur->priority) {
				max_weight = cur->priority;
				selected = cur;
			}
		}
		p += msize;
	}
	U_UNLOCK ();
	msg_debug ("get_upstream_master_slave: selecting upstream with priority %d", max_weight);

	return selected;
}

/*
 * Ketama manipulation functions
 */

static int
ketama_sort_cmp (const void *a1, const void *a2)
{
	return *((uint32_t *)a1) - *((uint32_t *)a2);
}

/*
 * Add ketama points for specified upstream
 */
int
upstream_ketama_add (struct upstream *up, char *up_key, size_t keylen, size_t keypoints)
{
	uint32_t h = 0;
	char tmp[4];
	int i;

	/* Allocate ketama points array */
	if (up->ketama_points == NULL) {
		up->ketama_points_size = keypoints;
		up->ketama_points = malloc (sizeof (uint32_t) * up->ketama_points_size);
		if (up->ketama_points == NULL) {
			return -1;
		}
	}

	h = get_hash_for_key (h, up_key, keylen);

	for (i = 0; i < keypoints; i++) {
		tmp[0] = i & 0xff;
		tmp[1] = (i >> 8) & 0xff;
		tmp[2] = (i >> 16) & 0xff;
		tmp[3] = (i >> 24) & 0xff;
		
		h = get_hash_for_key (h, tmp, sizeof (tmp) * sizeof (char));
		up->ketama_points[i] = h;
	}
	/* Keep points sorted */
	qsort (up->ketama_points, keypoints, sizeof (uint32_t), ketama_sort_cmp);

	return 0;
}

/*
 * Return upstream by hash and find nearest ketama point in some server
 */
struct upstream *
get_upstream_by_hash_ketama (void *ups, size_t members, size_t msize, time_t now, 
						time_t error_timeout, time_t revive_timeout, size_t max_errors,
						char *key, size_t keylen)
{
	int alive, i;
	uint32_t h = 0, step, middle, d, min_diff = UINT_MAX;
	char *p;
	struct upstream *cur = NULL, *nearest = NULL;
	
	alive = rescan_upstreams (ups, members, msize, now, error_timeout, revive_timeout, max_errors);

	if (alive == 0) {
		return NULL;
	}

	h = get_hash_for_key (h, key, keylen);
	
	U_RLOCK ();
	p = ups;
	nearest = (struct upstream *)p;
	for (i = 0; i < members; i++) {
		cur = (struct upstream *)p;
		if (!cur->dead && cur->ketama_points != NULL) {
			/* Find nearest ketama point for this key */
			step = cur->ketama_points_size / 2;
			middle = step;
			while (step != 1) {
				d = cur->ketama_points[middle] - h;
				if (abs (d) < min_diff) {
					min_diff = abs (d);
					nearest = cur;
				}
				step /= 2;
				if (d > 0) {
					middle -= step;
				}
				else {
					middle += step;
				}
			}
		}
	}
	U_UNLOCK ();
	return nearest;
}

#undef U_LOCK
#undef U_UNLOCK
#undef msg_debug
/* 
 * vi:ts=4 
 */
