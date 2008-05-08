#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <sys/types.h>


struct upstream {
	unsigned int errors;
	time_t time;
	unsigned char dead;
	unsigned char priority;
	int16_t weight;
	uint32_t *ketama_points;
	size_t ketama_points_size;
};

void upstream_fail (struct upstream *up, time_t now);
void upstream_ok (struct upstream *up, time_t now);
void revive_all_upstreams (void *ups, size_t members, size_t msize);
int upstream_ketama_add (struct upstream *up, char *up_key, size_t keylen, size_t keypoints);

struct upstream* get_random_upstream   (void *ups, size_t members, size_t msize, 
										time_t now, time_t error_timeout, 
										time_t revive_timeout, size_t max_errors);

struct upstream* get_upstream_by_hash  (void *ups, size_t members, size_t msize, 
										time_t now,  time_t error_timeout, 
										time_t revive_timeout, size_t max_errors,
										char *key, size_t keylen);

struct upstream* get_upstream_round_robin (void *ups, size_t members, size_t msize, 
										time_t now, time_t error_timeout, 
										time_t revive_timeout, size_t max_errors);

struct upstream* get_upstream_by_hash_ketama (void *ups, size_t members, size_t msize, time_t now, 
										time_t error_timeout, time_t revive_timeout, size_t max_errors,
										char *key, size_t keylen);


#endif /* UPSTREAM_H */
/* 
 * vi:ts=4 
 */
