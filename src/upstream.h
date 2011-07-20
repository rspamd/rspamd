#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <sys/types.h>
#include <stdint.h>

/*
 * Structure of generic upstream
 */
struct upstream {
	guint errors;						/**< Errors for this upstream 	*/
	time_t time;						/**< Time of marking 			*/
	guint dead;							/**< Dead flag					*/
	guint priority;						/**< Fixed priority				*/
	gint16 weight;						/**< Dynamic weight				*/
	guint32 *ketama_points;				/**< Ketama points array		*/
	size_t ketama_points_size;			/**< Ketama array size			*/
};

/*
 * Upstream error logic
 * 1. During error time we count upstream_ok and upstream_fail
 * 2. If failcount is more then maxerrors then we mark upstream as unavailable for dead time
 * 3. After dead time we mark upstream as alive and go to the step 1
 * 4. If all upstreams are dead, marks every upstream as alive
 */

/*
 * Add an error to an upstream
 */
void upstream_fail (struct upstream *up, time_t now);

/*
 * Increase upstream successes count
 */
void upstream_ok (struct upstream *up, time_t now);

/*
 * Make all upstreams alive
 */
void revive_all_upstreams (void *ups, size_t members, size_t msize);

/*
 * Add ketama points for upstream
 */
gint upstream_ketama_add (struct upstream *up, gchar *up_key, size_t keylen, size_t keypoints);

/*
 * Get a random upstream from array of upstreams
 * @param ups array of structures that contains struct upstream as their first element
 * @param members number of elements in array
 * @param msize size of each member
 * @param now current time
 * @param error_timeout time during which we are counting errors
 * @param revive_timeout time during which we counts upstream dead
 * @param max_errors maximum errors during error_timeout to mark upstream dead
 */
struct upstream* get_random_upstream   (void *ups, size_t members, size_t msize, 
										time_t now, time_t error_timeout, 
										time_t revive_timeout, size_t max_errors);

/*
 * Get upstream based on hash from array of upstreams
 * @param ups array of structures that contains struct upstream as their first element
 * @param members number of elements in array
 * @param msize size of each member
 * @param now current time
 * @param error_timeout time during which we are counting errors
 * @param revive_timeout time during which we counts upstream dead
 * @param max_errors maximum errors during error_timeout to mark upstream dead
 * @param key key for hashing
 * @param keylen length of the key
 */
struct upstream* get_upstream_by_hash  (void *ups, size_t members, size_t msize, 
										time_t now,  time_t error_timeout, 
										time_t revive_timeout, size_t max_errors,
										gchar *key, size_t keylen);

/*
 * Get an upstream from array of upstreams based on its current weight
 * @param ups array of structures that contains struct upstream as their first element
 * @param members number of elements in array
 * @param msize size of each member
 * @param now current time
 * @param error_timeout time during which we are counting errors
 * @param revive_timeout time during which we counts upstream dead
 * @param max_errors maximum errors during error_timeout to mark upstream dead
 */
struct upstream* get_upstream_round_robin (void *ups, size_t members, size_t msize, 
										time_t now, time_t error_timeout, 
										time_t revive_timeout, size_t max_errors);

/*
 * Get upstream based on hash from array of upstreams, this functions is using ketama algorithm
 * @param ups array of structures that contains struct upstream as their first element
 * @param members number of elements in array
 * @param msize size of each member
 * @param now current time
 * @param error_timeout time during which we are counting errors
 * @param revive_timeout time during which we counts upstream dead
 * @param max_errors maximum errors during error_timeout to mark upstream dead
 * @param key key for hashing
 * @param keylen length of the key
 */
struct upstream* get_upstream_by_hash_ketama (void *ups, size_t members, size_t msize, time_t now, 
										time_t error_timeout, time_t revive_timeout, size_t max_errors,
										gchar *key, size_t keylen);

/*
 * Get an upstream from array of upstreams based on its current priority (not weight)
 * @param ups array of structures that contains struct upstream as their first element
 * @param members number of elements in array
 * @param msize size of each member
 * @param now current time
 * @param error_timeout time during which we are counting errors
 * @param revive_timeout time during which we counts upstream dead
 * @param max_errors maximum errors during error_timeout to mark upstream dead
 */
struct upstream* get_upstream_master_slave (void *ups, size_t members, size_t msize,
										time_t now, time_t error_timeout,
										time_t revive_timeout, size_t max_errors);


#endif /* UPSTREAM_H */
/* 
 * vi:ts=4 
 */
