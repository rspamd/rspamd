/* Libottery by Nick Mathewson.

   This software has been dedicated to the public domain under the CC0
   public domain dedication.

   To the extent possible under law, the person who associated CC0 with
   libottery has waived all copyright and related or neighboring rights
   to libottery.

   You should have received a copy of the CC0 legalcode along with this
   work in doc/cc0.txt.  If not, see
      <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#ifndef OTTERY_NOLOCK_H_HEADER_INCLUDED_
#define OTTERY_NOLOCK_H_HEADER_INCLUDED_
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "ottery_common.h"

/** @file */

struct ottery_config;
struct ottery_state_nolock;

/** Size reserved for struct ottery_state_nolock */
#define OTTERY_STATE_NOLOCK_DUMMY_SIZE_ 1536

#ifndef OTTERY_INTERNAL
/**
 * The state for a non-thread-safe libottery PRNG
 *
 * Like struct ottery_state, but this structure (and its associated functions)
 * are not thread safe.  If you try to use this structure in more than one
 * thread at a time, your program's behavior will be undefined. It might
 * crash. It might insecurely give the same random sequence to multiple
 * threads.  It might fail in strange ways that you'd never predict.
 *
 * An ottery_state_nolock structure is constucted with ottery_st_init().  It
 * MUST be aligned on a 16-byte boundary.
 *
 * You may not use an ottery_state_nolock structure with any other function
 * before you have first initialized it with ottery_st_init_nolock().
 *
 * The contents of this structure are opaque; The definition here is
 * defined to be large enough so that programs that allocate it will get
 * more than enough room.
 */
struct __attribute__((aligned(16))) ottery_state_nolock {
  /** Nothing to see here */
  uint8_t dummy_[OTTERY_STATE_NOLOCK_DUMMY_SIZE_];
};
#endif

/**
 * Get the minimal size for allocating an ottery_state_nolock.
 *
 * sizeof(ottery_state_nolock) will give an overestimate to allow binary
 * compatibility with future versions of libottery. Use this function instead
 * to get the minimal number of bytes to allocate.
 *
 * @return The minimal number of bytes to use when allocating an
 *   ottery_state_nolock structure.
 */
size_t ottery_get_sizeof_state_nolock(void);

/**
 * Initialize an ottery_state_nolock structure.
 *
 * You must call this function on any ottery_state_nolock structure before
 * calling any other functions on it.
 *
 * @param st The ottery_state_nolock to initialize.
 * @param cfg Either NULL, or an ottery_config structure that has been
 *   initialized with ottery_config_init().
 * @return Zero on success, or one of the OTTERY_ERR_* error codes on failure.
 */
int ottery_st_init_nolock(struct ottery_state_nolock *st, const struct ottery_config *cfg);

/**
 * Add more entropy to an ottery_state_nolock structure.
 *
 * Calling this function should be needless, if you trust your operating
 * system's random number generator and entropy extraction features.  You
 * would want to use this function if you think the operating system's random
 * number generator might be inadequate, and you want to add more entropy from
 * EGD or something.
 *
 * You might also want to call this function if your belief system says that
 * it's useful to periodically add more raw entropy to a well-seeded
 * cryptographically strong PRNG.
 *
 * @param st The state which will receive more entropy.
 * @param seed Bytes to add to the state.
 * @param n The number of bytes to add.
 * @return Zero on success, or one of the OTTERY_ERR_* error codes on failure.
 */
int ottery_st_add_seed_nolock(struct ottery_state_nolock *st, const uint8_t *seed, size_t n);

/**
 * Destroy an ottery_state_nolock structure and release any resources that it
 * might hold.
 *
 * Ordinarily, you would want to call this at exit, or before freeing an
 * ottery_state_nolock
 *
 * @param st The state to wipe.
 */
void ottery_st_wipe_nolock(struct ottery_state_nolock *st);

/**
 * Explicitly prevent backtracking attacks. (Usually needless).
 *
 * Once this function has been called, an attacker who compromises the state
 * later on will not be able to recover bytes that have previously been
 * returned by any of the ottery_st_rand_*_nolock functions.
 *
 * You should not usually need to call this function: Libottery provides
 * backtracking resistance by default, so unless you have manually recompiled
 * with the OTTERY_NO_CLEAR_AFTER_YIELD option, this function isn't
 * necessary and has no effect.  Even *with* OTTERY_NO_CLEAR_AFTER_YIELD,
 * this function isn't necessary in ordinary operation: the libottery state is
 * implicitly "stirred" every 1k or so.
 *
 * @param st The state to stir.
 */
void ottery_st_prevent_backtracking_nolock(struct ottery_state_nolock *st);

/**
 * Use an ottery_state_nolock structure to fill a buffer with random bytes.
 *
 * @param st The state structure to use.
 * @param buf The buffer to fill.
 * @param n The number of bytes to write.
 */
void ottery_st_rand_bytes_nolock(struct ottery_state_nolock *st, void *buf, size_t n);
/**
 * Use an ottery_state_nolock structure to generate a random number of type unsigned.
 *
 * @param st The state structure to use.
 * @return A random number between 0 and UINT_MAX included,
 *   chosen uniformly.
 */
unsigned ottery_st_rand_unsigned_nolock(struct ottery_state_nolock *st);
/**
 * Use an ottery_state_nolock structure to generate a random number of type uint32_t.
 *
 * @param st The state structure to use.
 * @return A random number between 0 and UINT32_MAX included,
 *   chosen uniformly.
 */
uint32_t ottery_st_rand_uint32_nolock(struct ottery_state_nolock *st);
/**
 * Use an ottery_state_nolock structure to generate a random number of type uint64_t.
 *
 * @param st The state structure to use.
 * @return A random number between 0 and UINT64_MAX included,
 *   chosen uniformly.
 */
uint64_t ottery_st_rand_uint64_nolock(struct ottery_state_nolock *st);
/**
 * Use an ottery_state_nolock structure to generate a random number of type unsigned
 * in a given range.
 *
 * @param st The state structure to use.
 * @param top The upper bound of the range (inclusive).
 * @return A random number no larger than top, and no less than 0,
 *   chosen uniformly.
 */
unsigned ottery_st_rand_range_nolock(struct ottery_state_nolock *st, unsigned top);
/**
 * Use an ottery_state_nolock structure to generate a random number of type uint64_t
 * in a given range.
 *
 * @param st The state structure to use.
 * @param top The upper bound of the range (inclusive).
 * @return A random number no larger than top, and no less than 0,
 *   chosen uniformly.
 */
uint64_t ottery_st_rand_range64_nolock(struct ottery_state_nolock *st, uint64_t top);

#ifdef __cplusplus
}
#endif

#endif
