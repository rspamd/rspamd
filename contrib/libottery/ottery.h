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
#ifndef OTTERY_H_HEADER_INCLUDED_
#define OTTERY_H_HEADER_INCLUDED_
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "ottery_common.h"

/** @file */

struct ottery_config;

/* Functions that use an implicit global state */

/**
 * Fill a buffer with random bytes.
 *
 * @param buf The buffer to fill.
 * @param n The number of bytes to write.
 */
void ottery_rand_bytes(void *buf, size_t n);
/**
 * Generate a random number of type unsigned.
 *
 * @return A random number between 0 and UINT_MAX included,
 *   chosen uniformly.
 */
unsigned ottery_rand_unsigned(void);
/**
 * Generate a random number of type uint32_t.
 *
 * @return A random number between 0 and UINT32_MAX included,
 *   chosen uniformly.
 */
uint32_t ottery_rand_uint32(void);
/**
 * Generate a random number of type uint64_t.
 *
 * @return A random number between 0 and UINT64_MAX included,
 *   chosen uniformly.
 */
uint64_t ottery_rand_uint64(void);
/**
 * Generate a random number of type unsigned in a given range.
 *
 * @param top The upper bound of the range (inclusive).
 * @return A random number no larger than top, and no less than 0,
 *   chosen uniformly.
 */
unsigned ottery_rand_range(unsigned top);
/**
 * Generate a random number of type uint64_t in a given range.
 *
 * @param top The upper bound of the range (inclusive).
 * @return A random number no larger than top, and no less than 0,
 *   chosen uniformly.
 */
uint64_t ottery_rand_range64(uint64_t top);

/**
 * Initialize the libottery global state.
 *
 * Most users should not need to use this function. If you use it, you must
 * call it before any of: ottery_rand_bytes, ottery_rand_unsigned,
 * ottery_rand_uint64, ottery_rand_range, ottery_rand_uint64_range,
 * ottery_add_seed, ottery_wipe, ottery_stir.
 *
 * You would want to use this function if you want to select some non-default
 * behavior using an ottery_config structure.
 *
 * @param cfg Either NULL, or an ottery_config structure that has been
 *   initialized with ottery_config_init().
 * @return Zero on success, or one of the OTTERY_ERR_* error codes on failure.
 */
int ottery_init(const struct ottery_config *cfg);

/**
 * Add more entropy to the libottery global state.
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
 * @param seed Bytes to add to the state. If this value is NULL, we take
 *    more random bytes from the OS.
 * @param n The number of bytes to add. If this value is 0, we take more
 *    random bytes from the OS, regardless of the value of seed.
 * @return Zero on success, or one of the OTTERY_ERR_* error codes on failure.
 */
int ottery_add_seed(const uint8_t *seed, size_t n);

/**
 * Destroy the libottery global state and release any resources that it might
 * hold.
 *
 * Ordinarily, you would only want to call this at exit, if at all.
 */
void ottery_wipe(void);

/**
 * Explicitly tell libottery to prevent backtracking attacks. (Usually
 * needless.)
 *
 * Once this function has been called, an attacker who compromises the state
 * later on will not be able to recover bytes that have previously been
 * returned by any of the ottery_rand_* functions.
 *
 * You should not usually need to call this function: Libottery provides
 * backtracking resistance by default, so unless you have manually recompiled
 * with the OTTERY_NO_CLEAR_AFTER_YIELD option, this function isn't
 * necessary and has no effect.  Even *with* OTTERY_NO_CLEAR_AFTER_YIELD,
 * this function isn't necessary in ordinary operation: the libottery state is
 * implicitly "stirred" every 1k or so.
 */
void ottery_prevent_backtracking(void);

#ifdef __cplusplus
}
#endif

#endif
