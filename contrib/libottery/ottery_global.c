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
#define OTTERY_INTERNAL
#include <stdlib.h>
#include "ottery-internal.h"
#include "ottery.h"
#include "ottery_st.h"


/** Flag: true iff ottery_global_state_ is initialized. */
static int ottery_global_state_initialized_ = 0;
int ottery_valgrind_ = 0;
/** A global state to use for the ottery_* functions that don't take a
 * state. */
static struct ottery_state ottery_global_state_;

/** Initialize ottery_global_state_ if it has not been initialize. */
#define CHECK_INIT(rv) do {                                 \
	if (UNLIKELY(!ottery_global_state_initialized_)) {      \
	  int err;                                              \
	  if ((err = ottery_init(NULL))) {                      \
		ottery_fatal_error_(OTTERY_ERR_FLAG_GLOBAL_PRNG_INIT|err); \
		return rv;                                          \
	  }                                                     \
	}                                                       \
} while (0)

int
ottery_init(const struct ottery_config *cfg)
{
	if (getenv("VALGRIND")) {
		ottery_valgrind_ = 1;
	}
  int n = ottery_st_init(&ottery_global_state_, cfg);
  if (n == 0)
	ottery_global_state_initialized_ = 1;
  return n;
}

int
ottery_add_seed(const uint8_t *seed, size_t n)
{
  CHECK_INIT(0);
  return ottery_st_add_seed(&ottery_global_state_, seed, n);
}

void
ottery_wipe(void)
{
  if (ottery_global_state_initialized_) {
	ottery_global_state_initialized_ = 0;
	ottery_st_wipe(&ottery_global_state_);
  }
}

void
ottery_prevent_backtracking(void)
{
  CHECK_INIT();
  ottery_st_prevent_backtracking(&ottery_global_state_);
}

void
ottery_rand_bytes(void *out, size_t n)
{
  CHECK_INIT();
  ottery_st_rand_bytes(&ottery_global_state_, out, n);
}

unsigned
ottery_rand_unsigned(void)
{
  CHECK_INIT(0);
  return ottery_st_rand_unsigned(&ottery_global_state_);
}
uint32_t
ottery_rand_uint32(void)
{
  CHECK_INIT(0);
  return ottery_st_rand_uint32(&ottery_global_state_);
}
uint64_t
ottery_rand_uint64(void)
{
  CHECK_INIT(0);
  return ottery_st_rand_uint64(&ottery_global_state_);
}
unsigned
ottery_rand_range(unsigned top)
{
  CHECK_INIT(0);
  return ottery_st_rand_range(&ottery_global_state_, top);
}
uint64_t
ottery_rand_range64(uint64_t top)
{
  CHECK_INIT(0);
  return ottery_st_rand_range64(&ottery_global_state_, top);
}

const char *ottery_get_impl_name(void)
{
	CHECK_INIT(0);
	return ottery_global_state_.prf.name;
}