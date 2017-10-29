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
#include "ottery-internal.h"
#include "ottery.h"
#include "ottery_st.h"
#include "ottery_nolock.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include <stdio.h>

/* I've added a few assertions to sanity-check for debugging, but they should
 * never ever ever trigger.  It's fine to build this code with NDEBUG. */
#include <assert.h>

#ifdef _WIN32
/* On Windows, there is no fork(), so we don't need to worry about forking. */
#define OTTERY_NO_PID_CHECK
#endif

#ifdef BUILD_RSPAMD
#include "cryptobox.h"
#endif

/** Magic number for deciding whether an ottery_state is initialized. */
#define MAGIC_BASIS 0x11b07734

/** Macro: yield the correct magic number for an ottery_state, based on
 * its position in RAM. */
#define MAGIC(ptr) (((uint32_t)(uintptr_t)(ptr)) ^ MAGIC_BASIS)

static inline int ottery_st_rand_lock_and_check(struct ottery_state *st)
__attribute__((always_inline));
static int ottery_st_reseed(struct ottery_state *state);
static int ottery_st_add_seed_impl(struct ottery_state *st, const uint8_t *seed, size_t n, int locking, int check_magic);

#ifndef OTTERY_NO_WIPE_STACK
static void ottery_wipe_stack_(void) __attribute__((noinline));
#endif

#define LOCK(st)   ACQUIRE_LOCK(&(st)->mutex)
#define UNLOCK(st) RELEASE_LOCK(&(st)->mutex)

size_t
ottery_get_sizeof_config(void)
{
  return sizeof(struct ottery_config);
}

size_t
ottery_get_sizeof_state(void)
{
  return sizeof(struct ottery_state);
}

size_t
ottery_get_sizeof_state_nolock(void)
{
  return sizeof(struct ottery_state_nolock);
}

const char *
ottery_get_version_string(void)
{
  return OTTERY_VERSION_STRING;
}

uint32_t
ottery_get_version(void)
{
  return OTTERY_VERSION;
}

uint32_t
ottery_get_build_flags(void)
{
  uint32_t result = 0;
#ifdef OTTERY_NO_PID_CHECK
  result |= OTTERY_BLDFLG_NO_PID_CHECK;
#endif
#ifdef OTTERY_NO_INIT_CHECK
  result |= OTTERY_BLDFLG_NO_INIT_CHECK;
#endif
#ifdef OTTERY_NO_LOCKS
  result |= OTTERY_BLDFLG_NO_LOCKING;
#endif
#ifdef OTTERY_NO_CLEAR_AFTER_YIELD
  result |= OTTERY_BLDFLG_NO_CLEAR_AFTER_YIELD;
#endif
#ifdef OTTERY_NO_WIPE_STACK
  result |= OTTERY_BLDFLG_NO_WIPE_STACK;
#endif
#ifdef OTTERY_NO_SIMD
  result |= OTTERY_BLDFLG_NO_SIMD;
#endif
  return result;
}

#ifndef OTTERY_NO_CLEAR_AFTER_YIELD
/** Used to zero out the contents of our buffer after we've just given a few
 * to the user. */
#define CLEARBUF(ptr,n) do { memset((ptr), 0, (n)); } while (0)
#else
#define CLEARBUF(ptr,n) ((void)0)
#endif

/**
 * Volatile pointer to memset: we use this to keep the compiler from
 * eliminating our call to memset.  (Don't make this static.)
 */
void * (*volatile ottery_memset_volatile_)(void *, int, size_t) = memset;


void
ottery_memclear_(void *mem, size_t len)
{
  /* NOTE: whenever we change this, change test/test_memclear.c accordingly */
  ottery_memset_volatile_(mem, 0, len);
}

#ifndef OTTERY_NO_WIPE_STACK

/* Chosen more or less arbitrarily */
#define WIPE_STACK_LEN 512

/**
 * Try to clear memory on the stack to clean up after our PRF. This can't
 * easily be done in standard C, so we're doing an ugly hack in hopes that it
 * actually helps.
 *
 * This should never be necessary in a correct program, but if your program is
 * doing something stupid like leaking uninitialized stack, it might keep an
 * attacker from exploiting that.
 **/
static void
ottery_wipe_stack_(void)
{
  char buf[WIPE_STACK_LEN];
  ottery_memset_volatile_(buf, 0, sizeof(buf));
}
#else
#define ottery_wipe_stack_() ((void)0)
#endif

int
ottery_config_init(struct ottery_config *cfg)
{
  cfg->impl = NULL;
  cfg->entropy_config.urandom_fname = NULL;
  cfg->entropy_config.urandom_fd = -1;
  cfg->entropy_config.urandom_fd_is_set = 0;
  cfg->entropy_config.disabled_sources = 0;
  cfg->entropy_config.weak_sources = 0;
  cfg->entropy_config.egd_sockaddr = NULL;
  cfg->entropy_config.egd_socklen = 0;
  cfg->entropy_config.allow_nondev_urandom = 0;
  return 0;
}

static const struct ottery_prf *
ottery_get_impl(const char *impl)
{
  int i;
  const struct ottery_prf *ALL_PRFS[] = {
#ifdef HAVE_SIMD_CHACHA_2
    &ottery_prf_chacha20_krovetz_2_,
    &ottery_prf_chacha12_krovetz_2_,
    &ottery_prf_chacha8_krovetz_2_,
#endif
#ifdef HAVE_SIMD_CHACHA
    &ottery_prf_chacha20_krovetz_1_,
    &ottery_prf_chacha12_krovetz_1_,
    &ottery_prf_chacha8_krovetz_1_,
#endif

#ifdef BUILD_RSPAMD
#if defined(__x86_64__) && defined(RSPAMD_HAS_TARGET_ATTR)
    &ottery_prf_aes_cryptobox_,
#endif
    &ottery_prf_chacha20_cryptobox_,
#endif
	&ottery_prf_chacha20_merged_,
	&ottery_prf_chacha12_merged_,
	&ottery_prf_chacha8_merged_,

	NULL,
  };
  const uint32_t cap = ottery_get_cpu_capabilities_();

  for (i = 0; ALL_PRFS[i]; ++i) {
	const struct ottery_prf *prf = ALL_PRFS[i];
	if ((prf->required_cpucap & cap) != prf->required_cpucap)
	  continue;
	if (impl == NULL)
	  return prf;
	if (!strcmp(impl, prf->name))
	  return prf;
	if (!strcmp(impl, prf->impl))
	  return prf;
	if (!strcmp(impl, prf->flav))
	  return prf;
  }
  return NULL;
}

int
ottery_config_force_implementation(struct ottery_config *cfg,
								   const char *impl)
{
  const struct ottery_prf *prf = ottery_get_impl(impl);
  if (prf) {
	cfg->impl = prf;
	return 0;
  }
  return OTTERY_ERR_INVALID_ARGUMENT;
}

void
ottery_config_set_manual_prf_(struct ottery_config *cfg,
							  const struct ottery_prf *prf)
{
  cfg->impl = prf;
}

void
ottery_config_set_urandom_device(struct ottery_config *cfg,
								 const char *fname)
{
  cfg->entropy_config.urandom_fname = fname;
}

void
ottery_config_set_urandom_fd(struct ottery_config *cfg,
							 int fd)
{
  cfg->entropy_config.urandom_fd = fd;
  cfg->entropy_config.urandom_fd_is_set = (fd >= 0);
}

void
ottery_config_set_egd_socket(struct ottery_config *cfg,
							 const struct sockaddr *addr,
							 int len)
{
  cfg->entropy_config.egd_sockaddr = addr;
  cfg->entropy_config.egd_socklen = len;
}

void
ottery_config_disable_entropy_sources(struct ottery_config *cfg,
									  uint32_t disabled_sources)
{
  cfg->entropy_config.disabled_sources =
	(disabled_sources & OTTERY_ENTROPY_ALL_SOURCES);
}

void
ottery_config_mark_entropy_sources_weak(struct ottery_config *cfg,
										uint32_t disabled_sources)
{
  cfg->entropy_config.weak_sources =
	(disabled_sources & OTTERY_ENTROPY_ALL_SOURCES);
}

/**
 * As ottery_st_nextblock_nolock(), but fill the entire block with
 * entropy, and don't try to rekey the state.
 */
static void
ottery_st_nextblock_nolock_norekey(struct ottery_state *st)
{
  st->prf.generate(st->state, st->buffer, st->block_counter);
  ottery_wipe_stack_();
  ++st->block_counter;
}

/**
 * Generate (st->output_len) bytes of pseudorandom data from the PRF into
 * (st->buffer).  Use the first st->prf.state_bytes of those bytes to replace
 * the PRF state and advance (st->pos) to point after them.
 *
 * This function does not acquire the lock on the state; use it within
 * another function that does.
 *
 * @param st The state to use when generating the block.
 */
static void
ottery_st_nextblock_nolock(struct ottery_state_nolock *st)
{
  ottery_st_nextblock_nolock_norekey(st);
  st->prf.setup(st->state, st->buffer);
  CLEARBUF(st->buffer, st->prf.state_bytes);
  st->block_counter = 0;
  st->pos = st->prf.state_bytes;
}

/**
 * Initialize or reinitialize a PRNG state.
 *
 * @param st The state to initialize or reinitialize.
 * @param prf The configuration to use. (Ignored for reinit)
 * @return An OTTERY_ERR_* value (zero on success, nonzero on failure).
 */
static int
ottery_st_initialize(struct ottery_state *st,
					 const struct ottery_config *config,
					 int locked)
{
  const struct ottery_prf *prf = NULL;
  struct ottery_config cfg_tmp;
  int err;
  /* We really need our state to be aligned. If it isn't, let's give an
   * error now, and not a crash when the SIMD instructions start to fail.
   */
  if (((uintptr_t)st) & 0xf)
	return OTTERY_ERR_STATE_ALIGNMENT;

  if (!config) {
	ottery_config_init(&cfg_tmp);
	config = &cfg_tmp;
  }

  prf = config->impl;

  if (!prf)
	prf = ottery_get_impl(NULL);

  memset(st, 0, sizeof(*st));

  if (locked) {
	/* Now set up the spinlock or mutex or hybrid thing. */
	if (INIT_LOCK(&st->mutex))
	  return OTTERY_ERR_LOCK_INIT;
  }

  /* Check invariants for PRF, in case we wrote some bad code. */
  if ((prf->state_len > MAX_STATE_LEN) ||
	  (prf->state_bytes > MAX_STATE_BYTES) ||
	  (prf->state_bytes > prf->output_len) ||
	  (prf->output_len > MAX_OUTPUT_LEN))
	return OTTERY_ERR_INTERNAL;

  /* Check whether some of our structure size assumptions are right. */
  if ((sizeof(struct ottery_state) > OTTERY_STATE_DUMMY_SIZE_) ||
	  (sizeof(struct ottery_config) > OTTERY_CONFIG_DUMMY_SIZE_))
	return OTTERY_ERR_INTERNAL;

  memcpy(&st->entropy_config, &config->entropy_config,
		 sizeof(struct ottery_entropy_config));

  /* Copy the PRF into place. */
  memcpy(&st->prf, prf, sizeof(*prf));

  if ((err = ottery_st_reseed(st)))
	return err;

  /* Set the magic number last, or else we might look like we succeeded
   * when we didn't */
  st->magic = MAGIC(st);

  st->pid = getpid();

  return 0;
}

static int
ottery_st_reseed(struct ottery_state *st)
{
  /* Now seed the PRF: Generate some random bytes from the OS, and use them
   * as whatever keys/nonces/whatever the PRF wants to have. */
  /* XXXX Add seed rather than starting from scratch? */
  int err;
  uint32_t flags=0;
  size_t buflen = ottery_get_entropy_bufsize_(st->prf.state_bytes);
  uint8_t *buf = alloca(buflen);
  if (!buf)
	return OTTERY_ERR_INIT_STRONG_RNG;

  if ((err = ottery_get_entropy_(&st->entropy_config, &st->entropy_state, 0,
								  buf, st->prf.state_bytes,
								  &buflen,
								  &flags)))
	return err;
  if (buflen < st->prf.state_bytes)
	return OTTERY_ERR_ACCESS_STRONG_RNG;
  /* The first state_bytes bytes become the initial key. */
  st->prf.setup(st->state, buf);
  /* If there are more bytes, we mix them into the key with add_seed */
  if (buflen > st->prf.state_bytes)
	ottery_st_add_seed_impl(st,
							buf + st->prf.state_bytes,
							buflen - st->prf.state_bytes,
							0,
							0);
  ottery_memclear_(buf, buflen);
  st->last_entropy_flags = flags;
  st->entropy_src_flags = flags;

  /* Generate the first block of output. */
  st->block_counter = 0;
  ottery_st_nextblock_nolock(st);

  return 0;
}

int
ottery_st_init(struct ottery_state *st, const struct ottery_config *cfg)
{
  return ottery_st_initialize(st, cfg, 1);
}

int
ottery_st_init_nolock(struct ottery_state_nolock *st,
					  const struct ottery_config *cfg)
{
  return ottery_st_initialize(st, cfg, 0);
}

static int
ottery_st_add_seed_impl(struct ottery_state *st, const uint8_t *seed, size_t n, int locking, int check_magic)
{
#ifndef OTTERY_NO_INIT_CHECK
  if (check_magic && UNLIKELY(st->magic != MAGIC(st))) {
	ottery_fatal_error_(OTTERY_ERR_STATE_INIT);
	return OTTERY_ERR_STATE_INIT;
  }
#endif

  /* If the user passed NULL, then we should reseed from the operating
   * system. */
  uint8_t *tmp_seed = NULL;
  size_t tmp_seed_len = 0;
  uint32_t flags = 0;

  if (!seed || !n) {
	int err;
	tmp_seed_len = ottery_get_entropy_bufsize_(st->prf.state_bytes);
	tmp_seed = alloca(tmp_seed_len);
	if (!tmp_seed)
	  return OTTERY_ERR_INIT_STRONG_RNG;
	n = tmp_seed_len;
	if ((err = ottery_get_entropy_(&st->entropy_config, &st->entropy_state, 0,
									tmp_seed, st->prf.state_bytes,
									&n,
									&flags)))
	  return err;
	if (n < st->prf.state_bytes)
	  return OTTERY_ERR_ACCESS_STRONG_RNG;
	seed = tmp_seed;
  }

  if (locking)
	LOCK(st);
  /* The algorithm here is really easy. We grab a block of output from the
   * PRNG, that the first (state_bytes) bytes of that, XOR it with up to
   * (state_bytes) bytes of our new seed data, and use that to set our new
   * state. We do this over and over until we have no more seed data to add.
   */
  while (n) {
	unsigned i;
	size_t m = n > st->prf.state_bytes/2 ? st->prf.state_bytes/2 : n;
	ottery_st_nextblock_nolock_norekey(st);
	for (i = 0; i < m; ++i) {
	  st->buffer[i] ^= seed[i];
	}
	st->prf.setup(st->state, st->buffer);
	st->block_counter = 0;
	n -= m;
	seed += m;
  }

  /* Now make sure that st->buffer is set up with the new state. */
  ottery_st_nextblock_nolock(st);

  st->entropy_src_flags |= flags;
  st->last_entropy_flags = flags;

  if (locking)
	UNLOCK(st);

  /* If we used stack-allocated seed material, wipe it. */
  if (tmp_seed)
	ottery_memclear_(tmp_seed, tmp_seed_len);

  return 0;
}

int
ottery_st_add_seed(struct ottery_state *st, const uint8_t *seed, size_t n)
{
  return ottery_st_add_seed_impl(st, seed, n, 1, 1);
}
int
ottery_st_add_seed_nolock(struct ottery_state_nolock *st, const uint8_t *seed, size_t n)
{
  return ottery_st_add_seed_impl(st, seed, n, 0, 1);
}


void
ottery_st_wipe(struct ottery_state *st)
{
  DESTROY_LOCK(&st->mutex);

  ottery_st_wipe_nolock(st);
}

void
ottery_st_wipe_nolock(struct ottery_state_nolock *st)
{
  ottery_memclear_(st, sizeof(struct ottery_state));
}

void
ottery_st_prevent_backtracking_nolock(struct ottery_state_nolock *st)
{
#ifdef OTTERY_NO_CLEAR_AFTER_YIELD
  memset(st->buffer, 0, st->pos);
#else
  (void)st;
#endif
}

void
ottery_st_prevent_backtracking(struct ottery_state *st)
{
  LOCK(st);
  ottery_st_prevent_backtracking_nolock(st);
  UNLOCK(st);
}

/** Function that's invoked on a fatal error. See
 * ottery_set_fatal_handler() for more information. */
static void (*ottery_fatal_handler)(int) = NULL;

void
ottery_fatal_error_(int error)
{
  if (ottery_fatal_handler)
	ottery_fatal_handler(error);
  else
	abort();
}

void
ottery_set_fatal_handler(void (*fn)(int))
{
  ottery_fatal_handler = fn;
}

/**
 * Shared prologue for functions generating random bytes from an ottery_state.
 * Make sure that the state is initialized.
 */
static inline int
ottery_st_rand_check_init(struct ottery_state *st)
{
#ifndef OTTERY_NO_INIT_CHECK
  if (UNLIKELY(st->magic != MAGIC(st))) {
	ottery_fatal_error_(OTTERY_ERR_STATE_INIT);
	return -1;
  }
#else
  (void)st;
#endif
  return 0;
}

/* XXXX */
static inline int
ottery_st_rand_check_pid(struct ottery_state *st)
{
#ifndef OTTERY_NO_PID_CHECK
  if (UNLIKELY(st->pid != getpid())) {
	int err;
	if ((err = ottery_st_reseed(st))) {
	  ottery_fatal_error_(OTTERY_ERR_FLAG_POSTFORK_RESEED|err);
	  return -1;
	}
	st->pid = getpid();
  }
#else
  (void) st;
#endif
  return 0;
}

static inline int
ottery_st_rand_lock_and_check(struct ottery_state *st)
{
  if (ottery_st_rand_check_init(st))
	return -1;
  LOCK(st);
  if (ottery_st_rand_check_pid(st)) {
	UNLOCK(st);
	return -1;
  }
  return 0;
}

static inline int
ottery_st_rand_check_nolock(struct ottery_state_nolock *st)
{
  if (ottery_st_rand_check_init(st))
	return -1;
  if (ottery_st_rand_check_pid(st))
	return -1;
  return 0;
}

/**
 * Generate a small-ish number of bytes from an ottery_state, using
 * buffered data.  If there is insufficient data in the buffer right now,
 * use what we have, and generate more.
 *
 * @param st The state to use.
 * @param out A location to write to.
 * @param n The number of bytes to write. Must not be greater than
 *     st->prf.output_len*2 - st->prf.state_bytes - st->pos - 1.
 */
static inline void
ottery_st_rand_bytes_from_buf(struct ottery_state *st, uint8_t *out,
							  size_t n)
{
  if (n + st->pos < st->prf.output_len) {
	memcpy(out, st->buffer+st->pos, n);
	CLEARBUF(st->buffer+st->pos, n);
	st->pos += n;
  } else {
	unsigned cpy = st->prf.output_len - st->pos;
	memcpy(out, st->buffer+st->pos, cpy);
	n -= cpy;
	out += cpy;
	ottery_st_nextblock_nolock(st);
	memcpy(out, st->buffer+st->pos, n);
	CLEARBUF(st->buffer, n);
	st->pos += n;
	assert(st->pos < st->prf.output_len);
  }
}

static void
ottery_st_rand_bytes_impl(struct ottery_state *st, void *out_,
						  size_t n)
{
  uint8_t *out = out_;
  size_t cpy;

  if (n + st->pos < st->prf.output_len * 2 - st->prf.state_bytes - 1) {
	/* Fulfill it all from the buffer simply if possible. */
	ottery_st_rand_bytes_from_buf(st, out, n);
	return;
  }

  /* Okay. That's not going to happen.  Well, take what we can... */
  cpy = st->prf.output_len - st->pos;
  memcpy(out, st->buffer + st->pos, cpy);
  out += cpy;
  n -= cpy;

  /* Then take whole blocks so long as we need them, without stirring... */
  while (n >= st->prf.output_len) {
	/* (We could save a memcpy here if we generated the block directly at out
	 * rather than doing the memcpy here. First we'd need to make sure that we
	 * had gotten the block aligned to a 16-byte boundary, though, and we'd
	 * have some other tricky bookkeeping to do. Let's call this good enough
	 * for now.) */
	ottery_st_nextblock_nolock_norekey(st);
	memcpy(out, st->buffer, st->prf.output_len);
	out += st->prf.output_len;
	n -= st->prf.output_len;
  }

  /* Then stir for the last part. */
  ottery_st_nextblock_nolock(st);
  ottery_st_rand_bytes_from_buf(st, out, n);
}

void
ottery_st_rand_bytes(struct ottery_state *st, void *out_, size_t n)
{
  if (ottery_st_rand_lock_and_check(st))
	return;
  ottery_st_rand_bytes_impl(st, out_, n);
  UNLOCK(st);
}

void
ottery_st_rand_bytes_nolock(struct ottery_state_nolock *st, void *out_, size_t n)
{
  if (ottery_st_rand_check_nolock(st))
	return;
  ottery_st_rand_bytes_impl(st, out_, n);
}

/**
 * Assign an integer type from bytes at a possibly unaligned pointer.
 *
 * @param type the type of integer to assign.
 * @param r the integer lvalue to write to.
 * @param p a pointer to the bytes to read from.
 **/
#define INT_ASSIGN_PTR(type, r, p) do { \
	memcpy(&r, p, sizeof(type));        \
} while (0)

/**
 * Shared code for implementing rand_unsigned() and rand_uint64().
 *
 * @param st The state to use.
 * @param inttype The type of integer to generate.
 **/
#define OTTERY_RETURN_RAND_INTTYPE_IMPL(st, inttype, unlock) do {      \
	inttype result;                                                    \
	if (sizeof(inttype) + (st)->pos <= (st)->prf.output_len) {         \
	  INT_ASSIGN_PTR(inttype, result, (st)->buffer + (st)->pos);       \
	  CLEARBUF((st)->buffer + (st)->pos, sizeof(inttype));             \
	  (st)->pos += sizeof(inttype);                                    \
	  if (st->pos == (st)->prf.output_len) {                           \
		ottery_st_nextblock_nolock(st);                                \
	  }                                                                \
	} else {                                                           \
	  /* Our handling of this case here is significantly simpler */    \
	  /* than that of ottery_st_rand_bytes_from_buf, at the expense */ \
	  /* of wasting up to sizeof(inttype)-1 bytes. Since inttype */    \
	  /* is at most 8 bytes long, that's not such a big deal. */       \
	  ottery_st_nextblock_nolock(st);                                  \
	  INT_ASSIGN_PTR(inttype, result, (st)->buffer + (st)->pos);       \
	  CLEARBUF((st)->buffer, sizeof(inttype));                         \
	  (st)->pos += sizeof(inttype);                                    \
	}                                                                  \
	unlock;                                                            \
	return result;                                                     \
} while (0)

#define OTTERY_RETURN_RAND_INTTYPE(st, inttype) do {          \
	if (ottery_st_rand_lock_and_check(st))                    \
	  return (inttype)0;                                      \
	OTTERY_RETURN_RAND_INTTYPE_IMPL(st, inttype, UNLOCK(st)); \
} while (0)

#define OTTERY_RETURN_RAND_INTTYPE_NOLOCK(st, inttype) do { \
	if (ottery_st_rand_check_nolock(st))                    \
	  return (inttype)0;                                    \
	OTTERY_RETURN_RAND_INTTYPE_IMPL(st, inttype, );         \
} while (0)

unsigned
ottery_st_rand_unsigned(struct ottery_state *st)
{
  OTTERY_RETURN_RAND_INTTYPE(st, unsigned);
}

unsigned
ottery_st_rand_unsigned_nolock(struct ottery_state_nolock *st)
{
  OTTERY_RETURN_RAND_INTTYPE_NOLOCK(st, unsigned);
}

uint32_t
ottery_st_rand_uint32(struct ottery_state *st)
{
  OTTERY_RETURN_RAND_INTTYPE(st, uint32_t);
}

uint32_t
ottery_st_rand_uint32_nolock(struct ottery_state_nolock *st)
{
  OTTERY_RETURN_RAND_INTTYPE_NOLOCK(st, uint32_t);
}

uint64_t
ottery_st_rand_uint64(struct ottery_state *st)
{
  OTTERY_RETURN_RAND_INTTYPE(st, uint64_t);
}

uint64_t
ottery_st_rand_uint64_nolock(struct ottery_state_nolock *st)
{
  OTTERY_RETURN_RAND_INTTYPE_NOLOCK(st, uint64_t);
}

unsigned
ottery_st_rand_range_nolock(struct ottery_state_nolock *st, unsigned upper)
{
  unsigned lim = upper+1;
  unsigned divisor = lim ? (UINT_MAX / lim) : 1;
  unsigned n;
  do {
	n = (ottery_st_rand_unsigned_nolock(st) / divisor);
  } while (n > upper);

  return n;
}

uint64_t
ottery_st_rand_range64_nolock(struct ottery_state_nolock *st, uint64_t upper)
{
  uint64_t lim = upper+1;
  uint64_t divisor = lim ? (UINT64_MAX / lim) : 1;
  uint64_t n;
  do {
	n = (ottery_st_rand_uint64_nolock(st) / divisor);
  } while (n > upper);

  return n;
}

unsigned
ottery_st_rand_range(struct ottery_state *state, unsigned upper)
{
  unsigned n;
  if (ottery_st_rand_check_init(state))
	return 0;
  LOCK(state);
  n = ottery_st_rand_range_nolock(state, upper);
  UNLOCK(state);
  return n;
}

uint64_t
ottery_st_rand_range64(struct ottery_state *state, uint64_t upper)
{
  uint64_t n;
  if (ottery_st_rand_check_init(state))
	return 0;
  LOCK(state);
  n = ottery_st_rand_range64_nolock(state, upper);
  UNLOCK(state);
  return n;
}
