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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define SRC(x) OTTERY_ENTROPY_SRC_ ## x
#define DOM(x) OTTERY_ENTROPY_DOM_ ## x
#define FL(x)  OTTERY_ENTROPY_FL_  ## x

#include "ottery_entropy_cryptgenrandom.c"
#include "ottery_entropy_urandom.c"
#include "ottery_entropy_rdrand.c"
#include "ottery_entropy_egd.c"

/** Table of RNG functions and their properties. */
static struct ottery_randbytes_source {
  int (*fn)(const struct ottery_entropy_config *,
            struct ottery_entropy_state *,
            uint8_t *, size_t);
  uint32_t flags;
} RAND_SOURCES[] = {
#ifdef ENTROPY_SOURCE_CRYPTGENRANDOM
  ENTROPY_SOURCE_CRYPTGENRANDOM,
#endif
#ifdef ENTROPY_SOURCE_URANDOM
  ENTROPY_SOURCE_URANDOM,
#endif
#ifdef ENTROPY_SOURCE_EGD
  ENTROPY_SOURCE_EGD,
#endif
#ifdef ENTROPY_SOURCE_RDRAND
  ENTROPY_SOURCE_RDRAND,
#endif
  { NULL, 0 }
};

size_t
ottery_get_entropy_bufsize_(size_t n)
{
  return n * (sizeof(RAND_SOURCES)/sizeof(RAND_SOURCES[0]) - 1);
}

int
ottery_get_entropy_(const struct ottery_entropy_config *config,
                    struct ottery_entropy_state *state,
                     uint32_t select_sources,
                     uint8_t *bytes, size_t n, size_t *buflen,
                     uint32_t *flags_out)
{
  ssize_t err = OTTERY_ERR_INIT_STRONG_RNG, last_err = 0;
  int i;
  uint32_t got = 0;
  uint8_t *next;
  const uint32_t disabled_sources = config ? config->disabled_sources : 0;

  memset(bytes, 0, *buflen);
  next = bytes;

  *flags_out = 0;

  for (i=0; RAND_SOURCES[i].fn; ++i) {
    uint32_t flags = RAND_SOURCES[i].flags;
    /* Don't use a disabled source. */
    if (0 != (flags & disabled_sources))
      continue;
    /* If some flags must be set, only use those. */
    if ((flags & select_sources) != select_sources)
      continue;
    /* If we already have input from a certain domain, we don't need more */
    if ((flags & (got & OTTERY_ENTROPY_DOM_MASK)) != 0)
      continue;
    /* If we can't write these bytes, don't try. */
    if (next + n > bytes + *buflen)
      break;
    err = RAND_SOURCES[i].fn(config, state, next, n);
    if (err == 0) {
      uint32_t flags = RAND_SOURCES[i].flags;
      if (config && (flags & config->weak_sources))
        flags &= ~OTTERY_ENTROPY_FL_STRONG;

      got |= flags;
      next += n;
    } else {
      last_err = err;
    }
  }

  /* Do not report success unless at least one source was strong. */
  if (0 == (got & OTTERY_ENTROPY_FL_STRONG))
    return last_err ? last_err : OTTERY_ERR_INIT_STRONG_RNG;

  *flags_out = got;
  *buflen = next - bytes;

  return 0;
}
