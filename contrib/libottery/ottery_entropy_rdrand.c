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

#if defined(i386) || \
    defined(__i386) || \
    defined(__x86_64) || \
    defined(__M_IX86) || \
    defined(_M_IX86) || \
    defined(__INTEL_COMPILER)

/** Helper: invoke the RDRAND instruction to get 4 random bytes in the output
 * value. Return 0 on success, and an error on failure. */
static int
rdrand(uint32_t *therand) {
 unsigned char status;
 __asm volatile(".byte 0x0F, 0xC7, 0xF0 ; setc %1"
 : "=a" (*therand), "=qm" (status));
 return (status)==1 ? 0 : OTTERY_ERR_INIT_STRONG_RNG;
}

/** Generate bytes using the Intel RDRAND instruction. */
static int
ottery_get_entropy_rdrand(const struct ottery_entropy_config *cfg,
                          struct ottery_entropy_state *state,
                           uint8_t *out, size_t outlen)
{
  int err;
  uint32_t *up = (uint32_t *) out;
  (void) cfg;
  (void) state;
  if (! (ottery_get_cpu_capabilities_() & OTTERY_CPUCAP_RAND))
    return OTTERY_ERR_INIT_STRONG_RNG;
  while (outlen >= 4) {
    if ((err = rdrand(up)))
      return err;
    up += 1;
    outlen -= 4;
  }
  if (outlen) {
    uint32_t tmp;
    if ((err = rdrand(&tmp)))
      return err;
    memcpy(up, &tmp, outlen);
  }
  return 0;
}

#define ENTROPY_SOURCE_RDRAND                                           \
  { ottery_get_entropy_rdrand,  SRC(RDRAND)|DOM(CPU)|FL(FAST)|FL(STRONG) }

#endif

