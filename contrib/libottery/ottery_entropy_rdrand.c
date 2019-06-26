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

extern int ottery_valgrind_;
/** Helper: invoke the RDRAND instruction to get 4 random bytes in the output
 * value. Return 1 on success, and 0 on failure. */
#define rdrand32(x) ({ unsigned char err = 0; __asm volatile(".byte 0x0f; .byte 0xc7; .byte 0xf0; setc %1":"=a"(x), "=qm"(err) :"a"(0) :"cc"); err; })

/** Generate bytes using the Intel RDRAND instruction. */
static int
ottery_get_entropy_rdrand(const struct ottery_entropy_config *cfg,
                          struct ottery_entropy_state *state,
                           uint8_t *out, size_t outlen)
{
  uint32_t up;
  (void) cfg;
  (void) state;
  if (! (ottery_get_cpu_capabilities_() & OTTERY_CPUCAP_RAND) || ottery_valgrind_)
    return OTTERY_ERR_INIT_STRONG_RNG;
  while (outlen >= 4) {
    if (rdrand32(up) != 1)
      return OTTERY_ERR_INIT_STRONG_RNG;
    memcpy (out, &up, sizeof (up));
    out += sizeof (up);
    outlen -= 4;
  }

  if (outlen) {
    if (rdrand32(up) != 1)
      return OTTERY_ERR_INIT_STRONG_RNG;
    memcpy(out, &up, outlen);
  }
  return 0;
}

#define ENTROPY_SOURCE_RDRAND                                           \
  { ottery_get_entropy_rdrand,  SRC(RDRAND)|DOM(CPU)|FL(FAST)|FL(STRONG) }

#endif

