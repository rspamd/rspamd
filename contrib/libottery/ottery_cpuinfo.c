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
#include "ottery-internal.h"
#include <stdint.h>

#if defined(i386) || \
    defined(__i386) || \
    defined(__M_IX86) || \
    defined(_M_IX86)
#define X86
#elif defined(__x86_64) || \
      defined(_M_AMD64)
#define X86
#define X86_64
#endif

#if defined(__arm__) || \
  defined(_M_ARM)
#define ARM
#endif

#if defined(X86)
#ifdef _MSC_VER
#include <intrin.h>
#define cpuid(a,b) __cpuid((b), (a))
#else
static void
cpuid(int index, int regs[4])
{
  unsigned int eax, ebx, ecx, edx;
#ifdef X86_64
  __asm("cpuid" : "=a"(eax), "=b" (ebx), "=c"(ecx), "=d"(edx)
        : "0"(index));
#else
  __asm volatile(
               "xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
               : "=a" (eax), "=r" (ebx), "=c" (ecx), "=d" (edx)
               : "0" (index)
               : "cc" );
#endif

  regs[0] = eax;
  regs[1] = ebx;
  regs[2] = ecx;
  regs[3] = edx;
}
#endif
#endif

static uint32_t disabled_cpu_capabilities = 0;

void
ottery_disable_cpu_capabilities_(uint32_t disable)
{
  disabled_cpu_capabilities |= disable;
}

uint32_t
ottery_get_cpu_capabilities_(void)
{
#ifdef X86
  uint32_t cap = 0;
  int res[4];
  cpuid(1, res);
  if (res[3] & (1<<26))
    cap |= OTTERY_CPUCAP_SIMD;
  if (res[2] & (1<<9))
    cap |= OTTERY_CPUCAP_SSSE3;
  if (res[2] & (1<<25))
    cap |= OTTERY_CPUCAP_AES;
  if (res[2] & (1<<30))
    cap |= OTTERY_CPUCAP_RAND;
#else
  uint32_t cap = OTTERY_CPUCAP_SIMD;
#endif
  return cap & ~disabled_cpu_capabilities;
}
