#ifndef SIMDUTF_LASX_INTRINSICS_H
#define SIMDUTF_LASX_INTRINSICS_H

#include "simdutf.h"

// This should be the correct header whether
// you use visual studio or other compilers.
#include <lsxintrin.h>
#include <lasxintrin.h>

#if defined(__loongarch_asx)
  #ifdef __clang__
    #define VREGS_PREFIX "$vr"
    #define XREGS_PREFIX "$xr"
  #else // GCC
    #define VREGS_PREFIX "$f"
    #define XREGS_PREFIX "$f"
  #endif
  #define __ALL_REGS                                                           \
    "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,"  \
    "27,28,29,30,31"
// Convert __m128i to __m256i
static inline __m256i ____m256i(__m128i in) {
  __m256i out = __lasx_xvldi(0);
  __asm__ volatile(".irp i," __ALL_REGS "\n\t"
                   " .ifc %[out], " XREGS_PREFIX "\\i    \n\t"
                   "  .irp j," __ALL_REGS "\n\t"
                   "   .ifc %[in], " VREGS_PREFIX "\\j  \n\t"
                   "    xvpermi.q $xr\\i, $xr\\j, 0x0  \n\t"
                   "   .endif                           \n\t"
                   "  .endr                             \n\t"
                   " .endif                             \n\t"
                   ".endr                               \n\t"
                   : [out] "+f"(out)
                   : [in] "f"(in));
  return out;
}
// Convert two __m128i to __m256i
static inline __m256i lasx_set_q(__m128i inhi, __m128i inlo) {
  __m256i out;
  __asm__ volatile(".irp i," __ALL_REGS "\n\t"
                   " .ifc %[hi], " VREGS_PREFIX "\\i    \n\t"
                   "  .irp j," __ALL_REGS "\n\t"
                   "   .ifc %[lo], " VREGS_PREFIX "\\j  \n\t"
                   "    xvpermi.q $xr\\i, $xr\\j, 0x20  \n\t"
                   "   .endif                           \n\t"
                   "  .endr                             \n\t"
                   " .endif                             \n\t"
                   ".endr                               \n\t"
                   ".ifnc %[out], %[hi]                 \n\t"
                   ".irp i," __ALL_REGS "\n\t"
                   " .ifc %[out], " XREGS_PREFIX "\\i   \n\t"
                   "  .irp j," __ALL_REGS "\n\t"
                   "   .ifc %[hi], " VREGS_PREFIX "\\j  \n\t"
                   "    xvori.b $xr\\i, $xr\\j, 0       \n\t"
                   "   .endif                           \n\t"
                   "  .endr                             \n\t"
                   " .endif                             \n\t"
                   ".endr                               \n\t"
                   ".endif                              \n\t"
                   : [out] "=f"(out), [hi] "+f"(inhi)
                   : [lo] "f"(inlo));
  return out;
}
// Convert __m256i low part to __m128i
static inline __m128i lasx_extracti128_lo(__m256i in) {
  __m128i out;
  __asm__ volatile(".ifnc %[out], %[in]                 \n\t"
                   ".irp i," __ALL_REGS "\n\t"
                   " .ifc %[out], " VREGS_PREFIX "\\i   \n\t"
                   "  .irp j," __ALL_REGS "\n\t"
                   "   .ifc %[in], " XREGS_PREFIX "\\j  \n\t"
                   "    vori.b $vr\\i, $vr\\j, 0        \n\t"
                   "   .endif                           \n\t"
                   "  .endr                             \n\t"
                   " .endif                             \n\t"
                   ".endr                               \n\t"
                   ".endif                              \n\t"
                   : [out] "=f"(out)
                   : [in] "f"(in));
  return out;
}
// Convert __m256i high part to __m128i
static inline __m128i lasx_extracti128_hi(__m256i in) {
  __m128i out;
  __asm__ volatile(".irp i," __ALL_REGS "\n\t"
                   " .ifc %[out], " VREGS_PREFIX "\\i   \n\t"
                   "  .irp j," __ALL_REGS "\n\t"
                   "   .ifc %[in], " XREGS_PREFIX "\\j  \n\t"
                   "    xvpermi.q $xr\\i, $xr\\j, 0x11  \n\t"
                   "   .endif                           \n\t"
                   "  .endr                             \n\t"
                   " .endif                             \n\t"
                   ".endr                               \n\t"
                   : [out] "=f"(out)
                   : [in] "f"(in));
  return out;
}
#endif

#endif //  SIMDUTF_LASX_INTRINSICS_H
