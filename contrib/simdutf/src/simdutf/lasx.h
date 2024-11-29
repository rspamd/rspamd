#ifndef SIMDUTF_LASX_H
#define SIMDUTF_LASX_H

#ifdef SIMDUTF_FALLBACK_H
  #error "lasx.h must be included before fallback.h"
#endif

#include "simdutf/portability.h"

#ifndef SIMDUTF_IMPLEMENTATION_LASX
  #define SIMDUTF_IMPLEMENTATION_LASX (SIMDUTF_IS_LASX)
#endif
#if SIMDUTF_IMPLEMENTATION_LASX && SIMDUTF_IS_LASX
  #define SIMDUTF_CAN_ALWAYS_RUN_LASX 1
#else
  #define SIMDUTF_CAN_ALWAYS_RUN_LASX 0
#endif

#define SIMDUTF_CAN_ALWAYS_RUN_FALLBACK (SIMDUTF_IMPLEMENTATION_FALLBACK)
#include "simdutf/internal/isadetection.h"

#if SIMDUTF_IMPLEMENTATION_LASX

namespace simdutf {
/**
 * Implementation for LoongArch ASX.
 */
namespace lasx {} // namespace lasx
} // namespace simdutf

  #include "simdutf/lasx/implementation.h"

  #include "simdutf/lasx/begin.h"

  // Declarations
  #include "simdutf/lasx/intrinsics.h"
  #include "simdutf/lasx/bitmanipulation.h"
  #include "simdutf/lasx/simd.h"

  #include "simdutf/lasx/end.h"

#endif // SIMDUTF_IMPLEMENTATION_LASX

#endif // SIMDUTF_LASX_H
