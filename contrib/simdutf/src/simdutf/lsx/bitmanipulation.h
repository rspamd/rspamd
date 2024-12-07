#ifndef SIMDUTF_LSX_BITMANIPULATION_H
#define SIMDUTF_LSX_BITMANIPULATION_H

#include "simdutf.h"
#include <limits>

namespace simdutf {
namespace SIMDUTF_IMPLEMENTATION {
namespace {

simdutf_really_inline int count_ones(uint64_t input_num) {
  return __lsx_vpickve2gr_w(__lsx_vpcnt_d(__lsx_vreplgr2vr_d(input_num)), 0);
}

#if SIMDUTF_NEED_TRAILING_ZEROES
simdutf_really_inline int trailing_zeroes(uint64_t input_num) {
  return __builtin_ctzll(input_num);
}
#endif

} // unnamed namespace
} // namespace SIMDUTF_IMPLEMENTATION
} // namespace simdutf

#endif // SIMDUTF_LSX_BITMANIPULATION_H
