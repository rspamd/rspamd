#ifndef SIMDUTF_LSX_SIMD_H
#define SIMDUTF_LSX_SIMD_H

#include "simdutf.h"
#include "simdutf/lsx/bitmanipulation.h"
#include <type_traits>

namespace simdutf {
namespace SIMDUTF_IMPLEMENTATION {
namespace {
namespace simd {

template <typename T> struct simd8;

//
// Base class of simd8<uint8_t> and simd8<bool>, both of which use __m128i
// internally.
//
template <typename T, typename Mask = simd8<bool>> struct base_u8 {
  __m128i value;
  static const int SIZE = sizeof(value);

  // Conversion from/to SIMD register
  simdutf_really_inline base_u8(const __m128i _value) : value(_value) {}
  simdutf_really_inline operator const __m128i &() const { return this->value; }
  simdutf_really_inline operator __m128i &() { return this->value; }
  simdutf_really_inline T first() const {
    return __lsx_vpickve2gr_bu(this->value, 0);
  }
  simdutf_really_inline T last() const {
    return __lsx_vpickve2gr_bu(this->value, 15);
  }

  // Bit operations
  simdutf_really_inline simd8<T> operator|(const simd8<T> other) const {
    return __lsx_vor_v(this->value, other);
  }
  simdutf_really_inline simd8<T> operator&(const simd8<T> other) const {
    return __lsx_vand_v(this->value, other);
  }
  simdutf_really_inline simd8<T> operator^(const simd8<T> other) const {
    return __lsx_vxor_v(this->value, other);
  }
  simdutf_really_inline simd8<T> bit_andnot(const simd8<T> other) const {
    return __lsx_vandn_v(this->value, other);
  }
  simdutf_really_inline simd8<T> operator~() const { return *this ^ 0xFFu; }
  simdutf_really_inline simd8<T> &operator|=(const simd8<T> other) {
    auto this_cast = static_cast<simd8<T> *>(this);
    *this_cast = *this_cast | other;
    return *this_cast;
  }
  simdutf_really_inline simd8<T> &operator&=(const simd8<T> other) {
    auto this_cast = static_cast<simd8<T> *>(this);
    *this_cast = *this_cast & other;
    return *this_cast;
  }
  simdutf_really_inline simd8<T> &operator^=(const simd8<T> other) {
    auto this_cast = static_cast<simd8<T> *>(this);
    *this_cast = *this_cast ^ other;
    return *this_cast;
  }

  friend simdutf_really_inline Mask operator==(const simd8<T> lhs,
                                               const simd8<T> rhs) {
    return __lsx_vseq_b(lhs, rhs);
  }

  template <int N = 1>
  simdutf_really_inline simd8<T> prev(const simd8<T> prev_chunk) const {
    return __lsx_vor_v(__lsx_vbsll_v(this->value, N),
                       __lsx_vbsrl_v(prev_chunk.value, 16 - N));
  }
};

// SIMD byte mask type (returned by things like eq and gt)
template <> struct simd8<bool> : base_u8<bool> {
  typedef uint16_t bitmask_t;
  typedef uint32_t bitmask2_t;

  static simdutf_really_inline simd8<bool> splat(bool _value) {
    return __lsx_vreplgr2vr_b(uint8_t(-(!!_value)));
  }

  simdutf_really_inline simd8(const __m128i _value) : base_u8<bool>(_value) {}
  // False constructor
  simdutf_really_inline simd8() : simd8(__lsx_vldi(0)) {}
  // Splat constructor
  simdutf_really_inline simd8(bool _value) : simd8(splat(_value)) {}
  simdutf_really_inline void store(uint8_t dst[16]) const {
    return __lsx_vst(this->value, dst, 0);
  }

  simdutf_really_inline uint32_t to_bitmask() const {
    return __lsx_vpickve2gr_wu(__lsx_vmsknz_b(*this), 0);
  }

  simdutf_really_inline bool any() const {
    return __lsx_vpickve2gr_hu(__lsx_vmsknz_b(*this), 0) != 0;
  }
  simdutf_really_inline bool none() const {
    return __lsx_vpickve2gr_hu(__lsx_vmsknz_b(*this), 0) == 0;
  }
  simdutf_really_inline bool all() const {
    return __lsx_vpickve2gr_hu(__lsx_vmsknz_b(*this), 0) == 0xFFFF;
  }
};

// Unsigned bytes
template <> struct simd8<uint8_t> : base_u8<uint8_t> {
  static simdutf_really_inline simd8<uint8_t> splat(uint8_t _value) {
    return __lsx_vreplgr2vr_b(_value);
  }
  static simdutf_really_inline simd8<uint8_t> zero() { return __lsx_vldi(0); }
  static simdutf_really_inline simd8<uint8_t> load(const uint8_t *values) {
    return __lsx_vld(values, 0);
  }
  simdutf_really_inline simd8(const __m128i _value)
      : base_u8<uint8_t>(_value) {}
  // Zero constructor
  simdutf_really_inline simd8() : simd8(zero()) {}
  // Array constructor
  simdutf_really_inline simd8(const uint8_t values[16]) : simd8(load(values)) {}
  // Splat constructor
  simdutf_really_inline simd8(uint8_t _value) : simd8(splat(_value)) {}
  // Member-by-member initialization

  simdutf_really_inline
  simd8(uint8_t v0, uint8_t v1, uint8_t v2, uint8_t v3, uint8_t v4, uint8_t v5,
        uint8_t v6, uint8_t v7, uint8_t v8, uint8_t v9, uint8_t v10,
        uint8_t v11, uint8_t v12, uint8_t v13, uint8_t v14, uint8_t v15)
      : simd8((__m128i)v16u8{v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,
                             v12, v13, v14, v15}) {}

  // Repeat 16 values as many times as necessary (usually for lookup tables)
  simdutf_really_inline static simd8<uint8_t>
  repeat_16(uint8_t v0, uint8_t v1, uint8_t v2, uint8_t v3, uint8_t v4,
            uint8_t v5, uint8_t v6, uint8_t v7, uint8_t v8, uint8_t v9,
            uint8_t v10, uint8_t v11, uint8_t v12, uint8_t v13, uint8_t v14,
            uint8_t v15) {
    return simd8<uint8_t>(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12,
                          v13, v14, v15);
  }

  // Store to array
  simdutf_really_inline void store(uint8_t dst[16]) const {
    return __lsx_vst(this->value, dst, 0);
  }

  // Saturated math
  simdutf_really_inline simd8<uint8_t>
  saturating_add(const simd8<uint8_t> other) const {
    return __lsx_vsadd_bu(this->value, other);
  }
  simdutf_really_inline simd8<uint8_t>
  saturating_sub(const simd8<uint8_t> other) const {
    return __lsx_vssub_bu(this->value, other);
  }

  // Addition/subtraction are the same for signed and unsigned
  simdutf_really_inline simd8<uint8_t>
  operator+(const simd8<uint8_t> other) const {
    return __lsx_vadd_b(this->value, other);
  }
  simdutf_really_inline simd8<uint8_t>
  operator-(const simd8<uint8_t> other) const {
    return __lsx_vsub_b(this->value, other);
  }
  simdutf_really_inline simd8<uint8_t> &operator+=(const simd8<uint8_t> other) {
    *this = *this + other;
    return *this;
  }
  simdutf_really_inline simd8<uint8_t> &operator-=(const simd8<uint8_t> other) {
    *this = *this - other;
    return *this;
  }

  // Order-specific operations
  simdutf_really_inline simd8<uint8_t>
  max_val(const simd8<uint8_t> other) const {
    return __lsx_vmax_bu(*this, other);
  }
  simdutf_really_inline simd8<uint8_t>
  min_val(const simd8<uint8_t> other) const {
    return __lsx_vmin_bu(*this, other);
  }
  simdutf_really_inline simd8<bool>
  operator<=(const simd8<uint8_t> other) const {
    return __lsx_vsle_bu(*this, other);
  }
  simdutf_really_inline simd8<bool>
  operator>=(const simd8<uint8_t> other) const {
    return __lsx_vsle_bu(other, *this);
  }
  simdutf_really_inline simd8<bool>
  operator<(const simd8<uint8_t> other) const {
    return __lsx_vslt_bu(*this, other);
  }
  simdutf_really_inline simd8<bool>
  operator>(const simd8<uint8_t> other) const {
    return __lsx_vslt_bu(other, *this);
  }
  // Same as >, but instead of guaranteeing all 1's == true, false = 0 and true
  // = nonzero. For ARM, returns all 1's.
  simdutf_really_inline simd8<uint8_t>
  gt_bits(const simd8<uint8_t> other) const {
    return simd8<uint8_t>(*this > other);
  }
  // Same as <, but instead of guaranteeing all 1's == true, false = 0 and true
  // = nonzero. For ARM, returns all 1's.
  simdutf_really_inline simd8<uint8_t>
  lt_bits(const simd8<uint8_t> other) const {
    return simd8<uint8_t>(*this < other);
  }

  // Bit-specific operations
  simdutf_really_inline simd8<bool> any_bits_set(simd8<uint8_t> bits) const {
    return __lsx_vslt_bu(__lsx_vldi(0), __lsx_vand_v(this->value, bits));
  }
  simdutf_really_inline bool is_ascii() const {
    return __lsx_vpickve2gr_hu(__lsx_vmskgez_b(this->value), 0) == 0xFFFF;
  }

  simdutf_really_inline bool any_bits_set_anywhere() const {
    return __lsx_vpickve2gr_hu(__lsx_vmsknz_b(this->value), 0) > 0;
  }
  simdutf_really_inline bool any_bits_set_anywhere(simd8<uint8_t> bits) const {
    return (*this & bits).any_bits_set_anywhere();
  }
  template <int N> simdutf_really_inline simd8<uint8_t> shr() const {
    return __lsx_vsrli_b(this->value, N);
  }
  template <int N> simdutf_really_inline simd8<uint8_t> shl() const {
    return __lsx_vslli_b(this->value, N);
  }

  // Perform a lookup assuming the value is between 0 and 16 (undefined behavior
  // for out of range values)
  template <typename L>
  simdutf_really_inline simd8<L> lookup_16(simd8<L> lookup_table) const {
    return lookup_table.apply_lookup_16_to(*this);
  }

  template <typename L>
  simdutf_really_inline simd8<L>
  lookup_16(L replace0, L replace1, L replace2, L replace3, L replace4,
            L replace5, L replace6, L replace7, L replace8, L replace9,
            L replace10, L replace11, L replace12, L replace13, L replace14,
            L replace15) const {
    return lookup_16(simd8<L>::repeat_16(
        replace0, replace1, replace2, replace3, replace4, replace5, replace6,
        replace7, replace8, replace9, replace10, replace11, replace12,
        replace13, replace14, replace15));
  }

  template <typename T>
  simdutf_really_inline simd8<uint8_t>
  apply_lookup_16_to(const simd8<T> original) const {
    __m128i original_tmp = __lsx_vand_v(original, __lsx_vldi(0x1f));
    return __lsx_vshuf_b(__lsx_vldi(0), *this, simd8<uint8_t>(original_tmp));
  }
};

// Signed bytes
template <> struct simd8<int8_t> {
  __m128i value;

  static simdutf_really_inline simd8<int8_t> splat(int8_t _value) {
    return __lsx_vreplgr2vr_b(_value);
  }
  static simdutf_really_inline simd8<int8_t> zero() { return __lsx_vldi(0); }
  static simdutf_really_inline simd8<int8_t> load(const int8_t values[16]) {
    return __lsx_vld(values, 0);
  }

  template <endianness big_endian>
  simdutf_really_inline void store_ascii_as_utf16(char16_t *p) const {
    __m128i zero = __lsx_vldi(0);
    if (match_system(big_endian)) {
      __lsx_vst(__lsx_vilvl_b(zero, (__m128i)this->value),
                reinterpret_cast<uint16_t *>(p), 0);
      __lsx_vst(__lsx_vilvh_b(zero, (__m128i)this->value),
                reinterpret_cast<uint16_t *>(p + 8), 0);
    } else {
      __lsx_vst(__lsx_vilvl_b((__m128i)this->value, zero),
                reinterpret_cast<uint16_t *>(p), 0);
      __lsx_vst(__lsx_vilvh_b((__m128i)this->value, zero),
                reinterpret_cast<uint16_t *>(p + 8), 0);
    }
  }

  simdutf_really_inline void store_ascii_as_utf32(char32_t *p) const {
    __m128i zero = __lsx_vldi(0);
    __m128i in16low = __lsx_vilvl_b(zero, (__m128i)this->value);
    __m128i in16high = __lsx_vilvh_b(zero, (__m128i)this->value);
    __m128i in32_0 = __lsx_vilvl_h(zero, in16low);
    __m128i in32_1 = __lsx_vilvh_h(zero, in16low);
    __m128i in32_2 = __lsx_vilvl_h(zero, in16high);
    __m128i in32_3 = __lsx_vilvh_h(zero, in16high);
    __lsx_vst(in32_0, reinterpret_cast<uint32_t *>(p), 0);
    __lsx_vst(in32_1, reinterpret_cast<uint32_t *>(p + 4), 0);
    __lsx_vst(in32_2, reinterpret_cast<uint32_t *>(p + 8), 0);
    __lsx_vst(in32_3, reinterpret_cast<uint32_t *>(p + 12), 0);
  }

  // In places where the table can be reused, which is most uses in simdutf, it
  // is worth it to do 4 table lookups, as there is no direct zero extension
  // from u8 to u32.
  simdutf_really_inline void store_ascii_as_utf32_tbl(char32_t *p) const {
    const simd8<uint8_t> tb1{0, 255, 255, 255, 1, 255, 255, 255,
                             2, 255, 255, 255, 3, 255, 255, 255};
    const simd8<uint8_t> tb2{4, 255, 255, 255, 5, 255, 255, 255,
                             6, 255, 255, 255, 7, 255, 255, 255};
    const simd8<uint8_t> tb3{8,  255, 255, 255, 9,  255, 255, 255,
                             10, 255, 255, 255, 11, 255, 255, 255};
    const simd8<uint8_t> tb4{12, 255, 255, 255, 13, 255, 255, 255,
                             14, 255, 255, 255, 15, 255, 255, 255};

    // encourage store pairing and interleaving
    const auto shuf1 = this->apply_lookup_16_to(tb1);
    const auto shuf2 = this->apply_lookup_16_to(tb2);
    shuf1.store(reinterpret_cast<int8_t *>(p));
    shuf2.store(reinterpret_cast<int8_t *>(p + 4));

    const auto shuf3 = this->apply_lookup_16_to(tb3);
    const auto shuf4 = this->apply_lookup_16_to(tb4);
    shuf3.store(reinterpret_cast<int8_t *>(p + 8));
    shuf4.store(reinterpret_cast<int8_t *>(p + 12));
  }
  // Conversion from/to SIMD register
  simdutf_really_inline simd8(const __m128i _value) : value(_value) {}
  simdutf_really_inline operator const __m128i &() const { return this->value; }

  simdutf_really_inline operator const __m128i() const { return this->value; }

  simdutf_really_inline operator __m128i &() { return this->value; }

  // Zero constructor
  simdutf_really_inline simd8() : simd8(zero()) {}
  // Splat constructor
  simdutf_really_inline simd8(int8_t _value) : simd8(splat(_value)) {}
  // Array constructor
  simdutf_really_inline simd8(const int8_t *values) : simd8(load(values)) {}
  // Member-by-member initialization

  simdutf_really_inline simd8(int8_t v0, int8_t v1, int8_t v2, int8_t v3,
                              int8_t v4, int8_t v5, int8_t v6, int8_t v7,
                              int8_t v8, int8_t v9, int8_t v10, int8_t v11,
                              int8_t v12, int8_t v13, int8_t v14, int8_t v15)
      : simd8((__m128i)v16i8{v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11,
                             v12, v13, v14, v15}) {}

  // Repeat 16 values as many times as necessary (usually for lookup tables)
  simdutf_really_inline static simd8<int8_t>
  repeat_16(int8_t v0, int8_t v1, int8_t v2, int8_t v3, int8_t v4, int8_t v5,
            int8_t v6, int8_t v7, int8_t v8, int8_t v9, int8_t v10, int8_t v11,
            int8_t v12, int8_t v13, int8_t v14, int8_t v15) {
    return simd8<int8_t>(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12,
                         v13, v14, v15);
  }

  // Store to array
  simdutf_really_inline void store(int8_t dst[16]) const {
    return __lsx_vst(value, dst, 0);
  }

  simdutf_really_inline operator simd8<uint8_t>() const {
    return ((__m128i)this->value);
  }

  simdutf_really_inline simd8<int8_t>
  operator|(const simd8<int8_t> other) const {
    return __lsx_vor_v((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<int8_t>
  operator&(const simd8<int8_t> other) const {
    return __lsx_vand_v((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<int8_t>
  operator^(const simd8<int8_t> other) const {
    return __lsx_vxor_v((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<int8_t>
  bit_andnot(const simd8<int8_t> other) const {
    return __lsx_vandn_v((__m128i)other.value, (__m128i)value);
  }

  // Math
  simdutf_really_inline simd8<int8_t>
  operator+(const simd8<int8_t> other) const {
    return __lsx_vadd_b((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<int8_t>
  operator-(const simd8<int8_t> other) const {
    return __lsx_vsub_b((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<int8_t> &operator+=(const simd8<int8_t> other) {
    *this = *this + other;
    return *this;
  }
  simdutf_really_inline simd8<int8_t> &operator-=(const simd8<int8_t> other) {
    *this = *this - other;
    return *this;
  }

  simdutf_really_inline bool is_ascii() const {
    return (__lsx_vpickve2gr_hu(__lsx_vmskgez_b((__m128i)this->value), 0) ==
            0xffff);
  }

  // Order-sensitive comparisons
  simdutf_really_inline simd8<int8_t> max_val(const simd8<int8_t> other) const {
    return __lsx_vmax_b((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<int8_t> min_val(const simd8<int8_t> other) const {
    return __lsx_vmin_b((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<bool> operator>(const simd8<int8_t> other) const {
    return __lsx_vslt_b((__m128i)other.value, (__m128i)value);
  }
  simdutf_really_inline simd8<bool> operator<(const simd8<int8_t> other) const {
    return __lsx_vslt_b((__m128i)value, (__m128i)other.value);
  }
  simdutf_really_inline simd8<bool>
  operator==(const simd8<int8_t> other) const {
    return __lsx_vseq_b((__m128i)value, (__m128i)other.value);
  }

  template <int N = 1>
  simdutf_really_inline simd8<int8_t>
  prev(const simd8<int8_t> prev_chunk) const {
    return __lsx_vor_v(__lsx_vbsll_v(this->value, N),
                       __lsx_vbsrl_v(prev_chunk.value, 16 - N));
  }

  // Perform a lookup assuming no value is larger than 16
  template <typename L>
  simdutf_really_inline simd8<L> lookup_16(simd8<L> lookup_table) const {
    return lookup_table.apply_lookup_16_to(*this);
  }
  template <typename L>
  simdutf_really_inline simd8<L>
  lookup_16(L replace0, L replace1, L replace2, L replace3, L replace4,
            L replace5, L replace6, L replace7, L replace8, L replace9,
            L replace10, L replace11, L replace12, L replace13, L replace14,
            L replace15) const {
    return lookup_16(simd8<L>::repeat_16(
        replace0, replace1, replace2, replace3, replace4, replace5, replace6,
        replace7, replace8, replace9, replace10, replace11, replace12,
        replace13, replace14, replace15));
  }

  template <typename T>
  simdutf_really_inline simd8<int8_t>
  apply_lookup_16_to(const simd8<T> original) const {
    __m128i original_tmp = __lsx_vand_v(original, __lsx_vldi(0x1f));
    return __lsx_vshuf_b(__lsx_vldi(0), (__m128i)this->value,
                         simd8<uint8_t>(original_tmp));
  }
};

template <typename T> struct simd8x64 {
  static constexpr int NUM_CHUNKS = 64 / sizeof(simd8<T>);
  static_assert(
      NUM_CHUNKS == 4,
      "LoongArch kernel should use four registers per 64-byte block.");
  simd8<T> chunks[NUM_CHUNKS];

  simd8x64(const simd8x64<T> &o) = delete; // no copy allowed
  simd8x64<T> &
  operator=(const simd8<T> other) = delete; // no assignment allowed
  simd8x64() = delete;                      // no default constructor allowed

  simdutf_really_inline simd8x64(const simd8<T> chunk0, const simd8<T> chunk1,
                                 const simd8<T> chunk2, const simd8<T> chunk3)
      : chunks{chunk0, chunk1, chunk2, chunk3} {}
  simdutf_really_inline simd8x64(const T *ptr)
      : chunks{simd8<T>::load(ptr),
               simd8<T>::load(ptr + sizeof(simd8<T>) / sizeof(T)),
               simd8<T>::load(ptr + 2 * sizeof(simd8<T>) / sizeof(T)),
               simd8<T>::load(ptr + 3 * sizeof(simd8<T>) / sizeof(T))} {}

  simdutf_really_inline void store(T *ptr) const {
    this->chunks[0].store(ptr + sizeof(simd8<T>) * 0 / sizeof(T));
    this->chunks[1].store(ptr + sizeof(simd8<T>) * 1 / sizeof(T));
    this->chunks[2].store(ptr + sizeof(simd8<T>) * 2 / sizeof(T));
    this->chunks[3].store(ptr + sizeof(simd8<T>) * 3 / sizeof(T));
  }

  simdutf_really_inline simd8x64<T> &operator|=(const simd8x64<T> &other) {
    this->chunks[0] |= other.chunks[0];
    this->chunks[1] |= other.chunks[1];
    this->chunks[2] |= other.chunks[2];
    this->chunks[3] |= other.chunks[3];
    return *this;
  }

  simdutf_really_inline simd8<T> reduce_or() const {
    return (this->chunks[0] | this->chunks[1]) |
           (this->chunks[2] | this->chunks[3]);
  }

  simdutf_really_inline bool is_ascii() const { return reduce_or().is_ascii(); }

  template <endianness endian>
  simdutf_really_inline void store_ascii_as_utf16(char16_t *ptr) const {
    this->chunks[0].template store_ascii_as_utf16<endian>(ptr +
                                                          sizeof(simd8<T>) * 0);
    this->chunks[1].template store_ascii_as_utf16<endian>(ptr +
                                                          sizeof(simd8<T>) * 1);
    this->chunks[2].template store_ascii_as_utf16<endian>(ptr +
                                                          sizeof(simd8<T>) * 2);
    this->chunks[3].template store_ascii_as_utf16<endian>(ptr +
                                                          sizeof(simd8<T>) * 3);
  }

  simdutf_really_inline void store_ascii_as_utf32(char32_t *ptr) const {
    this->chunks[0].store_ascii_as_utf32_tbl(ptr + sizeof(simd8<T>) * 0);
    this->chunks[1].store_ascii_as_utf32_tbl(ptr + sizeof(simd8<T>) * 1);
    this->chunks[2].store_ascii_as_utf32_tbl(ptr + sizeof(simd8<T>) * 2);
    this->chunks[3].store_ascii_as_utf32_tbl(ptr + sizeof(simd8<T>) * 3);
  }

  simdutf_really_inline uint64_t to_bitmask() const {
    __m128i mask = __lsx_vbsll_v(__lsx_vmsknz_b(this->chunks[3]), 6);
    mask = __lsx_vor_v(mask, __lsx_vbsll_v(__lsx_vmsknz_b(this->chunks[2]), 4));
    mask = __lsx_vor_v(mask, __lsx_vbsll_v(__lsx_vmsknz_b(this->chunks[1]), 2));
    mask = __lsx_vor_v(mask, __lsx_vmsknz_b(this->chunks[0]));
    return __lsx_vpickve2gr_du(mask, 0);
  }

  simdutf_really_inline uint64_t eq(const T m) const {
    const simd8<T> mask = simd8<T>::splat(m);
    return simd8x64<bool>(this->chunks[0] == mask, this->chunks[1] == mask,
                          this->chunks[2] == mask, this->chunks[3] == mask)
        .to_bitmask();
  }

  simdutf_really_inline uint64_t lteq(const T m) const {
    const simd8<T> mask = simd8<T>::splat(m);
    return simd8x64<bool>(this->chunks[0] <= mask, this->chunks[1] <= mask,
                          this->chunks[2] <= mask, this->chunks[3] <= mask)
        .to_bitmask();
  }

  simdutf_really_inline uint64_t in_range(const T low, const T high) const {
    const simd8<T> mask_low = simd8<T>::splat(low);
    const simd8<T> mask_high = simd8<T>::splat(high);

    return simd8x64<bool>(
               (this->chunks[0] <= mask_high) & (this->chunks[0] >= mask_low),
               (this->chunks[1] <= mask_high) & (this->chunks[1] >= mask_low),
               (this->chunks[2] <= mask_high) & (this->chunks[2] >= mask_low),
               (this->chunks[3] <= mask_high) & (this->chunks[3] >= mask_low))
        .to_bitmask();
  }
  simdutf_really_inline uint64_t not_in_range(const T low, const T high) const {
    const simd8<T> mask_low = simd8<T>::splat(low);
    const simd8<T> mask_high = simd8<T>::splat(high);
    return simd8x64<bool>(
               (this->chunks[0] > mask_high) | (this->chunks[0] < mask_low),
               (this->chunks[1] > mask_high) | (this->chunks[1] < mask_low),
               (this->chunks[2] > mask_high) | (this->chunks[2] < mask_low),
               (this->chunks[3] > mask_high) | (this->chunks[3] < mask_low))
        .to_bitmask();
  }
  simdutf_really_inline uint64_t lt(const T m) const {
    const simd8<T> mask = simd8<T>::splat(m);
    return simd8x64<bool>(this->chunks[0] < mask, this->chunks[1] < mask,
                          this->chunks[2] < mask, this->chunks[3] < mask)
        .to_bitmask();
  }
  simdutf_really_inline uint64_t gt(const T m) const {
    const simd8<T> mask = simd8<T>::splat(m);
    return simd8x64<bool>(this->chunks[0] > mask, this->chunks[1] > mask,
                          this->chunks[2] > mask, this->chunks[3] > mask)
        .to_bitmask();
  }
  simdutf_really_inline uint64_t gteq(const T m) const {
    const simd8<T> mask = simd8<T>::splat(m);
    return simd8x64<bool>(this->chunks[0] >= mask, this->chunks[1] >= mask,
                          this->chunks[2] >= mask, this->chunks[3] >= mask)
        .to_bitmask();
  }
  simdutf_really_inline uint64_t gteq_unsigned(const uint8_t m) const {
    const simd8<uint8_t> mask = simd8<uint8_t>::splat(m);
    return simd8x64<bool>(simd8<uint8_t>(this->chunks[0].value) >= mask,
                          simd8<uint8_t>(this->chunks[1].value) >= mask,
                          simd8<uint8_t>(this->chunks[2].value) >= mask,
                          simd8<uint8_t>(this->chunks[3].value) >= mask)
        .to_bitmask();
  }
}; // struct simd8x64<T>
#include "simdutf/lsx/simd16-inl.h"
} // namespace simd
} // unnamed namespace
} // namespace SIMDUTF_IMPLEMENTATION
} // namespace simdutf

#endif // SIMDUTF_LSX_SIMD_H
