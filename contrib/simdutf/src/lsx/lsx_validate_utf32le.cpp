
const char32_t *lsx_validate_utf32le(const char32_t *input, size_t size) {
  const char32_t *end = input + size;

  __m128i offset = __lsx_vreplgr2vr_w(uint32_t(0xffff2000));
  __m128i standardoffsetmax = __lsx_vreplgr2vr_w(uint32_t(0xfffff7ff));
  __m128i standardmax = __lsx_vldi(-2288); /*0x10ffff*/
  __m128i currentmax = __lsx_vldi(0x0);
  __m128i currentoffsetmax = __lsx_vldi(0x0);

  while (input + 4 < end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint32_t *>(input), 0);
    currentmax = __lsx_vmax_wu(in, currentmax);
    // 0xD8__ + 0x2000 = 0xF8__ => 0xF8__ > 0xF7FF
    currentoffsetmax =
        __lsx_vmax_wu(__lsx_vadd_w(in, offset), currentoffsetmax);

    input += 4;
  }

  __m128i is_zero =
      __lsx_vxor_v(__lsx_vmax_wu(currentmax, standardmax), standardmax);
  if (__lsx_bnz_v(is_zero)) {
    return nullptr;
  }

  is_zero = __lsx_vxor_v(__lsx_vmax_wu(currentoffsetmax, standardoffsetmax),
                         standardoffsetmax);
  if (__lsx_bnz_v(is_zero)) {
    return nullptr;
  }

  return input;
}

const result lsx_validate_utf32le_with_errors(const char32_t *input,
                                              size_t size) {
  const char32_t *start = input;
  const char32_t *end = input + size;

  __m128i offset = __lsx_vreplgr2vr_w(uint32_t(0xffff2000));
  __m128i standardoffsetmax = __lsx_vreplgr2vr_w(uint32_t(0xfffff7ff));
  __m128i standardmax = __lsx_vldi(-2288); /*0x10ffff*/
  __m128i currentmax = __lsx_vldi(0x0);
  __m128i currentoffsetmax = __lsx_vldi(0x0);

  while (input + 4 < end) {
    __m128i in = __lsx_vld(reinterpret_cast<const uint32_t *>(input), 0);
    currentmax = __lsx_vmax_wu(in, currentmax);
    currentoffsetmax =
        __lsx_vmax_wu(__lsx_vadd_w(in, offset), currentoffsetmax);

    __m128i is_zero =
        __lsx_vxor_v(__lsx_vmax_wu(currentmax, standardmax), standardmax);
    if (__lsx_bnz_v(is_zero)) {
      return result(error_code::TOO_LARGE, input - start);
    }

    is_zero = __lsx_vxor_v(__lsx_vmax_wu(currentoffsetmax, standardoffsetmax),
                           standardoffsetmax);
    if (__lsx_bnz_v(is_zero)) {
      return result(error_code::SURROGATE, input - start);
    }

    input += 4;
  }

  return result(error_code::SUCCESS, input - start);
}
