std::pair<const char32_t *, char *>
lasx_convert_utf32_to_latin1(const char32_t *buf, size_t len,
                             char *latin1_output) {
  const char32_t *end = buf + len;
  const __m256i shuf_mask = ____m256i(
      (__m128i)v16u8{0, 4, 8, 12, 16, 20, 24, 28, 0, 0, 0, 0, 0, 0, 0, 0});
  __m256i v_ff = __lasx_xvrepli_w(0xFF);

  while (buf + 16 <= end) {
    __m256i in1 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m256i in2 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 32);

    __m256i in12 = __lasx_xvor_v(in1, in2);
    if (__lasx_xbz_v(__lasx_xvslt_wu(v_ff, in12))) {
      // 1. pack the bytes
      __m256i latin1_packed_tmp = __lasx_xvshuf_b(in2, in1, shuf_mask);
      latin1_packed_tmp = __lasx_xvpermi_d(latin1_packed_tmp, 0b00001000);
      __m128i latin1_packed = lasx_extracti128_lo(latin1_packed_tmp);
      latin1_packed = __lsx_vpermi_w(latin1_packed, latin1_packed, 0b11011000);
      // 2. store (8 bytes)
      __lsx_vst(latin1_packed, reinterpret_cast<uint8_t *>(latin1_output), 0);
      // 3. adjust pointers
      buf += 16;
      latin1_output += 16;
    } else {
      return std::make_pair(nullptr, reinterpret_cast<char *>(latin1_output));
    }
  } // while
  return std::make_pair(buf, latin1_output);
}

std::pair<result, char *>
lasx_convert_utf32_to_latin1_with_errors(const char32_t *buf, size_t len,
                                         char *latin1_output) {
  const char32_t *start = buf;
  const char32_t *end = buf + len;

  const __m256i shuf_mask = ____m256i(
      (__m128i)v16u8{0, 4, 8, 12, 16, 20, 24, 28, 0, 0, 0, 0, 0, 0, 0, 0});
  __m256i v_ff = __lasx_xvrepli_w(0xFF);

  while (buf + 16 <= end) {
    __m256i in1 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m256i in2 = __lasx_xvld(reinterpret_cast<const uint32_t *>(buf), 32);

    __m256i in12 = __lasx_xvor_v(in1, in2);
    if (__lasx_xbz_v(__lasx_xvslt_wu(v_ff, in12))) {
      // 1. pack the bytes
      __m256i latin1_packed_tmp = __lasx_xvshuf_b(in2, in1, shuf_mask);
      latin1_packed_tmp = __lasx_xvpermi_d(latin1_packed_tmp, 0b00001000);
      __m128i latin1_packed = lasx_extracti128_lo(latin1_packed_tmp);
      latin1_packed = __lsx_vpermi_w(latin1_packed, latin1_packed, 0b11011000);
      // 2. store (8 bytes)
      __lsx_vst(latin1_packed, reinterpret_cast<uint8_t *>(latin1_output), 0);
      // 3. adjust pointers
      buf += 16;
      latin1_output += 16;
    } else {
      // Let us do a scalar fallback.
      for (int k = 0; k < 16; k++) {
        uint32_t word = buf[k];
        if (word <= 0xff) {
          *latin1_output++ = char(word);
        } else {
          return std::make_pair(result(error_code::TOO_LARGE, buf - start + k),
                                latin1_output);
        }
      }
    }
  } // while
  return std::make_pair(result(error_code::SUCCESS, buf - start),
                        latin1_output);
}
