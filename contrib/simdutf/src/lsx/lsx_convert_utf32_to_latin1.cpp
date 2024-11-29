std::pair<const char32_t *, char *>
lsx_convert_utf32_to_latin1(const char32_t *buf, size_t len,
                            char *latin1_output) {
  const char32_t *end = buf + len;
  const v16u8 shuf_mask = {0, 4, 8, 12, 16, 20, 24, 28, 0, 0, 0, 0, 0, 0, 0, 0};
  __m128i v_ff = __lsx_vrepli_w(0xFF);

  while (buf + 16 <= end) {
    __m128i in1 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m128i in2 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 16);

    __m128i in12 = __lsx_vor_v(in1, in2);
    if (__lsx_bz_v(__lsx_vslt_wu(v_ff, in12))) {
      // 1. pack the bytes
      __m128i latin1_packed = __lsx_vshuf_b(in2, in1, (__m128i)shuf_mask);
      // 2. store (8 bytes)
      __lsx_vst(latin1_packed, reinterpret_cast<uint8_t *>(latin1_output), 0);
      // 3. adjust pointers
      buf += 8;
      latin1_output += 8;
    } else {
      return std::make_pair(nullptr, reinterpret_cast<char *>(latin1_output));
    }
  } // while
  return std::make_pair(buf, latin1_output);
}

std::pair<result, char *>
lsx_convert_utf32_to_latin1_with_errors(const char32_t *buf, size_t len,
                                        char *latin1_output) {
  const char32_t *start = buf;
  const char32_t *end = buf + len;

  const v16u8 shuf_mask = {0, 4, 8, 12, 16, 20, 24, 28, 0, 0, 0, 0, 0, 0, 0, 0};
  __m128i v_ff = __lsx_vrepli_w(0xFF);

  while (buf + 16 <= end) {
    __m128i in1 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 0);
    __m128i in2 = __lsx_vld(reinterpret_cast<const uint32_t *>(buf), 16);

    __m128i in12 = __lsx_vor_v(in1, in2);

    if (__lsx_bz_v(__lsx_vslt_wu(v_ff, in12))) {
      // 1. pack the bytes
      __m128i latin1_packed = __lsx_vshuf_b(in2, in1, (__m128i)shuf_mask);
      // 2. store (8 bytes)
      __lsx_vst(latin1_packed, reinterpret_cast<uint8_t *>(latin1_output), 0);
      // 3. adjust pointers
      buf += 8;
      latin1_output += 8;
    } else {
      // Let us do a scalar fallback.
      for (int k = 0; k < 8; k++) {
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
