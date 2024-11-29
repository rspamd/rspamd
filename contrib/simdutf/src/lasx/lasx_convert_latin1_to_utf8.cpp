/*
  Returns a pair: the first unprocessed byte from buf and utf8_output
  A scalar routing should carry on the conversion of the tail.
*/

std::pair<const char *, char *>
lasx_convert_latin1_to_utf8(const char *latin1_input, size_t len,
                            char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const size_t safety_margin = 12;
  const char *end = latin1_input + len - safety_margin;

  // We always write 16 bytes, of which more than the first 8 bytes
  // are valid. A safety margin of 8 is more than sufficient.
  while (latin1_input + 16 <= end) {
    __m128i in8 = __lsx_vld(reinterpret_cast<const uint8_t *>(latin1_input), 0);
    uint32_t ascii_mask = __lsx_vpickve2gr_wu(__lsx_vmskgez_b(in8), 0);
    if (ascii_mask == 0xFFFF) {
      __lsx_vst(in8, utf8_output, 0);
      utf8_output += 16;
      latin1_input += 16;
      continue;
    }
    // We just fallback on UTF-16 code. This could be optimized/simplified
    // further.
    __m256i in16 = __lasx_vext2xv_hu_bu(____m256i(in8));
    // 1. prepare 2-byte values
    // input 8-bit word : [aabb|bbbb] x 16
    // expected output   : [1100|00aa|10bb|bbbb] x 16
    // t0 = [0000|00aa|bbbb|bb00]
    __m256i t0 = __lasx_xvslli_h(in16, 2);
    // t1 = [0000|00aa|0000|0000]
    __m256i t1 = __lasx_xvand_v(t0, __lasx_xvldi(-2785));
    // t3 = [0000|00aa|00bb|bbbb]
    __m256i t2 = __lasx_xvbitsel_v(t1, in16, __lasx_xvrepli_h(0x3f));
    // t4 = [1100|00aa|10bb|bbbb]
    __m256i t3 = __lasx_xvor_v(t2, __lasx_xvreplgr2vr_h(uint16_t(0xc080)));
    // merge ASCII and 2-byte codewords
    __m256i one_byte_bytemask = __lasx_xvsle_hu(in16, __lasx_xvrepli_h(0x7F));
    __m256i utf8_unpacked = __lasx_xvbitsel_v(t3, in16, one_byte_bytemask);

    const uint8_t *row0 =
        &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
            [lasx_1_2_utf8_bytes_mask[(ascii_mask & 0xFF)]][0];
    __m128i shuffle0 = __lsx_vld(row0 + 1, 0);
    __m128i utf8_unpacked_lo = lasx_extracti128_lo(utf8_unpacked);
    __m128i utf8_packed0 =
        __lsx_vshuf_b(utf8_unpacked_lo, utf8_unpacked_lo, shuffle0);
    __lsx_vst(utf8_packed0, utf8_output, 0);
    utf8_output += row0[0];

    const uint8_t *row1 = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                              [lasx_1_2_utf8_bytes_mask[(ascii_mask >> 8)]][0];
    __m128i shuffle1 = __lsx_vld(row1 + 1, 0);
    __m128i utf8_unpacked_hi = lasx_extracti128_hi(utf8_unpacked);
    __m128i utf8_packed1 =
        __lsx_vshuf_b(utf8_unpacked_hi, utf8_unpacked_hi, shuffle1);
    __lsx_vst(utf8_packed1, utf8_output, 0);
    utf8_output += row1[0];

    latin1_input += 16;
  } // while

  return std::make_pair(latin1_input, reinterpret_cast<char *>(utf8_output));
}
