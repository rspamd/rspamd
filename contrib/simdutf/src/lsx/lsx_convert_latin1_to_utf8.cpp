/*
  Returns a pair: the first unprocessed byte from buf and utf8_output
  A scalar routing should carry on the conversion of the tail.
*/

std::pair<const char *, char *>
lsx_convert_latin1_to_utf8(const char *latin1_input, size_t len,
                           char *utf8_out) {
  uint8_t *utf8_output = reinterpret_cast<uint8_t *>(utf8_out);
  const char *end = latin1_input + len;

  __m128i zero = __lsx_vldi(0);
  // We always write 16 bytes, of which more than the first 8 bytes
  // are valid. A safety margin of 8 is more than sufficient.
  while (latin1_input + 16 <= end) {
    __m128i in8 = __lsx_vld(reinterpret_cast<const uint8_t *>(latin1_input), 0);
    uint32_t ascii = __lsx_vpickve2gr_hu(__lsx_vmskgez_b(in8), 0);
    if (ascii == 0xffff) { // ASCII fast path!!!!
      __lsx_vst(in8, utf8_output, 0);
      utf8_output += 16;
      latin1_input += 16;
      continue;
    }
    // We just fallback on UTF-16 code. This could be optimized/simplified
    // further.
    __m128i in16 = __lsx_vilvl_b(zero, in8);
    // 1. prepare 2-byte values
    // input 8-bit word : [aabb|bbbb] x 8
    // expected output   : [1100|00aa|10bb|bbbb] x 8
    // t0 = [0000|00aa|bbbb|bb00]
    __m128i t0 = __lsx_vslli_h(in16, 2);
    // t1 = [0000|00aa|0000|0000]
    __m128i t1 = __lsx_vand_v(t0, __lsx_vldi(-2785));
    // t3 = [0000|00aa|00bb|bbbb]
    __m128i t2 = __lsx_vbitsel_v(t1, in16, __lsx_vrepli_h(0x3f));
    // t4 = [1100|00aa|10bb|bbbb]
    __m128i t3 = __lsx_vor_v(t2, __lsx_vreplgr2vr_h(uint16_t(0xc080)));
    // merge ASCII and 2-byte codewords
    __m128i one_byte_bytemask = __lsx_vsle_hu(in16, __lsx_vrepli_h(0x7F));
    __m128i utf8_unpacked = __lsx_vbitsel_v(t3, in16, one_byte_bytemask);

    const uint8_t *row = &simdutf::tables::utf16_to_utf8::pack_1_2_utf8_bytes
                             [lsx_1_2_utf8_bytes_mask[(ascii & 0xff)]][0];
    __m128i shuffle = __lsx_vld(row + 1, 0);
    __m128i utf8_packed = __lsx_vshuf_b(zero, utf8_unpacked, shuffle);

    // store bytes
    __lsx_vst(utf8_packed, utf8_output, 0);
    // adjust pointers
    latin1_input += 8;
    utf8_output += row[0];

  } // while

  return std::make_pair(latin1_input, reinterpret_cast<char *>(utf8_output));
}
