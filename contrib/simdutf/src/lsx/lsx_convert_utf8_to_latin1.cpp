size_t convert_masked_utf8_to_latin1(const char *input,
                                     uint64_t utf8_end_of_code_point_mask,
                                     char *&latin1_output) {
  // we use an approach where we try to process up to 12 input bytes.
  // Why 12 input bytes and not 16? Because we are concerned with the size of
  // the lookup tables. Also 12 is nicely divisible by two and three.
  //
  __m128i in = __lsx_vld(reinterpret_cast<const uint8_t *>(input), 0);

  const uint16_t input_utf8_end_of_code_point_mask =
      utf8_end_of_code_point_mask & 0xfff;
  // Optimization note: our main path below is load-latency dependent. Thus it
  // is maybe beneficial to have fast paths that depend on branch prediction but
  // have less latency. This results in more instructions but, potentially, also
  // higher speeds.

  // We first try a few fast paths.
  // The obvious first test is ASCII, which actually consumes the full 16.
  if ((utf8_end_of_code_point_mask & 0xFFFF) == 0xFFFF) {
    // We process in chunks of 16 bytes
    __lsx_vst(in, reinterpret_cast<uint8_t *>(latin1_output), 0);
    latin1_output += 16; // We wrote 16 18-bit characters.
    return 16;           // We consumed 16 bytes.
  }
  /// We do not have a fast path available, or the fast path is unimportant, so
  /// we fallback.
  const uint8_t idx = simdutf::tables::utf8_to_utf16::utf8bigindex
      [input_utf8_end_of_code_point_mask][0];

  const uint8_t consumed = simdutf::tables::utf8_to_utf16::utf8bigindex
      [input_utf8_end_of_code_point_mask][1];
  // this indicates an invalid input:
  if (idx >= 64) {
    return consumed;
  }
  // Here we should have (idx < 64), if not, there is a bug in the validation or
  // elsewhere. SIX (6) input code-code units this is a relatively easy scenario
  // we process SIX (6) input code-code units. The max length in bytes of six
  // code code units spanning between 1 and 2 bytes each is 12 bytes. Converts 6
  // 1-2 byte UTF-8 characters to 6 UTF-16 characters. This is a relatively easy
  // scenario we process SIX (6) input code-code units. The max length in bytes
  // of six code code units spanning between 1 and 2 bytes each is 12 bytes.
  __m128i sh = __lsx_vld(reinterpret_cast<const uint8_t *>(
                             simdutf::tables::utf8_to_utf16::shufutf8[idx]),
                         0);
  // Shuffle
  // 1 byte: 00000000 0bbbbbbb
  // 2 byte: 110aaaaa 10bbbbbb
  sh = __lsx_vand_v(sh, __lsx_vldi(0x1f));
  __m128i perm = __lsx_vshuf_b(__lsx_vldi(0), in, sh);
  // ascii mask
  // 1 byte: 11111111 11111111
  // 2 byte: 00000000 00000000
  __m128i ascii_mask = __lsx_vslt_bu(perm, __lsx_vldi(0x80));
  // utf8 mask
  // 1 byte: 00000000 00000000
  // 2 byte: 00111111 00111111
  __m128i utf8_mask = __lsx_vand_v(__lsx_vsle_bu(__lsx_vldi(0x80), perm),
                                   __lsx_vldi(0b00111111));
  // mask
  //  1 byte: 11111111 11111111
  //  2 byte: 00111111 00111111
  __m128i mask = __lsx_vor_v(utf8_mask, ascii_mask);

  __m128i composed = __lsx_vbitsel_v(__lsx_vsrli_h(perm, 2), perm, mask);
  // writing 8 bytes even though we only care about the first 6 bytes.
  __m128i latin1_packed = __lsx_vpickev_b(__lsx_vldi(0), composed);

  uint64_t buffer[2];
  // __lsx_vst(latin1_packed, reinterpret_cast<uint8_t *>(latin1_output), 0);
  __lsx_vst(latin1_packed, reinterpret_cast<uint8_t *>(buffer), 0);
  std::memcpy(latin1_output, buffer, 6);
  latin1_output += 6; // We wrote 6 bytes.
  return consumed;
}
