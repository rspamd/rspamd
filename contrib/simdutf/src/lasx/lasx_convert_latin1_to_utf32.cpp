std::pair<const char *, char32_t *>
lasx_convert_latin1_to_utf32(const char *buf, size_t len,
                             char32_t *utf32_output) {
  const char *end = buf + len;

  // LASX requires 32-byte alignment, otherwise performance will be degraded
  while (((uint64_t)utf32_output & 0x1F) && buf < end) {
    *utf32_output++ = ((uint32_t)*buf) & 0xFF;
    buf++;
  }

  while (buf + 32 <= end) {
    __m256i in8 = __lasx_xvld(reinterpret_cast<const uint8_t *>(buf), 0);

    __m256i in32_0 = __lasx_vext2xv_wu_bu(in8);
    __lasx_xvst(in32_0, reinterpret_cast<uint32_t *>(utf32_output), 0);

    __m256i in8_1 = __lasx_xvpermi_d(in8, 0b00000001);
    __m256i in32_1 = __lasx_vext2xv_wu_bu(in8_1);
    __lasx_xvst(in32_1, reinterpret_cast<uint32_t *>(utf32_output), 32);

    __m256i in8_2 = __lasx_xvpermi_d(in8, 0b00000010);
    __m256i in32_2 = __lasx_vext2xv_wu_bu(in8_2);
    __lasx_xvst(in32_2, reinterpret_cast<uint32_t *>(utf32_output), 64);

    __m256i in8_3 = __lasx_xvpermi_d(in8, 0b00000011);
    __m256i in32_3 = __lasx_vext2xv_wu_bu(in8_3);
    __lasx_xvst(in32_3, reinterpret_cast<uint32_t *>(utf32_output), 96);

    utf32_output += 32;
    buf += 32;
  }

  if (buf + 16 <= end) {
    __m128i in8 = __lsx_vld(reinterpret_cast<const uint8_t *>(buf), 0);

    __m128i zero = __lsx_vldi(0);
    __m128i in16low = __lsx_vilvl_b(zero, in8);
    __m128i in16high = __lsx_vilvh_b(zero, in8);
    __m128i in32_0 = __lsx_vilvl_h(zero, in16low);
    __m128i in32_1 = __lsx_vilvh_h(zero, in16low);
    __m128i in32_2 = __lsx_vilvl_h(zero, in16high);
    __m128i in32_3 = __lsx_vilvh_h(zero, in16high);

    __lsx_vst(in32_0, reinterpret_cast<uint32_t *>(utf32_output), 0);
    __lsx_vst(in32_1, reinterpret_cast<uint32_t *>(utf32_output), 16);
    __lsx_vst(in32_2, reinterpret_cast<uint32_t *>(utf32_output), 32);
    __lsx_vst(in32_3, reinterpret_cast<uint32_t *>(utf32_output), 48);

    utf32_output += 16;
    buf += 16;
  }

  return std::make_pair(buf, utf32_output);
}
