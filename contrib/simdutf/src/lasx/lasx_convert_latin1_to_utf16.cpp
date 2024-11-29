std::pair<const char *, char16_t *>
lasx_convert_latin1_to_utf16le(const char *buf, size_t len,
                               char16_t *utf16_output) {
  const char *end = buf + len;

  // Performance degradation when memory address is not 32-byte aligned
  while (((uint64_t)utf16_output & 0x1F) && buf < end) {
    *utf16_output++ = uint8_t(*buf) & 0xFF;
    buf++;
  }

  while (buf + 32 <= end) {
    __m256i in8 = __lasx_xvld(reinterpret_cast<const uint8_t *>(buf), 0);

    __m256i inlow = __lasx_vext2xv_hu_bu(in8);
    __m256i in8_high = __lasx_xvpermi_q(in8, in8, 0b00000001);
    __m256i inhigh = __lasx_vext2xv_hu_bu(in8_high);
    __lasx_xvst(inlow, reinterpret_cast<uint16_t *>(utf16_output), 0);
    __lasx_xvst(inhigh, reinterpret_cast<uint16_t *>(utf16_output), 32);

    utf16_output += 32;
    buf += 32;
  }

  if (buf + 16 <= end) {
    __m128i zero = __lsx_vldi(0);
    __m128i in8 = __lsx_vld(reinterpret_cast<const uint8_t *>(buf), 0);

    __m128i inlow = __lsx_vilvl_b(zero, in8);
    __m128i inhigh = __lsx_vilvh_b(zero, in8);
    __lsx_vst(inlow, reinterpret_cast<uint16_t *>(utf16_output), 0);
    __lsx_vst(inhigh, reinterpret_cast<uint16_t *>(utf16_output), 16);

    utf16_output += 16;
    buf += 16;
  }
  return std::make_pair(buf, utf16_output);
}

std::pair<const char *, char16_t *>
lasx_convert_latin1_to_utf16be(const char *buf, size_t len,
                               char16_t *utf16_output) {
  const char *end = buf + len;

  while (((uint64_t)utf16_output & 0x1F) && buf < end) {
    *utf16_output++ = (uint16_t(*buf++) << 8);
  }

  __m256i zero = __lasx_xvldi(0);
  while (buf + 32 <= end) {
    __m256i in8 = __lasx_xvld(reinterpret_cast<const uint8_t *>(buf), 0);

    __m256i in8_shuf = __lasx_xvpermi_d(in8, 0b11011000);

    __m256i inlow = __lasx_xvilvl_b(in8_shuf, zero);
    __m256i inhigh = __lasx_xvilvh_b(in8_shuf, zero);
    __lasx_xvst(inlow, reinterpret_cast<uint16_t *>(utf16_output), 0);
    __lasx_xvst(inhigh, reinterpret_cast<uint16_t *>(utf16_output), 32);
    utf16_output += 32;
    buf += 32;
  }

  if (buf + 16 <= end) {
    __m128i zero_128 = __lsx_vldi(0);
    __m128i in8 = __lsx_vld(reinterpret_cast<const uint8_t *>(buf), 0);

    __m128i inlow = __lsx_vilvl_b(in8, zero_128);
    __m128i inhigh = __lsx_vilvh_b(in8, zero_128);
    __lsx_vst(inlow, reinterpret_cast<uint16_t *>(utf16_output), 0);
    __lsx_vst(inhigh, reinterpret_cast<uint16_t *>(utf16_output), 16);
    utf16_output += 16;
    buf += 16;
  }

  return std::make_pair(buf, utf16_output);
}
