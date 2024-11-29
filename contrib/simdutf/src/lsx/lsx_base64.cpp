/**
 * References and further reading:
 *
 * Wojciech Muła, Daniel Lemire, Base64 encoding and decoding at almost the
 * speed of a memory copy, Software: Practice and Experience 50 (2), 2020.
 * https://arxiv.org/abs/1910.05109
 *
 * Wojciech Muła, Daniel Lemire, Faster Base64 Encoding and Decoding using AVX2
 * Instructions, ACM Transactions on the Web 12 (3), 2018.
 * https://arxiv.org/abs/1704.00605
 *
 * Simon Josefsson. 2006. The Base16, Base32, and Base64 Data Encodings.
 * https://tools.ietf.org/html/rfc4648. (2006). Internet Engineering Task Force,
 * Request for Comments: 4648.
 *
 * Alfred Klomp. 2014a. Fast Base64 encoding/decoding with SSE vectorization.
 * http://www.alfredklomp.com/programming/sse-base64/. (2014).
 *
 * Alfred Klomp. 2014b. Fast Base64 stream encoder/decoder in C99, with SIMD
 * acceleration. https://github.com/aklomp/base64. (2014).
 *
 * Hanson Char. 2014. A Fast and Correct Base 64 Codec. (2014).
 * https://aws.amazon.com/blogs/developer/a-fast-and-correct-base-64-codec/
 *
 * Nick Kopp. 2013. Base64 Encoding on a GPU.
 * https://www.codeproject.com/Articles/276993/Base-Encoding-on-a-GPU. (2013).
 */

template <bool isbase64url>
size_t encode_base64(char *dst, const char *src, size_t srclen,
                     base64_options options) {
  // credit: Wojciech Muła
  // SSE (lookup: pshufb improved unrolled)
  const uint8_t *input = (const uint8_t *)src;
  static const char *lookup_tbl =
      isbase64url
          ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
          : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  uint8_t *out = (uint8_t *)dst;

  v16u8 shuf;
  __m128i v_fc0fc00, v_3f03f0, shift_r, shift_l, base64_tbl0, base64_tbl1,
      base64_tbl2, base64_tbl3;
  if (srclen >= 16) {
    shuf = v16u8{1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10};
    v_fc0fc00 = __lsx_vreplgr2vr_w(uint32_t(0x0fc0fc00));
    v_3f03f0 = __lsx_vreplgr2vr_w(uint32_t(0x003f03f0));
    shift_r = __lsx_vreplgr2vr_w(uint32_t(0x0006000a));
    shift_l = __lsx_vreplgr2vr_w(uint32_t(0x00080004));
    base64_tbl0 = __lsx_vld(lookup_tbl, 0);
    base64_tbl1 = __lsx_vld(lookup_tbl, 16);
    base64_tbl2 = __lsx_vld(lookup_tbl, 32);
    base64_tbl3 = __lsx_vld(lookup_tbl, 48);
  }

  size_t i = 0;
  for (; i + 52 <= srclen; i += 48) {
    __m128i in0 =
        __lsx_vld(reinterpret_cast<const __m128i *>(input + i), 4 * 3 * 0);
    __m128i in1 =
        __lsx_vld(reinterpret_cast<const __m128i *>(input + i), 4 * 3 * 1);
    __m128i in2 =
        __lsx_vld(reinterpret_cast<const __m128i *>(input + i), 4 * 3 * 2);
    __m128i in3 =
        __lsx_vld(reinterpret_cast<const __m128i *>(input + i), 4 * 3 * 3);

    in0 = __lsx_vshuf_b(in0, in0, (__m128i)shuf);
    in1 = __lsx_vshuf_b(in1, in1, (__m128i)shuf);
    in2 = __lsx_vshuf_b(in2, in2, (__m128i)shuf);
    in3 = __lsx_vshuf_b(in3, in3, (__m128i)shuf);

    __m128i t0_0 = __lsx_vand_v(in0, v_fc0fc00);
    __m128i t0_1 = __lsx_vand_v(in1, v_fc0fc00);
    __m128i t0_2 = __lsx_vand_v(in2, v_fc0fc00);
    __m128i t0_3 = __lsx_vand_v(in3, v_fc0fc00);

    __m128i t1_0 = __lsx_vsrl_h(t0_0, shift_r);
    __m128i t1_1 = __lsx_vsrl_h(t0_1, shift_r);
    __m128i t1_2 = __lsx_vsrl_h(t0_2, shift_r);
    __m128i t1_3 = __lsx_vsrl_h(t0_3, shift_r);

    __m128i t2_0 = __lsx_vand_v(in0, v_3f03f0);
    __m128i t2_1 = __lsx_vand_v(in1, v_3f03f0);
    __m128i t2_2 = __lsx_vand_v(in2, v_3f03f0);
    __m128i t2_3 = __lsx_vand_v(in3, v_3f03f0);

    __m128i t3_0 = __lsx_vsll_h(t2_0, shift_l);
    __m128i t3_1 = __lsx_vsll_h(t2_1, shift_l);
    __m128i t3_2 = __lsx_vsll_h(t2_2, shift_l);
    __m128i t3_3 = __lsx_vsll_h(t2_3, shift_l);

    __m128i input0 = __lsx_vor_v(t1_0, t3_0);
    __m128i input0_shuf0 = __lsx_vshuf_b(base64_tbl1, base64_tbl0, input0);
    __m128i input0_shuf1 = __lsx_vshuf_b(base64_tbl3, base64_tbl2,
                                         __lsx_vsub_b(input0, __lsx_vldi(32)));
    __m128i input0_mask = __lsx_vslei_bu(input0, 31);
    __m128i input0_result =
        __lsx_vbitsel_v(input0_shuf1, input0_shuf0, input0_mask);
    __lsx_vst(input0_result, reinterpret_cast<__m128i *>(out), 0);
    out += 16;

    __m128i input1 = __lsx_vor_v(t1_1, t3_1);
    __m128i input1_shuf0 = __lsx_vshuf_b(base64_tbl1, base64_tbl0, input1);
    __m128i input1_shuf1 = __lsx_vshuf_b(base64_tbl3, base64_tbl2,
                                         __lsx_vsub_b(input1, __lsx_vldi(32)));
    __m128i input1_mask = __lsx_vslei_bu(input1, 31);
    __m128i input1_result =
        __lsx_vbitsel_v(input1_shuf1, input1_shuf0, input1_mask);
    __lsx_vst(input1_result, reinterpret_cast<__m128i *>(out), 0);
    out += 16;

    __m128i input2 = __lsx_vor_v(t1_2, t3_2);
    __m128i input2_shuf0 = __lsx_vshuf_b(base64_tbl1, base64_tbl0, input2);
    __m128i input2_shuf1 = __lsx_vshuf_b(base64_tbl3, base64_tbl2,
                                         __lsx_vsub_b(input2, __lsx_vldi(32)));
    __m128i input2_mask = __lsx_vslei_bu(input2, 31);
    __m128i input2_result =
        __lsx_vbitsel_v(input2_shuf1, input2_shuf0, input2_mask);
    __lsx_vst(input2_result, reinterpret_cast<__m128i *>(out), 0);
    out += 16;

    __m128i input3 = __lsx_vor_v(t1_3, t3_3);
    __m128i input3_shuf0 = __lsx_vshuf_b(base64_tbl1, base64_tbl0, input3);
    __m128i input3_shuf1 = __lsx_vshuf_b(base64_tbl3, base64_tbl2,
                                         __lsx_vsub_b(input3, __lsx_vldi(32)));
    __m128i input3_mask = __lsx_vslei_bu(input3, 31);
    __m128i input3_result =
        __lsx_vbitsel_v(input3_shuf1, input3_shuf0, input3_mask);
    __lsx_vst(input3_result, reinterpret_cast<__m128i *>(out), 0);
    out += 16;
  }
  for (; i + 16 <= srclen; i += 12) {

    __m128i in = __lsx_vld(reinterpret_cast<const __m128i *>(input + i), 0);

    // bytes from groups A, B and C are needed in separate 32-bit lanes
    // in = [DDDD|CCCC|BBBB|AAAA]
    //
    //      an input triplet has layout
    //      [????????|ccdddddd|bbbbcccc|aaaaaabb]
    //        byte 3   byte 2   byte 1   byte 0    -- byte 3 comes from the next
    //        triplet
    //
    //      shuffling changes the order of bytes: 1, 0, 2, 1
    //      [bbbbcccc|ccdddddd|aaaaaabb|bbbbcccc]
    //           ^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^
    //                  processed bits
    in = __lsx_vshuf_b(in, in, (__m128i)shuf);

    // unpacking
    // t0    = [0000cccc|cc000000|aaaaaa00|00000000]
    __m128i t0 = __lsx_vand_v(in, v_fc0fc00);
    // t1    = [00000000|00cccccc|00000000|00aaaaaa]
    //          ((c >> 6),  (a >> 10))
    __m128i t1 = __lsx_vsrl_h(t0, shift_r);

    // t2    = [00000000|00dddddd|000000bb|bbbb0000]
    __m128i t2 = __lsx_vand_v(in, v_3f03f0);
    // t3    = [00dddddd|00000000|00bbbbbb|00000000]
    //          ((d << 8), (b << 4))
    __m128i t3 = __lsx_vsll_h(t2, shift_l);

    // res   = [00dddddd|00cccccc|00bbbbbb|00aaaaaa] = t1 | t3
    __m128i indices = __lsx_vor_v(t1, t3);

    __m128i indices_shuf0 = __lsx_vshuf_b(base64_tbl1, base64_tbl0, indices);
    __m128i indices_shuf1 = __lsx_vshuf_b(
        base64_tbl3, base64_tbl2, __lsx_vsub_b(indices, __lsx_vldi(32)));
    __m128i indices_mask = __lsx_vslei_bu(indices, 31);
    __m128i indices_result =
        __lsx_vbitsel_v(indices_shuf1, indices_shuf0, indices_mask);

    __lsx_vst(indices_result, reinterpret_cast<__m128i *>(out), 0);
    out += 16;
  }

  return i / 3 * 4 + scalar::base64::tail_encode_base64((char *)out, src + i,
                                                        srclen - i, options);
}

static inline void compress(__m128i data, uint16_t mask, char *output) {
  if (mask == 0) {
    __lsx_vst(data, reinterpret_cast<__m128i *>(output), 0);
    return;
  }
  // this particular implementation was inspired by work done by @animetosho
  // we do it in two steps, first 8 bytes and then second 8 bytes
  uint8_t mask1 = uint8_t(mask);      // least significant 8 bits
  uint8_t mask2 = uint8_t(mask >> 8); // most significant 8 bits
  // next line just loads the 64-bit values thintable_epi8[mask1] and
  // thintable_epi8[mask2] into a 128-bit register, using only
  // two instructions on most compilers.

  v2u64 shufmask = {tables::base64::thintable_epi8[mask1],
                    tables::base64::thintable_epi8[mask2]};

  // we increment by 0x08 the second half of the mask
  v4u32 hi = {0, 0, 0x08080808, 0x08080808};
  __m128i shufmask1 = __lsx_vadd_b((__m128i)shufmask, (__m128i)hi);

  // this is the version "nearly pruned"
  __m128i pruned = __lsx_vshuf_b(data, data, shufmask1);
  // we still need to put the two halves together.
  // we compute the popcount of the first half:
  int pop1 = tables::base64::BitsSetTable256mul2[mask1];
  // then load the corresponding mask, what it does is to write
  // only the first pop1 bytes from the first 8 bytes, and then
  // it fills in with the bytes from the second 8 bytes + some filling
  // at the end.
  __m128i compactmask =
      __lsx_vld(reinterpret_cast<const __m128i *>(
                    tables::base64::pshufb_combine_table + pop1 * 8),
                0);
  __m128i answer = __lsx_vshuf_b(pruned, pruned, compactmask);

  __lsx_vst(answer, reinterpret_cast<__m128i *>(output), 0);
}

struct block64 {
  __m128i chunks[4];
};

template <bool base64_url>
static inline uint16_t to_base64_mask(__m128i *src, bool *error) {
  const v16u8 ascii_space_tbl = {0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                 0x0,  0x9, 0xa, 0x0, 0xc, 0xd, 0x0, 0x0};
  // credit: aqrit
  /*
  '0'(0x30)-'9'(0x39) => delta_values_index = 4
  'A'(0x41)-'Z'(0x5a) => delta_values_index = 4/5/12(4+8)
  'a'(0x61)-'z'(0x7a) => delta_values_index = 6/7/14(6+8)
  '+'(0x2b)           => delta_values_index = 3
  '/'(0x2f)           => delta_values_index = 2+8 = 10
  '-'(0x2d)           => delta_values_index = 2+8 = 10
  '_'(0x5f)           => delta_values_index = 5+8 = 13
  */
  v16u8 delta_asso = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
                      0x0, 0x0, 0x0, 0x0, 0x0, 0xF, 0x0, 0xF};
  v16i8 delta_values;
  if (base64_url) {
    delta_values =
        v16i8{int8_t(0x00), int8_t(0x00), int8_t(0x00), int8_t(0x13),
              int8_t(0x04), int8_t(0xBF), int8_t(0xBF), int8_t(0xB9),
              int8_t(0xB9), int8_t(0x00), int8_t(0x11), int8_t(0xC3),
              int8_t(0xBF), int8_t(0xE0), int8_t(0xB9), int8_t(0xB9)};
  } else {
    delta_values =
        v16i8{int8_t(0x00), int8_t(0x00), int8_t(0x00), int8_t(0x13),
              int8_t(0x04), int8_t(0xBF), int8_t(0xBF), int8_t(0xB9),
              int8_t(0xB9), int8_t(0x00), int8_t(0x10), int8_t(0xC3),
              int8_t(0xBF), int8_t(0xBF), int8_t(0xB9), int8_t(0xB9)};
  }

  v16u8 check_asso;
  if (base64_url) {
    check_asso = v16u8{0x0D, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                       0x01, 0x01, 0x03, 0x07, 0x0B, 0x06, 0x0B, 0x12};
  } else {
    check_asso = v16u8{0x0D, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                       0x01, 0x01, 0x03, 0x07, 0x0B, 0x0B, 0x0B, 0x0F};
  }

  v16i8 check_values;
  if (base64_url) {
    check_values = v16i8{int8_t(0x0),  int8_t(0x80), int8_t(0x80), int8_t(0x80),
                         int8_t(0xCF), int8_t(0xBF), int8_t(0xD3), int8_t(0xA6),
                         int8_t(0xB5), int8_t(0x86), int8_t(0xD0), int8_t(0x80),
                         int8_t(0xB0), int8_t(0x80), int8_t(0x0),  int8_t(0x0)};
  } else {
    check_values =
        v16i8{int8_t(0x80), int8_t(0x80), int8_t(0x80), int8_t(0x80),
              int8_t(0xCF), int8_t(0xBF), int8_t(0xD5), int8_t(0xA6),
              int8_t(0xB5), int8_t(0x86), int8_t(0xD1), int8_t(0x80),
              int8_t(0xB1), int8_t(0x80), int8_t(0x91), int8_t(0x80)};
  }

  const __m128i shifted = __lsx_vsrli_b(*src, 3);
  __m128i asso_index = __lsx_vand_v(*src, __lsx_vldi(0xF));
  const __m128i delta_hash =
      __lsx_vavgr_bu(__lsx_vshuf_b((__m128i)delta_asso, (__m128i)delta_asso,
                                   (__m128i)asso_index),
                     shifted);
  const __m128i check_hash =
      __lsx_vavgr_bu(__lsx_vshuf_b((__m128i)check_asso, (__m128i)check_asso,
                                   (__m128i)asso_index),
                     shifted);

  const __m128i out =
      __lsx_vsadd_b(__lsx_vshuf_b((__m128i)delta_values, (__m128i)delta_values,
                                  (__m128i)delta_hash),
                    *src);
  const __m128i chk =
      __lsx_vsadd_b(__lsx_vshuf_b((__m128i)check_values, (__m128i)check_values,
                                  (__m128i)check_hash),
                    *src);
  unsigned int mask = __lsx_vpickve2gr_hu(__lsx_vmskltz_b(chk), 0);
  if (mask) {
    __m128i ascii_space = __lsx_vseq_b(__lsx_vshuf_b((__m128i)ascii_space_tbl,
                                                     (__m128i)ascii_space_tbl,
                                                     (__m128i)asso_index),
                                       *src);
    *error |=
        (mask != __lsx_vpickve2gr_hu(__lsx_vmskltz_b((__m128i)ascii_space), 0));
  }

  *src = out;
  return (uint16_t)mask;
}

template <bool base64_url>
static inline uint64_t to_base64_mask(block64 *b, bool *error) {
  *error = 0;
  uint64_t m0 = to_base64_mask<base64_url>(&b->chunks[0], error);
  uint64_t m1 = to_base64_mask<base64_url>(&b->chunks[1], error);
  uint64_t m2 = to_base64_mask<base64_url>(&b->chunks[2], error);
  uint64_t m3 = to_base64_mask<base64_url>(&b->chunks[3], error);
  return m0 | (m1 << 16) | (m2 << 32) | (m3 << 48);
}

static inline void copy_block(block64 *b, char *output) {
  __lsx_vst(b->chunks[0], reinterpret_cast<__m128i *>(output), 0);
  __lsx_vst(b->chunks[1], reinterpret_cast<__m128i *>(output), 16);
  __lsx_vst(b->chunks[2], reinterpret_cast<__m128i *>(output), 32);
  __lsx_vst(b->chunks[3], reinterpret_cast<__m128i *>(output), 48);
}

static inline uint64_t compress_block(block64 *b, uint64_t mask, char *output) {
  uint64_t nmask = ~mask;
  uint64_t count =
      __lsx_vpickve2gr_d(__lsx_vpcnt_h(__lsx_vreplgr2vr_d(nmask)), 0);
  uint16_t *count_ptr = (uint16_t *)&count;
  compress(b->chunks[0], uint16_t(mask), output);
  compress(b->chunks[1], uint16_t(mask >> 16), output + count_ptr[0]);
  compress(b->chunks[2], uint16_t(mask >> 32),
           output + count_ptr[0] + count_ptr[1]);
  compress(b->chunks[3], uint16_t(mask >> 48),
           output + count_ptr[0] + count_ptr[1] + count_ptr[2]);
  return count_ones(nmask);
}

// The caller of this function is responsible to ensure that there are 64 bytes
// available from reading at src. The data is read into a block64 structure.
static inline void load_block(block64 *b, const char *src) {
  b->chunks[0] = __lsx_vld(reinterpret_cast<const __m128i *>(src), 0);
  b->chunks[1] = __lsx_vld(reinterpret_cast<const __m128i *>(src), 16);
  b->chunks[2] = __lsx_vld(reinterpret_cast<const __m128i *>(src), 32);
  b->chunks[3] = __lsx_vld(reinterpret_cast<const __m128i *>(src), 48);
}

// The caller of this function is responsible to ensure that there are 128 bytes
// available from reading at src. The data is read into a block64 structure.
static inline void load_block(block64 *b, const char16_t *src) {
  __m128i m1 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 0);
  __m128i m2 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 16);
  __m128i m3 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 32);
  __m128i m4 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 48);
  __m128i m5 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 64);
  __m128i m6 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 80);
  __m128i m7 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 96);
  __m128i m8 = __lsx_vld(reinterpret_cast<const __m128i *>(src), 112);
  b->chunks[0] = __lsx_vssrlni_bu_h(m2, m1, 0);
  b->chunks[1] = __lsx_vssrlni_bu_h(m4, m3, 0);
  b->chunks[2] = __lsx_vssrlni_bu_h(m6, m5, 0);
  b->chunks[3] = __lsx_vssrlni_bu_h(m8, m7, 0);
}

static inline void base64_decode(char *out, __m128i str) {
  __m128i t0 = __lsx_vor_v(
      __lsx_vslli_w(str, 26),
      __lsx_vslli_w(__lsx_vand_v(str, __lsx_vldi(-1758 /*0x0000FF00*/)), 12));
  __m128i t1 =
      __lsx_vsrli_w(__lsx_vand_v(str, __lsx_vldi(-3521 /*0x003F0000*/)), 2);
  __m128i t2 = __lsx_vor_v(t0, t1);
  __m128i t3 = __lsx_vor_v(t2, __lsx_vsrli_w(str, 16));
  const v16u8 pack_shuffle = {3, 2,  1,  7,  6, 5, 11, 10,
                              9, 15, 14, 13, 0, 0, 0,  0};
  t3 = __lsx_vshuf_b(t3, t3, (__m128i)pack_shuffle);

  // Store the output:
  // we only need 12.
  __lsx_vstelm_d(t3, out, 0, 0);
  __lsx_vstelm_w(t3, out + 8, 0, 2);
}
// decode 64 bytes and output 48 bytes
static inline void base64_decode_block(char *out, const char *src) {
  base64_decode(out, __lsx_vld(reinterpret_cast<const __m128i *>(src), 0));
  base64_decode(out + 12,
                __lsx_vld(reinterpret_cast<const __m128i *>(src), 16));
  base64_decode(out + 24,
                __lsx_vld(reinterpret_cast<const __m128i *>(src), 32));
  base64_decode(out + 36,
                __lsx_vld(reinterpret_cast<const __m128i *>(src), 48));
}
static inline void base64_decode_block_safe(char *out, const char *src) {
  base64_decode_block(out, src);
}
static inline void base64_decode_block(char *out, block64 *b) {
  base64_decode(out, b->chunks[0]);
  base64_decode(out + 12, b->chunks[1]);
  base64_decode(out + 24, b->chunks[2]);
  base64_decode(out + 36, b->chunks[3]);
}
static inline void base64_decode_block_safe(char *out, block64 *b) {
  base64_decode_block(out, b);
}

template <bool base64_url, typename char_type>
full_result
compress_decode_base64(char *dst, const char_type *src, size_t srclen,
                       base64_options options,
                       last_chunk_handling_options last_chunk_options) {
  const uint8_t *to_base64 = base64_url ? tables::base64::to_base64_url_value
                                        : tables::base64::to_base64_value;
  size_t equallocation =
      srclen; // location of the first padding character if any
  // skip trailing spaces
  while (srclen > 0 && scalar::base64::is_eight_byte(src[srclen - 1]) &&
         to_base64[uint8_t(src[srclen - 1])] == 64) {
    srclen--;
  }
  size_t equalsigns = 0;
  if (srclen > 0 && src[srclen - 1] == '=') {
    equallocation = srclen - 1;
    srclen--;
    equalsigns = 1;
    // skip trailing spaces
    while (srclen > 0 && scalar::base64::is_eight_byte(src[srclen - 1]) &&
           to_base64[uint8_t(src[srclen - 1])] == 64) {
      srclen--;
    }
    if (srclen > 0 && src[srclen - 1] == '=') {
      equallocation = srclen - 1;
      srclen--;
      equalsigns = 2;
    }
  }
  if (srclen == 0) {
    if (equalsigns > 0) {
      return {INVALID_BASE64_CHARACTER, equallocation, 0};
    }
    return {SUCCESS, 0, 0};
  }
  const char_type *const srcinit = src;
  const char *const dstinit = dst;
  const char_type *const srcend = src + srclen;

  constexpr size_t block_size = 10;
  char buffer[block_size * 64];
  char *bufferptr = buffer;
  if (srclen >= 64) {
    const char_type *const srcend64 = src + srclen - 64;
    while (src <= srcend64) {
      block64 b;
      load_block(&b, src);
      src += 64;
      bool error = false;
      uint64_t badcharmask = to_base64_mask<base64_url>(&b, &error);
      if (badcharmask) {
        if (error) {
          src -= 64;
          while (src < srcend && scalar::base64::is_eight_byte(*src) &&
                 to_base64[uint8_t(*src)] <= 64) {
            src++;
          }
          if (src < srcend) {
            // should never happen
          }
          return {error_code::INVALID_BASE64_CHARACTER, size_t(src - srcinit),
                  size_t(dst - dstinit)};
        }
      }

      if (badcharmask != 0) {
        // optimization opportunity: check for simple masks like those made of
        // continuous 1s followed by continuous 0s. And masks containing a
        // single bad character.
        bufferptr += compress_block(&b, badcharmask, bufferptr);
      } else {
        // optimization opportunity: if bufferptr == buffer and mask == 0, we
        // can avoid the call to compress_block and decode directly.
        copy_block(&b, bufferptr);
        bufferptr += 64;
      }
      if (bufferptr >= (block_size - 1) * 64 + buffer) {
        for (size_t i = 0; i < (block_size - 1); i++) {
          base64_decode_block(dst, buffer + i * 64);
          dst += 48;
        }
        std::memcpy(buffer, buffer + (block_size - 1) * 64,
                    64); // 64 might be too much
        bufferptr -= (block_size - 1) * 64;
      }
    }
  }
  char *buffer_start = buffer;
  // Optimization note: if this is almost full, then it is worth our
  // time, otherwise, we should just decode directly.
  int last_block = (int)((bufferptr - buffer_start) % 64);
  if (last_block != 0 && srcend - src + last_block >= 64) {
    while ((bufferptr - buffer_start) % 64 != 0 && src < srcend) {
      uint8_t val = to_base64[uint8_t(*src)];
      *bufferptr = char(val);
      if (!scalar::base64::is_eight_byte(*src) || val > 64) {
        return {error_code::INVALID_BASE64_CHARACTER, size_t(src - srcinit),
                size_t(dst - dstinit)};
      }
      bufferptr += (val <= 63);
      src++;
    }
  }

  for (; buffer_start + 64 <= bufferptr; buffer_start += 64) {
    base64_decode_block(dst, buffer_start);
    dst += 48;
  }
  if ((bufferptr - buffer_start) % 64 != 0) {
    while (buffer_start + 4 < bufferptr) {
      uint32_t triple = ((uint32_t(uint8_t(buffer_start[0])) << 3 * 6) +
                         (uint32_t(uint8_t(buffer_start[1])) << 2 * 6) +
                         (uint32_t(uint8_t(buffer_start[2])) << 1 * 6) +
                         (uint32_t(uint8_t(buffer_start[3])) << 0 * 6))
                        << 8;
      triple = scalar::utf32::swap_bytes(triple);
      std::memcpy(dst, &triple, 4);

      dst += 3;
      buffer_start += 4;
    }
    if (buffer_start + 4 <= bufferptr) {
      uint32_t triple = ((uint32_t(uint8_t(buffer_start[0])) << 3 * 6) +
                         (uint32_t(uint8_t(buffer_start[1])) << 2 * 6) +
                         (uint32_t(uint8_t(buffer_start[2])) << 1 * 6) +
                         (uint32_t(uint8_t(buffer_start[3])) << 0 * 6))
                        << 8;
      triple = scalar::utf32::swap_bytes(triple);
      std::memcpy(dst, &triple, 3);

      dst += 3;
      buffer_start += 4;
    }
    // we may have 1, 2 or 3 bytes left and we need to decode them so let us
    // backtrack
    int leftover = int(bufferptr - buffer_start);
    while (leftover > 0) {
      while (to_base64[uint8_t(*(src - 1))] == 64) {
        src--;
      }
      src--;
      leftover--;
    }
  }
  if (src < srcend + equalsigns) {
    full_result r = scalar::base64::base64_tail_decode(
        dst, src, srcend - src, equalsigns, options, last_chunk_options);
    r.input_count += size_t(src - srcinit);
    if (r.error == error_code::INVALID_BASE64_CHARACTER ||
        r.error == error_code::BASE64_EXTRA_BITS) {
      return r;
    } else {
      r.output_count += size_t(dst - dstinit);
    }
    if (last_chunk_options != stop_before_partial &&
        r.error == error_code::SUCCESS && equalsigns > 0) {
      // additional checks
      if ((r.output_count % 3 == 0) ||
          ((r.output_count % 3) + 1 + equalsigns != 4)) {
        r.error = error_code::INVALID_BASE64_CHARACTER;
        r.input_count = equallocation;
      }
    }
    return r;
  }
  if (equalsigns > 0) {
    if ((size_t(dst - dstinit) % 3 == 0) ||
        ((size_t(dst - dstinit) % 3) + 1 + equalsigns != 4)) {
      return {INVALID_BASE64_CHARACTER, equallocation, size_t(dst - dstinit)};
    }
  }
  return {SUCCESS, srclen, size_t(dst - dstinit)};
}
