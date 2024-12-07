template <simdutf_ByteFlip bflip>
simdutf_really_inline static size_t
rvv_utf32_store_utf16_m4(uint16_t *dst, vuint32m4_t utf32, size_t vl,
                         vbool4_t m4even) {
  /* convert [000000000000aaaa|aaaaaabbbbbbbbbb]
   * to      [110111bbbbbbbbbb|110110aaaaaaaaaa] */
  vuint32m4_t sur = __riscv_vsub_vx_u32m4(utf32, 0x10000, vl);
  sur = __riscv_vor_vv_u32m4(__riscv_vsll_vx_u32m4(sur, 16, vl),
                             __riscv_vsrl_vx_u32m4(sur, 10, vl), vl);
  sur = __riscv_vand_vx_u32m4(sur, 0x3FF03FF, vl);
  sur = __riscv_vor_vx_u32m4(sur, 0xDC00D800, vl);
  /* merge 1 byte utf32 and 2 byte sur */
  vbool8_t m4 = __riscv_vmsgtu_vx_u32m4_b8(utf32, 0xFFFF, vl);
  vuint16m4_t utf32_16 = __riscv_vreinterpret_v_u32m4_u16m4(
      __riscv_vmerge_vvm_u32m4(utf32, sur, m4, vl));
  /* compress and store */
  vbool4_t mOut = __riscv_vmor_mm_b4(
      __riscv_vmsne_vx_u16m4_b4(utf32_16, 0, vl * 2), m4even, vl * 2);
  vuint16m4_t vout = __riscv_vcompress_vm_u16m4(utf32_16, mOut, vl * 2);
  vl = __riscv_vcpop_m_b4(mOut, vl * 2);
  __riscv_vse16_v_u16m4(dst, simdutf_byteflip<bflip>(vout, vl), vl);
  return vl;
};
