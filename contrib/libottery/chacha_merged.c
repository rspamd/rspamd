/*
 * This code is based on Dan Bernstein's pure C "merged" ChaCha
 * implementation; details below.
 *
 * Note that I've ripped out all of the code that wasn't suitable for doing
 * block-oriented operation, all (residual) support for 128-bit ChaCha keys,
 * all support for counter values over 32 bits, the ability to xor the stream
 * with a plaintext, and so on.
 *
 * Future versions of this might remove bigendian conversions too.  DO NOT use
 * this code for your stream cipher: go back to the original source.  (I got
 * this copy from SUPERCOP).
 */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/
#include <string.h>
#include "ottery-internal.h"
#define u8 uint8_t
#define u32 uint32_t
#include "chacha_merged_ecrypt.h"

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[16] = "expand 32-byte k";

static void ECRYPT_keysetup(ECRYPT_ctx *x,const u8 *k,u32 ivbits)
{
  const char *constants;
  (void)ivbits;

  x->input[4] = U8TO32_LITTLE(k + 0);
  x->input[5] = U8TO32_LITTLE(k + 4);
  x->input[6] = U8TO32_LITTLE(k + 8);
  x->input[7] = U8TO32_LITTLE(k + 12);
  k += 16;
  constants = sigma;
  x->input[8] = U8TO32_LITTLE(k + 0);
  x->input[9] = U8TO32_LITTLE(k + 4);
  x->input[10] = U8TO32_LITTLE(k + 8);
  x->input[11] = U8TO32_LITTLE(k + 12);
  x->input[0] = U8TO32_LITTLE(constants + 0);
  x->input[1] = U8TO32_LITTLE(constants + 4);
  x->input[2] = U8TO32_LITTLE(constants + 8);
  x->input[3] = U8TO32_LITTLE(constants + 12);
}

static void ECRYPT_ivsetup(ECRYPT_ctx *x,const u8 *iv)
{
  x->input[12] = 0;
  x->input[13] = 0;
  x->input[14] = U8TO32_LITTLE(iv + 0);
  x->input[15] = U8TO32_LITTLE(iv + 4);
}

#define IDX_STEP    16
#define OUTPUT_LEN  (IDX_STEP * 64)

static inline void chacha_merged_getblocks(const int chacha_rounds, ECRYPT_ctx *x,u8 *c) __attribute__((always_inline));

/** Generate OUTPUT_LEN bytes of output using the key, nonce, and counter in x,
 * and store them in c.
 */
static void chacha_merged_getblocks(const int chacha_rounds, ECRYPT_ctx *x,u8 *c)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  unsigned i, block;

  j0 = x->input[0];
  j1 = x->input[1];
  j2 = x->input[2];
  j3 = x->input[3];
  j4 = x->input[4];
  j5 = x->input[5];
  j6 = x->input[6];
  j7 = x->input[7];
  j8 = x->input[8];
  j9 = x->input[9];
  j10 = x->input[10];
  j11 = x->input[11];
  j12 = x->input[12];
  j13 = x->input[13];
  j14 = x->input[14];
  j15 = x->input[15];

  for (block = 0; block < IDX_STEP; ++block) {
    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (i = chacha_rounds;i > 0;i -= 2) {
      QUARTERROUND( x0, x4, x8,x12)
      QUARTERROUND( x1, x5, x9,x13)
      QUARTERROUND( x2, x6,x10,x14)
      QUARTERROUND( x3, x7,x11,x15)
      QUARTERROUND( x0, x5,x10,x15)
      QUARTERROUND( x1, x6,x11,x12)
      QUARTERROUND( x2, x7, x8,x13)
      QUARTERROUND( x3, x4, x9,x14)
    }
    x0 = PLUS(x0,j0);
    x1 = PLUS(x1,j1);
    x2 = PLUS(x2,j2);
    x3 = PLUS(x3,j3);
    x4 = PLUS(x4,j4);
    x5 = PLUS(x5,j5);
    x6 = PLUS(x6,j6);
    x7 = PLUS(x7,j7);
    x8 = PLUS(x8,j8);
    x9 = PLUS(x9,j9);
    x10 = PLUS(x10,j10);
    x11 = PLUS(x11,j11);
    x12 = PLUS(x12,j12);
    x13 = PLUS(x13,j13);
    x14 = PLUS(x14,j14);
    x15 = PLUS(x15,j15);

    j12 = PLUSONE(j12);
    /* Ottery: j13 can never need to be incremented. */

    U32TO8_LITTLE(c + 0,x0);
    U32TO8_LITTLE(c + 4,x1);
    U32TO8_LITTLE(c + 8,x2);
    U32TO8_LITTLE(c + 12,x3);
    U32TO8_LITTLE(c + 16,x4);
    U32TO8_LITTLE(c + 20,x5);
    U32TO8_LITTLE(c + 24,x6);

    U32TO8_LITTLE(c + 28,x7);
    U32TO8_LITTLE(c + 32,x8);
    U32TO8_LITTLE(c + 36,x9);
    U32TO8_LITTLE(c + 40,x10);
    U32TO8_LITTLE(c + 44,x11);
    U32TO8_LITTLE(c + 48,x12);
    U32TO8_LITTLE(c + 52,x13);
    U32TO8_LITTLE(c + 56,x14);
    U32TO8_LITTLE(c + 60,x15);

    c += 64;
  }
}

#define STATE_LEN   (sizeof(ECRYPT_ctx))
#define STATE_BYTES 40

static void
chacha_merged_state_setup(void *state_, const uint8_t *bytes)
{
  ECRYPT_ctx *x = state_;
  ECRYPT_keysetup(x, bytes, 0);
  ECRYPT_ivsetup(x, bytes+32);
}

static void
chacha8_merged_generate(void *state_, uint8_t *output, uint32_t idx)
{
  ECRYPT_ctx *x = state_;
  x->input[12] = idx * IDX_STEP;
  chacha_merged_getblocks(8, x, output);
}

static void
chacha12_merged_generate(void *state_, uint8_t *output, uint32_t idx)
{
  ECRYPT_ctx *x = state_;
  x->input[12] = idx * IDX_STEP;
  chacha_merged_getblocks(12, x, output);
}

static void
chacha20_merged_generate(void *state_, uint8_t *output, uint32_t idx)
{
  ECRYPT_ctx *x = state_;
  x->input[12] = idx * IDX_STEP;
  chacha_merged_getblocks(20, x, output);
}

#define PRF_CHACHA(r) {                         \
  "CHACHA" #r,                                  \
  "CHACHA" #r "-NOSIMD",                        \
  "CHACHA" #r "-NOSIMD-DEFAULT",                \
  STATE_LEN,                                    \
  STATE_BYTES,                                  \
  OUTPUT_LEN,                                   \
  0,                                            \
  chacha_merged_state_setup,                    \
  chacha ## r ## _merged_generate               \
}

const struct ottery_prf ottery_prf_chacha8_merged_ = PRF_CHACHA(8);
const struct ottery_prf ottery_prf_chacha12_merged_ = PRF_CHACHA(12);
const struct ottery_prf ottery_prf_chacha20_merged_ = PRF_CHACHA(20);

