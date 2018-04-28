/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#include "config.h"
#include "t1ha_bits.h"

static __always_inline void init_ab(t1ha_state256_t *s, uint64_t x,
                                    uint64_t y) {
  s->n.a = x;
  s->n.b = y;
}

static __always_inline void init_cd(t1ha_state256_t *s, uint64_t x,
                                    uint64_t y) {
  s->n.c = rot64(y, 23) + ~x;
  s->n.d = ~y + rot64(x, 19);
}

static __always_inline void update(t1ha_state256_t *__restrict s,
                                   const uint64_t *__restrict v) {
  uint64_t w0 = fetch64_le(v + 0);
  uint64_t w1 = fetch64_le(v + 1);
  uint64_t w2 = fetch64_le(v + 2);
  uint64_t w3 = fetch64_le(v + 3);

  uint64_t d02 = w0 + rot64(w2 + s->n.d, 56);
  uint64_t c13 = w1 + rot64(w3 + s->n.c, 19);
#ifdef __e2k__
  /* FIXME: temporary workaround for lcc's ELBRUS scheduling bug (LY) */
  s->n.c ^= s->n.a + rot64(w0, 57);
  s->n.d ^= s->n.b + rot64(w1, 38);
#else
  s->n.d ^= s->n.b + rot64(w1, 38);
  s->n.c ^= s->n.a + rot64(w0, 57);
#endif
  s->n.b ^= prime_6 * (c13 + w2);
  s->n.a ^= prime_5 * (d02 + w3);
}

static __always_inline void squash(t1ha_state256_t *s) {
  s->n.a ^= prime_6 * (s->n.c + rot64(s->n.d, 23));
  s->n.b ^= prime_5 * (rot64(s->n.c, 19) + s->n.d);
}

static __always_inline const void *
loop(bool need_copy4align, uint64_t *__restrict buffer4align,
     t1ha_state256_t *__restrict s, const void *__restrict data, size_t len) {
  const void *detent = (const uint8_t *)data + len - 31;
  do {
    const uint64_t *v = (const uint64_t *)data;
    if (unlikely(need_copy4align))
      v = (const uint64_t *)memcpy(buffer4align, unaligned(v), 32);
    update(s, v);
    data = (const uint64_t *)data + 4;
  } while (likely(data < detent));
  return data;
}

static __always_inline void tail_ab(t1ha_state256_t *__restrict s,
                                    const uint64_t *__restrict v, size_t len) {
  switch (len) {
  default:
    mixup64(&s->n.a, &s->n.b, fetch64_le(v++), prime_4);
  /* fall through */
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    mixup64(&s->n.b, &s->n.a, fetch64_le(v++), prime_3);
  /* fall through */
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    mixup64(&s->n.a, &s->n.b, fetch64_le(v++), prime_2);
  /* fall through */
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    mixup64(&s->n.b, &s->n.a, tail64_le(v, len), prime_1);
  /* fall through */
  case 0:
    return;
  }
}

static __always_inline void tail_abcd(t1ha_state256_t *__restrict s,
                                      const uint64_t *__restrict v,
                                      size_t len) {
  switch (len) {
  default:
    mixup64(&s->n.a, &s->n.d, fetch64_le(v++), prime_4);
  /* fall through */
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    mixup64(&s->n.b, &s->n.a, fetch64_le(v++), prime_3);
  /* fall through */
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    mixup64(&s->n.c, &s->n.b, fetch64_le(v++), prime_2);
  /* fall through */
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    mixup64(&s->n.d, &s->n.c, tail64_le(v, len), prime_1);
  /* fall through */
  case 0:
    return;
  }
}

static __always_inline uint64_t final128(uint64_t a, uint64_t b, uint64_t c,
                                         uint64_t d, uint64_t *h) {
  mixup64(&a, &b, rot64(c, 41) ^ d, prime_0);
  mixup64(&b, &c, rot64(d, 23) ^ a, prime_6);
  mixup64(&c, &d, rot64(a, 19) ^ b, prime_5);
  mixup64(&d, &a, rot64(b, 31) ^ c, prime_4);
  *h = c + d;
  return a ^ b;
}

//------------------------------------------------------------------------------

uint64_t t1ha2_atonce(const void *data, size_t length, uint64_t seed) {
  t1ha_state256_t state;
  init_ab(&state, seed, length);

  const int need_copy4align = (((uintptr_t)data) & 7) != 0 && !UNALIGNED_OK;
  uint64_t buffer4align[4];

  if (unlikely(length > 32)) {
    init_cd(&state, seed, length);
    data = loop(need_copy4align, buffer4align, &state, data, length);
    squash(&state);
    length &= 31;
  }

  const uint64_t *v = (const uint64_t *)data;
  if (unlikely(need_copy4align) && length > 8)
    v = (const uint64_t *)memcpy(&buffer4align, unaligned(v), length);

  tail_ab(&state, v, length);
  return final64(state.n.a, state.n.b);
}

uint64_t t1ha2_atonce128(uint64_t *__restrict extra_result,
                         const void *__restrict data, size_t length,
                         uint64_t seed) {
  t1ha_state256_t state;
  init_ab(&state, seed, length);
  init_cd(&state, seed, length);

  const int need_copy4align = (((uintptr_t)data) & 7) != 0 && !UNALIGNED_OK;
  uint64_t buffer4align[4];

  if (unlikely(length > 32)) {
    data = loop(need_copy4align, buffer4align, &state, data, length);
    length &= 31;
  }

  const uint64_t *v = (const uint64_t *)data;
  if (unlikely(need_copy4align) && length > 8)
    v = (const uint64_t *)memcpy(&buffer4align, unaligned(v), length);

  tail_abcd(&state, v, length);
  return final128(state.n.a, state.n.b, state.n.c, state.n.d, extra_result);
}

//------------------------------------------------------------------------------

void t1ha2_init(t1ha_context_t *ctx, uint64_t seed_x, uint64_t seed_y) {
  init_ab(&ctx->state, seed_x, seed_y);
  init_cd(&ctx->state, seed_x, seed_y);
  ctx->partial = 0;
  ctx->total = 0;
}

void t1ha2_update(t1ha_context_t *__restrict ctx, const void *__restrict data,
                  size_t length) {
  ctx->total += length;

  if (ctx->partial) {
    const size_t left = 32 - ctx->partial;
    const size_t chunk = (length >= left) ? left : length;
    memcpy(ctx->buffer.bytes + ctx->partial, unaligned(data), chunk);
    ctx->partial += chunk;
    if (ctx->partial < 32) {
      assert(left >= length);
      return;
    }
    ctx->partial = 0;
    data = (const uint8_t *)data + chunk;
    length -= chunk;
    update(&ctx->state, ctx->buffer.u64);
  }

  if (length >= 32) {
    const bool need_copy4align = (((uintptr_t)data) & 7) != 0 && !UNALIGNED_OK;
    if (need_copy4align)
      data = loop(true, ctx->buffer.u64, &ctx->state, data, length);
    else
      data = loop(false, NULL, &ctx->state, data, length);
    length &= 31;
  }

  if (length)
    memcpy(ctx->buffer.bytes, unaligned(data), ctx->partial = length);
}

uint64_t t1ha2_final(t1ha_context_t *__restrict ctx,
                     uint64_t *__restrict extra_result) {
  uint64_t bytes = (ctx->total << 3) ^ (UINT64_C(1) << 63);
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
  bytes = bswap64(bytes);
#endif
  t1ha2_update(ctx, &bytes, 8);

  if (likely(!extra_result)) {
    squash(&ctx->state);
    tail_ab(&ctx->state, ctx->buffer.u64, ctx->partial);
    return final64(ctx->state.n.a, ctx->state.n.b);
  }

  tail_abcd(&ctx->state, ctx->buffer.u64, ctx->partial);
  return final128(ctx->state.n.a, ctx->state.n.b, ctx->state.n.c,
                  ctx->state.n.d, extra_result);
}
