/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "ottery-internal.h"
#include "libcryptobox/chacha20/chacha.h"

#define STATE_LEN   (sizeof(chacha_state))
#define STATE_BYTES 40

#define IDX_STEP    16
#define OUTPUT_LEN  (IDX_STEP * 64)

static void
chacha20_cryptobox_state_setup (void *state_, const uint8_t *bytes)
{
	chacha_state *x = state_;
	chacha_init (x, (chacha_key *)bytes, (chacha_iv *)(bytes + 32), 20);
}

static void
chacha20_cryptobox_generate (void *state_, uint8_t *output, uint32_t idx)
{
	chacha_state *x = state_;

	memset (output, 0, OUTPUT_LEN);
	memcpy (output, &idx, sizeof (idx));
	chacha_update (x, output, output, OUTPUT_LEN);
}

#define PRF_CHACHA(r) {                         \
  "CHACHA" #r "-CRYPTOBOX",                    \
  "CHACHA" #r "-CRYPTOBOX",                    \
  "CHACHA" #r "-CRYPTOBOX",                    \
  STATE_LEN,                                    \
  STATE_BYTES,                                  \
  OUTPUT_LEN,                                   \
  0,                                             \
  chacha ## r ## _cryptobox_state_setup,         \
  chacha ## r ## _cryptobox_generate             \
}

const struct ottery_prf ottery_prf_chacha20_cryptobox_ = PRF_CHACHA(20);
