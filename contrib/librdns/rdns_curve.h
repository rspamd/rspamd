/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
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
#ifndef RDNS_CURVE_H_
#define RDNS_CURVE_H_

#ifdef  __cplusplus
extern "C" {
#endif

struct rdns_curve_ctx;

/**
 * Create new dnscurve ctx
 * @return
 */
struct rdns_curve_ctx* rdns_curve_ctx_new (double rekey_interval);

/**
 * Add key for server `name`
 * @param ctx curve context
 * @param name name of server (ip address)
 * @param pubkey pubkey bytes (must be `RDSN_CURVE_PUBKEY_LEN`)
 */
void rdns_curve_ctx_add_key (struct rdns_curve_ctx *ctx,
		const char *name, const unsigned char *pubkey);

/**
 * Destroy curve context
 * @param ctx
 */
void rdns_curve_ctx_destroy (struct rdns_curve_ctx *ctx);


/**
 * Register DNSCurve plugin (libsodium should be enabled for this)
 * @param resolver
 * @param ctx
 */
void rdns_curve_register_plugin (struct rdns_resolver *resolver,
		struct rdns_curve_ctx *ctx);

/**
 * Create DNSCurve key from the base16 encoded string
 * @param hex input hex (must be NULL terminated)
 * @return a key or NULL (not NULL terminated)
 */
unsigned char * rdns_curve_key_from_hex (const char *hex);

#ifdef  __cplusplus
}
#endif

#endif /* RDNS_CURVE_H_ */
