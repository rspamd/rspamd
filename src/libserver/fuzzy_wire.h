/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_FUZZY_STORAGE_H
#define RSPAMD_FUZZY_STORAGE_H

#include "config.h"
#include "rspamd.h"
#include "shingles.h"
#include "cryptobox.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSPAMD_FUZZY_VERSION 4
#define RSPAMD_FUZZY_KEYLEN 8

#define RSPAMD_FUZZY_FLAG_WEAK (1u << 7u)
/* Use lower 4 bits for the version */
#define RSPAMD_FUZZY_VERSION_MASK 0x0fu
/* Capability bit: client supports v2 (multi-flag) replies */
#define RSPAMD_FUZZY_V2_CAP (1u << 4u)
/* Commands for fuzzy storage */
#define FUZZY_CHECK 0
#define FUZZY_WRITE 1
#define FUZZY_DEL 2
#define FUZZY_STAT 3
#define FUZZY_PING 4
#define FUZZY_CLIENT_MAX 4
/* Internal commands */
#define FUZZY_REFRESH 100 /* Update expire */
#define FUZZY_DUP 101     /* Skip duplicate in update queue */

/**
 * The epoch of the fuzzy client
 */
enum rspamd_fuzzy_epoch {
	RSPAMD_FUZZY_EPOCH10, /**< 1.0+ encryption */
	RSPAMD_FUZZY_EPOCH11, /**< 1.7+ extended reply */
	RSPAMD_FUZZY_EPOCH12, /**< multi-flag reply */
	RSPAMD_FUZZY_EPOCH_MAX
};

RSPAMD_PACKED(rspamd_fuzzy_cmd)
{
	uint8_t version;
	uint8_t cmd;
	uint8_t shingles_count;
	uint8_t flag;
	int32_t value;
	uint32_t tag;
	char digest[rspamd_cryptobox_HASHBYTES];
};

RSPAMD_PACKED(rspamd_fuzzy_shingle_cmd)
{
	struct rspamd_fuzzy_cmd basic;
	struct rspamd_shingle sgl;
};

RSPAMD_PACKED(rspamd_fuzzy_reply_v1)
{
	int32_t value;
	uint32_t flag;
	uint32_t tag;
	float prob;
};

/*
 * Flags stored in the first reserved byte of a reply.
 * MATCHED_DIGEST is set when the digest field contains the actual digest
 * stored in the storage (a direct or shingle match resolved by the
 * backend); legacy storages leave the reserved bytes zeroed, so its
 * absence merely means "unknown".
 */
#define RSPAMD_FUZZY_REPLY_FLAG_MATCHED_DIGEST (1u << 0u)

RSPAMD_PACKED(rspamd_fuzzy_reply)
{
	struct rspamd_fuzzy_reply_v1 v1;
	char digest[rspamd_cryptobox_HASHBYTES];
	uint32_t ts;
	unsigned char reserved[12];
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_req_hdr)
{
	unsigned char magic[4];
	unsigned char key_id[RSPAMD_FUZZY_KEYLEN];
	unsigned char pubkey[32];
	unsigned char nonce[rspamd_cryptobox_MAX_NONCEBYTES];
	unsigned char mac[rspamd_cryptobox_MAX_MACBYTES];
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_cmd)
{
	struct rspamd_fuzzy_encrypted_req_hdr hdr;
	struct rspamd_fuzzy_cmd cmd;
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_shingle_cmd)
{
	struct rspamd_fuzzy_encrypted_req_hdr hdr;
	struct rspamd_fuzzy_shingle_cmd cmd;
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_rep_hdr)
{
	unsigned char nonce[rspamd_cryptobox_MAX_NONCEBYTES];
	unsigned char mac[rspamd_cryptobox_MAX_MACBYTES];
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_reply)
{
	struct rspamd_fuzzy_encrypted_rep_hdr hdr;
	struct rspamd_fuzzy_reply rep;
};

#define RSPAMD_FUZZY_MAX_EXTRA_FLAGS 7

RSPAMD_PACKED(rspamd_fuzzy_flag_entry)
{
	int32_t value;
	uint32_t flag;
};

RSPAMD_PACKED(rspamd_fuzzy_reply_v2)
{
	struct rspamd_fuzzy_reply_v1 v1;
	char digest[rspamd_cryptobox_HASHBYTES];
	uint32_t ts;
	uint8_t n_extra_flags;
	uint8_t reserved[3];
	struct rspamd_fuzzy_flag_entry extra_flags[RSPAMD_FUZZY_MAX_EXTRA_FLAGS];
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_reply_v2)
{
	struct rspamd_fuzzy_encrypted_rep_hdr hdr;
	struct rspamd_fuzzy_reply_v2 rep;
};

static const unsigned char fuzzy_encrypted_magic[4] = {'r', 's', 'f', 'e'};

/*
 * Extensions are a sequence of TLV entries appended to a fuzzy command.
 *
 * Framing depends on the type byte:
 *
 * - types below RSPAMD_FUZZY_EXT_SKIPPABLE_MIN are legacy ones where the
 *   length is implied by the type itself. A parser that does not know such a
 *   type cannot tell where the entry ends, so it has no choice but to reject
 *   the whole command;
 * - types starting from RSPAMD_FUZZY_EXT_SKIPPABLE_MIN are always followed by
 *   a single length byte, so an unknown entry in that range can be skipped
 *   and the remaining extensions are still parsed.
 *
 * Hence, all new extensions MUST use the skippable range.
 */
#define RSPAMD_FUZZY_EXT_SKIPPABLE_MIN 0x80

enum rspamd_fuzzy_extension_type {
	/* Legacy types, implicit length */
	RSPAMD_FUZZY_EXT_SOURCE_DOMAIN = 'd', /* length byte + MIME From domain */
	RSPAMD_FUZZY_EXT_SOURCE_IP4 = '4',    /* 4 bytes */
	RSPAMD_FUZZY_EXT_SOURCE_IP6 = '6',    /* 16 bytes */
	/* Skippable types, explicit length byte */
	RSPAMD_FUZZY_EXT_SENDER_FACTS = 0x80, /* 4 bytes, big endian bit field */
};

struct rspamd_fuzzy_cmd_extension {
	enum rspamd_fuzzy_extension_type ext;
	unsigned int length;
	struct rspamd_fuzzy_cmd_extension *next;
	unsigned char *payload;
};

/**
 * Parse the wire representation of the command extensions.
 *
 * Unknown types in the skippable range are ignored, everything else that
 * cannot be understood or does not fit into the buffer is an error.
 *
 * @param buf start of the extensions area
 * @param buflen its length
 * @param res on success set to the head of the extensions list or to NULL if
 *            there were no extensions we know about; the list is a single
 *            allocation that must be released by one g_free()
 * @return FALSE if the extensions area is malformed
 */
gboolean rspamd_fuzzy_extensions_from_wire(const unsigned char *buf, gsize buflen,
										   struct rspamd_fuzzy_cmd_extension **res);

/*
 * RSPAMD_FUZZY_EXT_SENDER_FACTS payload: a big endian uint32 describing the
 * sender (and only the sender: never the recipient, the local users or the
 * local policy).
 *
 * The top 8 bits are a class byte that allows the meaning of the remaining 24
 * bits to be redefined later without spending another extension type. The
 * layout below is class 0, any other class must be ignored by a reader that
 * does not know it.
 *
 * The payload is exactly RSPAMD_FUZZY_SENDER_FACTS_LEN bytes and the parser
 * rejects any other length: since the type is known, a different length is a
 * malformed packet. Should a wider payload ever be needed it has to take a new
 * type byte from the skippable range (which older parsers then skip) rather
 * than grow this one (which they could not).
 */
#define RSPAMD_FUZZY_SENDER_FACTS_LEN 4
#define RSPAMD_FUZZY_SENDER_FACTS_CLASS_SHIFT 24
#define RSPAMD_FUZZY_SENDER_FACTS_CLASS_MASK 0xffu
#define RSPAMD_FUZZY_SENDER_FACTS_CLASS_V0 0

#define RSPAMD_FUZZY_SF_SPF_SHIFT 0
#define RSPAMD_FUZZY_SF_SPF_MASK 0x7u
#define RSPAMD_FUZZY_SF_DKIM_SHIFT 3
#define RSPAMD_FUZZY_SF_DKIM_MASK 0x7u
#define RSPAMD_FUZZY_SF_DMARC_SHIFT 6
#define RSPAMD_FUZZY_SF_DMARC_MASK 0x7u
#define RSPAMD_FUZZY_SF_PTR_SHIFT 9
#define RSPAMD_FUZZY_SF_PTR_MASK 0x3u
#define RSPAMD_FUZZY_SF_PTR_GENERIC_SHIFT 11
#define RSPAMD_FUZZY_SF_RCPTS_SHIFT 12
#define RSPAMD_FUZZY_SF_RCPTS_MASK 0x3u
#define RSPAMD_FUZZY_SF_TLS_SHIFT 14
/* Bits 15..23: reserved, written as zero and ignored on read */
#define RSPAMD_FUZZY_SF_RESERVED_MASK 0xff8000u

enum rspamd_fuzzy_sf_spf {
	RSPAMD_FUZZY_SF_SPF_ABSENT = 0,
	RSPAMD_FUZZY_SF_SPF_NONE,
	RSPAMD_FUZZY_SF_SPF_PASS,
	RSPAMD_FUZZY_SF_SPF_FAIL,
	RSPAMD_FUZZY_SF_SPF_SOFTFAIL,
	RSPAMD_FUZZY_SF_SPF_NEUTRAL,
	RSPAMD_FUZZY_SF_SPF_PERMERROR,
	RSPAMD_FUZZY_SF_SPF_TEMPERROR,
};

enum rspamd_fuzzy_sf_dkim {
	RSPAMD_FUZZY_SF_DKIM_ABSENT = 0,
	RSPAMD_FUZZY_SF_DKIM_NONE,
	RSPAMD_FUZZY_SF_DKIM_PASS,
	RSPAMD_FUZZY_SF_DKIM_FAIL,
	RSPAMD_FUZZY_SF_DKIM_PERMERROR,
	RSPAMD_FUZZY_SF_DKIM_TEMPERROR,
};

enum rspamd_fuzzy_sf_dmarc {
	RSPAMD_FUZZY_SF_DMARC_ABSENT = 0,
	RSPAMD_FUZZY_SF_DMARC_NO_RECORD,
	RSPAMD_FUZZY_SF_DMARC_PASS,
	RSPAMD_FUZZY_SF_DMARC_FAIL_NONE,
	RSPAMD_FUZZY_SF_DMARC_FAIL_QUARANTINE,
	RSPAMD_FUZZY_SF_DMARC_FAIL_REJECT,
	RSPAMD_FUZZY_SF_DMARC_PERMERROR,
	RSPAMD_FUZZY_SF_DMARC_TEMPERROR,
};

enum rspamd_fuzzy_sf_ptr {
	RSPAMD_FUZZY_SF_PTR_UNKNOWN = 0,
	RSPAMD_FUZZY_SF_PTR_NONE,
	RSPAMD_FUZZY_SF_PTR_PRESENT,
	RSPAMD_FUZZY_SF_PTR_CONFIRMED,
};

enum rspamd_fuzzy_sf_rcpts {
	RSPAMD_FUZZY_SF_RCPTS_ONE = 0,
	RSPAMD_FUZZY_SF_RCPTS_FEW,  /* 2..5 */
	RSPAMD_FUZZY_SF_RCPTS_MANY, /* 6..20 */
	RSPAMD_FUZZY_SF_RCPTS_BULK, /* 21+ */
};

static inline uint32_t
rspamd_fuzzy_sf_pack(unsigned int spf, unsigned int dkim, unsigned int dmarc,
					 unsigned int ptr, gboolean ptr_generic,
					 unsigned int rcpts, gboolean tls)
{
	return ((spf & RSPAMD_FUZZY_SF_SPF_MASK) << RSPAMD_FUZZY_SF_SPF_SHIFT) |
		   ((dkim & RSPAMD_FUZZY_SF_DKIM_MASK) << RSPAMD_FUZZY_SF_DKIM_SHIFT) |
		   ((dmarc & RSPAMD_FUZZY_SF_DMARC_MASK) << RSPAMD_FUZZY_SF_DMARC_SHIFT) |
		   ((ptr & RSPAMD_FUZZY_SF_PTR_MASK) << RSPAMD_FUZZY_SF_PTR_SHIFT) |
		   ((ptr_generic ? 1u : 0u) << RSPAMD_FUZZY_SF_PTR_GENERIC_SHIFT) |
		   ((rcpts & RSPAMD_FUZZY_SF_RCPTS_MASK) << RSPAMD_FUZZY_SF_RCPTS_SHIFT) |
		   ((tls ? 1u : 0u) << RSPAMD_FUZZY_SF_TLS_SHIFT) |
		   ((uint32_t) RSPAMD_FUZZY_SENDER_FACTS_CLASS_V0
			<< RSPAMD_FUZZY_SENDER_FACTS_CLASS_SHIFT);
}

static inline const char *
rspamd_fuzzy_sf_spf_str(unsigned int v)
{
	static const char *tbl[] = {NULL, "none", "pass", "fail", "softfail",
								"neutral", "permerror", "temperror"};

	return v < G_N_ELEMENTS(tbl) ? tbl[v] : NULL;
}

static inline const char *
rspamd_fuzzy_sf_dkim_str(unsigned int v)
{
	static const char *tbl[] = {NULL, "none", "pass", "fail", "permerror",
								"temperror"};

	return v < G_N_ELEMENTS(tbl) ? tbl[v] : NULL;
}

static inline const char *
rspamd_fuzzy_sf_dmarc_str(unsigned int v)
{
	static const char *tbl[] = {NULL, "no_record", "pass", "fail_none",
								"fail_quarantine", "fail_reject", "permerror",
								"temperror"};

	return v < G_N_ELEMENTS(tbl) ? tbl[v] : NULL;
}

static inline const char *
rspamd_fuzzy_sf_ptr_str(unsigned int v)
{
	static const char *tbl[] = {NULL, "none", "present", "confirmed"};

	return v < G_N_ELEMENTS(tbl) ? tbl[v] : NULL;
}

static inline const char *
rspamd_fuzzy_sf_rcpts_str(unsigned int v)
{
	static const char *tbl[] = {"1", "2-5", "6-20", "21+"};

	return v < G_N_ELEMENTS(tbl) ? tbl[v] : NULL;
}

struct rspamd_fuzzy_stat_entry {
	const char *name;
	uint64_t fuzzy_cnt;
};

RSPAMD_PACKED(fuzzy_peer_cmd)
{
	int32_t is_shingle;
	union {
		struct rspamd_fuzzy_cmd normal;
		struct rspamd_fuzzy_shingle_cmd shingle;
	} cmd;
};

#ifdef __cplusplus
}
#endif

#endif
