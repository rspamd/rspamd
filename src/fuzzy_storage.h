#ifndef RSPAMD_FUZZY_STORAGE_H
#define RSPAMD_FUZZY_STORAGE_H

#include "config.h"
#include "rspamd.h"
#include "shingles.h"
#include "cryptobox.h"

#define RSPAMD_FUZZY_VERSION 3
#define RSPAMD_FUZZY_KEYLEN 8

/* Commands for fuzzy storage */
#define FUZZY_CHECK 0
#define FUZZY_WRITE 1
#define FUZZY_DEL 2
#define FUZZY_STAT 3


/**
 * The epoch of the fuzzy client
 */
enum rspamd_fuzzy_epoch {
	RSPAMD_FUZZY_EPOCH6 = 0, /**< pre 0.6.x */
	RSPAMD_FUZZY_EPOCH8, /**< 0.8 till 0.9 */
	RSPAMD_FUZZY_EPOCH9, /**< 0.9 + */
	RSPAMD_FUZZY_EPOCH10, /**< 1.0+ encryption */
	RSPAMD_FUZZY_EPOCH_MAX
};

RSPAMD_PACKED(rspamd_fuzzy_cmd) {
	guint8 version;
	guint8 cmd;
	guint8 shingles_count;
	guint8 flag;
	gint32 value;
	guint32 tag;
	gchar digest[rspamd_cryptobox_HASHBYTES];
};

RSPAMD_PACKED(rspamd_fuzzy_shingle_cmd) {
	struct rspamd_fuzzy_cmd basic;
	struct rspamd_shingle sgl;
};

RSPAMD_PACKED(rspamd_fuzzy_reply) {
	gint32 value;
	guint32 flag;
	guint32 tag;
	float prob;
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_req_hdr) {
	guchar magic[4];
	guchar key_id[RSPAMD_FUZZY_KEYLEN];
	guchar pubkey[32];
	guchar nonce[rspamd_cryptobox_MAX_NONCEBYTES];
	guchar mac[rspamd_cryptobox_MAX_MACBYTES];
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_cmd) {
	struct rspamd_fuzzy_encrypted_req_hdr hdr;
	struct rspamd_fuzzy_cmd cmd;
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_shingle_cmd) {
	struct rspamd_fuzzy_encrypted_req_hdr hdr;
	struct rspamd_fuzzy_shingle_cmd cmd;
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_rep_hdr) {
	guchar nonce[rspamd_cryptobox_MAX_NONCEBYTES];
	guchar mac[rspamd_cryptobox_MAX_MACBYTES];
};

RSPAMD_PACKED(rspamd_fuzzy_encrypted_reply) {
	struct rspamd_fuzzy_encrypted_rep_hdr hdr;
	struct rspamd_fuzzy_reply rep;
};

static const guchar fuzzy_encrypted_magic[4] = {'r', 's', 'f', 'e'};

struct rspamd_fuzzy_stat_entry {
	const gchar *name;
	guint32 fuzzy_cnt;
};

#endif
