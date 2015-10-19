#ifndef RSPAMD_FUZZY_STORAGE_H
#define RSPAMD_FUZZY_STORAGE_H

#include "config.h"
#include "rspamd.h"
#include "shingles.h"
#include "cryptobox.h"

#define RSPAMD_FUZZY_VERSION 3

/* Commands for fuzzy storage */
#define FUZZY_CHECK 0
#define FUZZY_WRITE 1
#define FUZZY_DEL 2

RSPAMD_PACKED(rspamd_fuzzy_cmd) {
	guint8 version;
	guint8 cmd;
	guint8 shingles_count;
	guint8 flag;
	gint32 value;
	guint32 tag;
	gchar digest[64];
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
	guchar reserved[8];
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

#endif
