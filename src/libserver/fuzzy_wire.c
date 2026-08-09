/*
 * Copyright 2025 Vsevolod Stakhov
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

#include "config.h"
#include "fuzzy_wire.h"

enum rspamd_fuzzy_ext_step {
	RSPAMD_FUZZY_EXT_STEP_KNOWN,
	RSPAMD_FUZZY_EXT_STEP_SKIP,
	RSPAMD_FUZZY_EXT_STEP_ERROR,
};

/*
 * Decode a single TLV entry starting at *pp (which must be less than end) and
 * advance *pp past it. The buffer is never modified, payload points inside it.
 */
static enum rspamd_fuzzy_ext_step
rspamd_fuzzy_ext_next(const unsigned char **pp, const unsigned char *end,
					  unsigned char *type, const unsigned char **payload,
					  unsigned int *length)
{
	const unsigned char *p = *pp;
	unsigned char t = *p++;
	unsigned int len;
	gboolean known;

	switch (t) {
	case RSPAMD_FUZZY_EXT_SOURCE_IP4:
		len = sizeof(struct in_addr);
		known = TRUE;
		break;
	case RSPAMD_FUZZY_EXT_SOURCE_IP6:
		len = sizeof(struct in6_addr);
		known = TRUE;
		break;
	case RSPAMD_FUZZY_EXT_SOURCE_DOMAIN:
		if (p >= end) {
			/* Truncated length byte */
			return RSPAMD_FUZZY_EXT_STEP_ERROR;
		}

		len = *p++;
		known = TRUE;
		break;
	default:
		if (t < RSPAMD_FUZZY_EXT_SKIPPABLE_MIN) {
			/*
			 * A legacy type we do not know: its length is implied by the type,
			 * so we cannot tell where this entry ends
			 */
			return RSPAMD_FUZZY_EXT_STEP_ERROR;
		}

		if (p >= end) {
			/* Truncated length byte */
			return RSPAMD_FUZZY_EXT_STEP_ERROR;
		}

		len = *p++;

		if (t == RSPAMD_FUZZY_EXT_SENDER_FACTS) {
			if (len != RSPAMD_FUZZY_SENDER_FACTS_LEN) {
				/*
				 * We do know this type and it is fixed width, so a different
				 * length is a malformed packet rather than a dialect from the
				 * future: anything that needs a wider payload has to take a
				 * new type byte instead of growing this one
				 */
				return RSPAMD_FUZZY_EXT_STEP_ERROR;
			}

			known = TRUE;
		}
		else {
			known = FALSE;
		}
		break;
	}

	if (len > (gsize) (end - p)) {
		/* Truncation */
		return RSPAMD_FUZZY_EXT_STEP_ERROR;
	}

	*type = t;
	*payload = p;
	*length = len;
	*pp = p + len;

	return known ? RSPAMD_FUZZY_EXT_STEP_KNOWN : RSPAMD_FUZZY_EXT_STEP_SKIP;
}

gboolean
rspamd_fuzzy_extensions_from_wire(const unsigned char *buf, gsize buflen,
								  struct rspamd_fuzzy_cmd_extension **res)
{
	const unsigned char *p, *end = buf + buflen, *payload;
	struct rspamd_fuzzy_cmd_extension *exts;
	unsigned char *storage, *data_buf;
	unsigned char type;
	unsigned int length;
	gsize st_len = 0, n_ext = 0, i;

	g_assert(res != NULL);
	*res = NULL;

	/* First pass: validate everything and count what we can store */
	for (p = buf; p < end;) {
		switch (rspamd_fuzzy_ext_next(&p, end, &type, &payload, &length)) {
		case RSPAMD_FUZZY_EXT_STEP_KNOWN:
			n_ext++;
			st_len += length;
			break;
		case RSPAMD_FUZZY_EXT_STEP_SKIP:
			break;
		default:
			return FALSE;
		}
	}

	if (n_ext == 0) {
		return TRUE;
	}

	/*
	 * Memory layout: n_ext of struct rspamd_fuzzy_cmd_extension
	 *                payload for each extension in a continuous data segment
	 */
	storage = g_malloc(n_ext * sizeof(struct rspamd_fuzzy_cmd_extension) + st_len);
	exts = (struct rspamd_fuzzy_cmd_extension *) storage;
	data_buf = storage + n_ext * sizeof(struct rspamd_fuzzy_cmd_extension);

	/* Second pass: the buffer has been validated, so merely copy the payloads */
	for (p = buf, i = 0; p < end && i < n_ext;) {
		enum rspamd_fuzzy_ext_step step = rspamd_fuzzy_ext_next(&p, end, &type,
																&payload, &length);

		if (step == RSPAMD_FUZZY_EXT_STEP_SKIP) {
			continue;
		}
		else if (step != RSPAMD_FUZZY_EXT_STEP_KNOWN) {
			/* Cannot happen as the first pass has validated the buffer */
			break;
		}

		exts[i].ext = type;
		exts[i].length = length;
		exts[i].payload = data_buf;
		exts[i].next = NULL;
		memcpy(data_buf, payload, length);
		data_buf += length;

		if (i > 0) {
			exts[i - 1].next = &exts[i];
		}

		i++;
	}

	if (i == 0) {
		g_free(storage);

		return TRUE;
	}

	*res = exts;

	return TRUE;
}
