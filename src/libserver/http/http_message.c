/*-
 * Copyright 2019 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "http_message.h"
#include "http_connection.h"
#include "http_private.h"
#include "libutil/printf.h"
#include "libserver/logger.h"
#include "utlist.h"
#include "unix-std.h"

struct rspamd_http_message *
rspamd_http_new_message (enum rspamd_http_message_type type)
{
	struct rspamd_http_message *new;

	new = g_malloc0 (sizeof (struct rspamd_http_message));

	if (type == HTTP_REQUEST) {
		new->url = rspamd_fstring_new ();
	}
	else {
		new->url = NULL;
		new->code = 200;
	}

	new->port = 80;
	new->type = type;
	new->method = HTTP_INVALID;
	new->headers = kh_init (rspamd_http_headers_hash);

	REF_INIT_RETAIN (new, rspamd_http_message_free);

	return new;
}

struct rspamd_http_message*
rspamd_http_message_from_url (const gchar *url)
{
	struct http_parser_url pu;
	struct rspamd_http_message *msg;
	const gchar *host, *path;
	size_t pathlen, urllen;
	guint flags = 0;

	if (url == NULL) {
		return NULL;
	}

	urllen = strlen (url);
	memset (&pu, 0, sizeof (pu));

	if (http_parser_parse_url (url, urllen, FALSE, &pu) != 0) {
		msg_warn ("cannot parse URL: %s", url);
		return NULL;
	}

	if ((pu.field_set & (1 << UF_HOST)) == 0) {
		msg_warn ("no host argument in URL: %s", url);
		return NULL;
	}

	if ((pu.field_set & (1 << UF_SCHEMA))) {
		if (pu.field_data[UF_SCHEMA].len == sizeof ("https") - 1 &&
			memcmp (url + pu.field_data[UF_SCHEMA].off, "https", 5) == 0) {
			flags |= RSPAMD_HTTP_FLAG_SSL;
		}
	}

	if ((pu.field_set & (1 << UF_PATH)) == 0) {
		path = "/";
		pathlen = 1;
	}
	else {
		path = url + pu.field_data[UF_PATH].off;
		pathlen = urllen - pu.field_data[UF_PATH].off;
	}

	msg = rspamd_http_new_message (HTTP_REQUEST);
	host = url + pu.field_data[UF_HOST].off;
	msg->flags = flags;

	if ((pu.field_set & (1 << UF_PORT)) != 0) {
		msg->port = pu.port;
	}
	else {
		/* XXX: magic constant */
		if (flags & RSPAMD_HTTP_FLAG_SSL) {
			msg->port = 443;
		}
		else {
			msg->port = 80;
		}
	}

	msg->host = g_string_new_len (host, pu.field_data[UF_HOST].len);
	msg->url = rspamd_fstring_append (msg->url, path, pathlen);

	REF_INIT_RETAIN (msg, rspamd_http_message_free);

	return msg;
}

const gchar *
rspamd_http_message_get_body (struct rspamd_http_message *msg,
							  gsize *blen)
{
	const gchar *ret = NULL;

	if (msg->body_buf.len > 0) {
		ret = msg->body_buf.begin;
	}

	if (blen) {
		*blen = msg->body_buf.len;
	}

	return ret;
}

static void
rspamd_http_shname_dtor (void *p)
{
	struct rspamd_storage_shmem *n = p;

#ifdef HAVE_SANE_SHMEM
	shm_unlink (n->shm_name);
#else
	unlink (n->shm_name);
#endif
	g_free (n->shm_name);
	g_free (n);
}

struct rspamd_storage_shmem *
rspamd_http_message_shmem_ref (struct rspamd_http_message *msg)
{
	if ((msg->flags & RSPAMD_HTTP_FLAG_SHMEM) && msg->body_buf.c.shared.name) {
		REF_RETAIN (msg->body_buf.c.shared.name);
		return msg->body_buf.c.shared.name;
	}

	return NULL;
}

guint
rspamd_http_message_get_flags (struct rspamd_http_message *msg)
{
	return msg->flags;
}

void
rspamd_http_message_shmem_unref (struct rspamd_storage_shmem *p)
{
	REF_RELEASE (p);
}

gboolean
rspamd_http_message_set_body (struct rspamd_http_message *msg,
							  const gchar *data, gsize len)
{
	union _rspamd_storage_u *storage;
	storage = &msg->body_buf.c;

	rspamd_http_message_storage_cleanup (msg);

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		storage->shared.name = g_malloc (sizeof (*storage->shared.name));
		REF_INIT_RETAIN (storage->shared.name, rspamd_http_shname_dtor);
#ifdef HAVE_SANE_SHMEM
		#if defined(__DragonFly__)
		// DragonFly uses regular files for shm. User rspamd is not allowed to create
		// files in the root.
		storage->shared.name->shm_name = g_strdup ("/tmp/rhm.XXXXXXXXXXXXXXXXXXXX");
#else
		storage->shared.name->shm_name = g_strdup ("/rhm.XXXXXXXXXXXXXXXXXXXX");
#endif
		storage->shared.shm_fd = rspamd_shmem_mkstemp (storage->shared.name->shm_name);
#else
		/* XXX: assume that tempdir is /tmp */
		storage->shared.name->shm_name = g_strdup ("/tmp/rhm.XXXXXXXXXXXXXXXXXXXX");
		storage->shared.shm_fd = mkstemp (storage->shared.name->shm_name);
#endif

		if (storage->shared.shm_fd == -1) {
			return FALSE;
		}

		if (len != 0 && len != G_MAXSIZE) {
			if (ftruncate (storage->shared.shm_fd, len) == -1) {
				return FALSE;
			}

			msg->body_buf.str = mmap (NULL, len,
					PROT_WRITE|PROT_READ, MAP_SHARED,
					storage->shared.shm_fd, 0);

			if (msg->body_buf.str == MAP_FAILED) {
				return FALSE;
			}

			msg->body_buf.begin = msg->body_buf.str;
			msg->body_buf.allocated_len = len;

			if (data != NULL) {
				memcpy (msg->body_buf.str, data, len);
				msg->body_buf.len = len;
			}
		}
		else {
			msg->body_buf.len = 0;
			msg->body_buf.begin = NULL;
			msg->body_buf.str = NULL;
			msg->body_buf.allocated_len = 0;
		}
	}
	else {
		if (len != 0 && len != G_MAXSIZE) {
			if (data == NULL) {
				storage->normal = rspamd_fstring_sized_new (len);
				msg->body_buf.len = 0;
			}
			else {
				storage->normal = rspamd_fstring_new_init (data, len);
				msg->body_buf.len = len;
			}
		}
		else {
			storage->normal = rspamd_fstring_new ();
		}

		msg->body_buf.begin = storage->normal->str;
		msg->body_buf.str = storage->normal->str;
		msg->body_buf.allocated_len = storage->normal->allocated;
	}

	msg->flags |= RSPAMD_HTTP_FLAG_HAS_BODY;

	return TRUE;
}

void
rspamd_http_message_set_method (struct rspamd_http_message *msg,
								const gchar *method)
{
	gint i;

	/* Linear search: not very efficient method */
	for (i = 0; i < HTTP_METHOD_MAX; i ++) {
		if (g_ascii_strcasecmp (method, http_method_str (i)) == 0) {
			msg->method = i;
		}
	}
}

gboolean
rspamd_http_message_set_body_from_fd (struct rspamd_http_message *msg,
									  gint fd)
{
	union _rspamd_storage_u *storage;
	struct stat st;

	rspamd_http_message_storage_cleanup (msg);

	storage = &msg->body_buf.c;
	msg->flags |= RSPAMD_HTTP_FLAG_SHMEM|RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE;

	storage->shared.shm_fd = dup (fd);
	msg->body_buf.str = MAP_FAILED;

	if (storage->shared.shm_fd == -1) {
		return FALSE;
	}

	if (fstat (storage->shared.shm_fd, &st) == -1) {
		return FALSE;
	}

	msg->body_buf.str = mmap (NULL, st.st_size,
			PROT_READ, MAP_SHARED,
			storage->shared.shm_fd, 0);

	if (msg->body_buf.str == MAP_FAILED) {
		return FALSE;
	}

	msg->body_buf.begin = msg->body_buf.str;
	msg->body_buf.len = st.st_size;
	msg->body_buf.allocated_len = st.st_size;

	return TRUE;
}

gboolean
rspamd_http_message_set_body_from_fstring_steal (struct rspamd_http_message *msg,
												 rspamd_fstring_t *fstr)
{
	union _rspamd_storage_u *storage;

	rspamd_http_message_storage_cleanup (msg);

	storage = &msg->body_buf.c;
	msg->flags &= ~(RSPAMD_HTTP_FLAG_SHMEM|RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE);

	storage->normal = fstr;
	msg->body_buf.str = fstr->str;
	msg->body_buf.begin = msg->body_buf.str;
	msg->body_buf.len = fstr->len;
	msg->body_buf.allocated_len = fstr->allocated;

	return TRUE;
}

gboolean
rspamd_http_message_set_body_from_fstring_copy (struct rspamd_http_message *msg,
												const rspamd_fstring_t *fstr)
{
	union _rspamd_storage_u *storage;

	rspamd_http_message_storage_cleanup (msg);

	storage = &msg->body_buf.c;
	msg->flags &= ~(RSPAMD_HTTP_FLAG_SHMEM|RSPAMD_HTTP_FLAG_SHMEM_IMMUTABLE);

	storage->normal = rspamd_fstring_new_init (fstr->str, fstr->len);
	msg->body_buf.str = storage->normal->str;
	msg->body_buf.begin = msg->body_buf.str;
	msg->body_buf.len = storage->normal->len;
	msg->body_buf.allocated_len = storage->normal->allocated;

	return TRUE;
}


gboolean
rspamd_http_message_grow_body (struct rspamd_http_message *msg, gsize len)
{
	struct stat st;
	union _rspamd_storage_u *storage;
	gsize newlen;

	storage = &msg->body_buf.c;

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		if (storage->shared.shm_fd == -1) {
			return FALSE;
		}

		if (fstat (storage->shared.shm_fd, &st) == -1) {
			return FALSE;
		}

		/* Check if we need to grow */
		if ((gsize)st.st_size < msg->body_buf.len + len) {
			/* Need to grow */
			newlen = rspamd_fstring_suggest_size (msg->body_buf.len, st.st_size,
					len);
			/* Unmap as we need another size of segment */
			if (msg->body_buf.str != MAP_FAILED) {
				munmap (msg->body_buf.str, st.st_size);
			}

			if (ftruncate (storage->shared.shm_fd, newlen) == -1) {
				return FALSE;
			}

			msg->body_buf.str = mmap (NULL, newlen,
					PROT_WRITE|PROT_READ, MAP_SHARED,
					storage->shared.shm_fd, 0);
			if (msg->body_buf.str == MAP_FAILED) {
				return FALSE;
			}

			msg->body_buf.begin = msg->body_buf.str;
			msg->body_buf.allocated_len = newlen;
		}
	}
	else {
		storage->normal = rspamd_fstring_grow (storage->normal, len);

		/* Append might cause realloc */
		msg->body_buf.begin = storage->normal->str;
		msg->body_buf.len = storage->normal->len;
		msg->body_buf.str = storage->normal->str;
		msg->body_buf.allocated_len = storage->normal->allocated;
	}

	return TRUE;
}

gboolean
rspamd_http_message_append_body (struct rspamd_http_message *msg,
								 const gchar *data, gsize len)
{
	union _rspamd_storage_u *storage;

	storage = &msg->body_buf.c;

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		if (!rspamd_http_message_grow_body (msg, len)) {
			return FALSE;
		}

		memcpy (msg->body_buf.str + msg->body_buf.len, data, len);
		msg->body_buf.len += len;
	}
	else {
		storage->normal = rspamd_fstring_append (storage->normal, data, len);

		/* Append might cause realloc */
		msg->body_buf.begin = storage->normal->str;
		msg->body_buf.len = storage->normal->len;
		msg->body_buf.str = storage->normal->str;
		msg->body_buf.allocated_len = storage->normal->allocated;
	}

	return TRUE;
}

void
rspamd_http_message_storage_cleanup (struct rspamd_http_message *msg)
{
	union _rspamd_storage_u *storage;
	struct stat st;

	if (msg->flags & RSPAMD_HTTP_FLAG_SHMEM) {
		storage = &msg->body_buf.c;

		if (storage->shared.shm_fd > 0) {
			g_assert (fstat (storage->shared.shm_fd, &st) != -1);

			if (msg->body_buf.str != MAP_FAILED) {
				munmap (msg->body_buf.str, st.st_size);
			}

			close (storage->shared.shm_fd);
		}

		if (storage->shared.name != NULL) {
			REF_RELEASE (storage->shared.name);
		}

		storage->shared.shm_fd = -1;
		msg->body_buf.str = MAP_FAILED;
	}
	else {
		if (msg->body_buf.c.normal) {
			rspamd_fstring_free (msg->body_buf.c.normal);
		}

		msg->body_buf.c.normal = NULL;
	}

	msg->body_buf.len = 0;
}

void
rspamd_http_message_free (struct rspamd_http_message *msg)
{
	struct rspamd_http_header *hdr, *hcur, *hcurtmp;

	kh_foreach_value (msg->headers, hdr, {
		DL_FOREACH_SAFE (hdr, hcur, hcurtmp) {
			rspamd_fstring_free (hcur->combined);
			g_free (hcur);
		}
	});

	kh_destroy (rspamd_http_headers_hash, msg->headers);
	rspamd_http_message_storage_cleanup (msg);

	if (msg->url != NULL) {
		rspamd_fstring_free (msg->url);
	}
	if (msg->status != NULL) {
		rspamd_fstring_free (msg->status);
	}
	if (msg->host != NULL) {
		g_string_free (msg->host, TRUE);
	}
	if (msg->peer_key != NULL) {
		rspamd_pubkey_unref (msg->peer_key);
	}

	g_free (msg);
}

void
rspamd_http_message_set_peer_key (struct rspamd_http_message *msg,
								  struct rspamd_cryptobox_pubkey *pk)
{
	if (msg->peer_key != NULL) {
		rspamd_pubkey_unref (msg->peer_key);
	}

	if (pk) {
		msg->peer_key = rspamd_pubkey_ref (pk);
	}
	else {
		msg->peer_key = NULL;
	}
}

void
rspamd_http_message_add_header_len (struct rspamd_http_message *msg,
									const gchar *name,
									const gchar *value,
									gsize len)
{
	struct rspamd_http_header *hdr, *found;
	guint nlen, vlen;
	khiter_t k;
	gint r;

	if (msg != NULL && name != NULL && value != NULL) {
		hdr = g_malloc0 (sizeof (struct rspamd_http_header));
		nlen = strlen (name);
		vlen = len;

		if (g_ascii_strcasecmp (name, "host") == 0) {
			msg->flags |= RSPAMD_HTTP_FLAG_HAS_HOST_HEADER;
		}

		hdr->combined = rspamd_fstring_sized_new (nlen + vlen + 4);
		rspamd_printf_fstring (&hdr->combined, "%s: %*s\r\n", name, (gint)vlen,
				value);
		hdr->name.begin = hdr->combined->str;
		hdr->name.len = nlen;
		hdr->value.begin = hdr->combined->str + nlen + 2;
		hdr->value.len = vlen;

		k = kh_put (rspamd_http_headers_hash, msg->headers, &hdr->name,
				&r);

		if (r != 0) {
			kh_value (msg->headers, k) = hdr;
			found = NULL;
		}
		else {
			found = kh_value (msg->headers, k);
		}

		DL_APPEND (found, hdr);
	}
}

void
rspamd_http_message_add_header (struct rspamd_http_message *msg,
								const gchar *name,
								const gchar *value)
{
	if (value) {
		rspamd_http_message_add_header_len (msg, name, value, strlen (value));
	}
}

void
rspamd_http_message_add_header_fstr (struct rspamd_http_message *msg,
									 const gchar *name,
									 rspamd_fstring_t *value)
{
	struct rspamd_http_header *hdr, *found = NULL;
	guint nlen, vlen;
	khiter_t k;
	gint r;

	if (msg != NULL && name != NULL && value != NULL) {
		hdr = g_malloc0 (sizeof (struct rspamd_http_header));
		nlen = strlen (name);
		vlen = value->len;
		hdr->combined = rspamd_fstring_sized_new (nlen + vlen + 4);
		rspamd_printf_fstring (&hdr->combined, "%s: %V\r\n", name, value);
		hdr->name.begin = hdr->combined->str;
		hdr->name.len = nlen;
		hdr->value.begin = hdr->combined->str + nlen + 2;
		hdr->value.len = vlen;

		k = kh_put (rspamd_http_headers_hash, msg->headers, &hdr->name,
				&r);

		if (r != 0) {
			kh_value (msg->headers, k) = hdr;
			found = NULL;
		}
		else {
			found = kh_value (msg->headers, k);
		}

		DL_APPEND (found, hdr);
	}
}

const rspamd_ftok_t *
rspamd_http_message_find_header (struct rspamd_http_message *msg,
								 const gchar *name)
{
	const rspamd_ftok_t *res = NULL;
	rspamd_ftok_t srch;
	guint slen = strlen (name);
	khiter_t k;

	if (msg != NULL) {
		srch.begin = name;
		srch.len = slen;

		k = kh_get (rspamd_http_headers_hash, msg->headers, &srch);

		if (k != kh_end (msg->headers)) {
			res = &(kh_value (msg->headers, k)->value);
		}
	}

	return res;
}

GPtrArray*
rspamd_http_message_find_header_multiple (
		struct rspamd_http_message *msg,
		const gchar *name)
{
	GPtrArray *res = NULL;
	struct rspamd_http_header *hdr, *cur;
	rspamd_ftok_t srch;
	khiter_t k;
	guint cnt = 0;

	guint slen = strlen (name);

	if (msg != NULL) {
		srch.begin = name;
		srch.len = slen;

		k = kh_get (rspamd_http_headers_hash, msg->headers, &srch);

		if (k != kh_end (msg->headers)) {
			hdr = kh_value (msg->headers, k);

			LL_COUNT (hdr, cur, cnt);
			res = g_ptr_array_sized_new (cnt);

			LL_FOREACH (hdr, cur) {
				g_ptr_array_add (res, &cur->value);
			}
		}
	}


	return res;
}


gboolean
rspamd_http_message_remove_header (struct rspamd_http_message *msg,
								   const gchar *name)
{
	struct rspamd_http_header *hdr, *hcur, *hcurtmp;
	gboolean res = FALSE;
	guint slen = strlen (name);
	rspamd_ftok_t srch;
	khiter_t k;

	if (msg != NULL) {
		srch.begin = name;
		srch.len = slen;

		k = kh_get (rspamd_http_headers_hash, msg->headers, &srch);

		if (k != kh_end (msg->headers)) {
			hdr = kh_value (msg->headers, k);
			kh_del (rspamd_http_headers_hash, msg->headers, k);
			res = TRUE;

			DL_FOREACH_SAFE (hdr, hcur, hcurtmp) {
				rspamd_fstring_free (hcur->combined);
				g_free (hcur);
			}
		}
	}

	return res;
}