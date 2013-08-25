/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "rcl.h"
#include "rcl_internal.h"
#include "util.h"

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#endif

/**
 * @file rcl_util.c
 * Utilities for rcl parsing
 */


static void
rspamd_cl_obj_free_internal (rspamd_cl_object_t *obj, gboolean allow_rec)
{
	rspamd_cl_object_t *sub, *tmp;

	while (obj != NULL) {
		if (obj->key != NULL) {
			g_free (obj->key);
		}

		if (obj->type == RSPAMD_CL_STRING) {
			g_free (obj->value.sv);
		}
		else if (obj->type == RSPAMD_CL_ARRAY) {
			sub = obj->value.ov;
			while (sub != NULL) {
				tmp = sub->next;
				rspamd_cl_obj_free_internal (sub, FALSE);
				sub = tmp;
			}
		}
		else if (obj->type == RSPAMD_CL_OBJECT) {
			HASH_ITER (hh, obj->value.ov, sub, tmp) {
				HASH_DELETE (hh, obj->value.ov, sub);
				rspamd_cl_obj_free_internal (sub, TRUE);
			}
		}
		tmp = obj->next;
		g_slice_free1 (sizeof (rspamd_cl_object_t), obj);
		obj = tmp;

		if (!allow_rec) {
			break;
		}
	}
}

void
rspamd_cl_obj_free (rspamd_cl_object_t *obj)
{
	rspamd_cl_obj_free_internal (obj, TRUE);
}

void
rspamd_cl_unescape_json_string (gchar *str)
{
	gchar *t = str, *h = str;
	gint i, uval;

	/* t is target (tortoise), h is source (hare) */

	while (*h != '\0') {
		if (*h == '\\') {
			h ++;
			switch (*h) {
			case 'n':
				*t++ = '\n';
				break;
			case 'r':
				*t++ = '\r';
				break;
			case 'b':
				*t++ = '\b';
				break;
			case 't':
				*t++ = '\t';
				break;
			case 'f':
				*t++ = '\f';
				break;
			case '\\':
				*t++ = '\\';
				break;
			case '"':
				*t++ = '"';
				break;
			case 'u':
				/* Unicode escape */
				uval = 0;
				for (i = 0; i < 4; i++) {
					uval <<= 4;
					if (g_ascii_isdigit (h[i])) {
						uval += h[i] - '0';
					}
					else if (h[i] >= 'a' && h[i] <= 'f') {
						uval += h[i] - 'a' + 10;
					}
					else if (h[i] >= 'A' && h[i] <= 'F') {
						uval += h[i] - 'A' + 10;
					}
				}
				h += 3;
				/* Encode */
				if(uval < 0x80) {
					t[0] = (char)uval;
					t ++;
				}
				else if(uval < 0x800) {
					t[0] = 0xC0 + ((uval & 0x7C0) >> 6);
					t[1] = 0x80 + ((uval & 0x03F));
					t += 2;
				}
				else if(uval < 0x10000) {
					t[0] = 0xE0 + ((uval & 0xF000) >> 12);
					t[1] = 0x80 + ((uval & 0x0FC0) >> 6);
					t[2] = 0x80 + ((uval & 0x003F));
					t += 3;
				}
				else if(uval <= 0x10FFFF) {
					t[0] = 0xF0 + ((uval & 0x1C0000) >> 18);
					t[1] = 0x80 + ((uval & 0x03F000) >> 12);
					t[2] = 0x80 + ((uval & 0x000FC0) >> 6);
					t[3] = 0x80 + ((uval & 0x00003F));
					t += 4;
				}
				else {
					*t++ = '?';
				}
				break;
			default:
				*t++ = '?';
				break;
			}
			h ++;
		}
		else {
			*t++ = *h++;
		}
	}
}

rspamd_cl_object_t*
rspamd_cl_parser_get_object (struct rspamd_cl_parser *parser, GError **err)
{
	if (parser->state != RSPAMD_RCL_STATE_INIT && parser->state != RSPAMD_RCL_STATE_ERROR) {
		return rspamd_cl_obj_ref (parser->top_obj);
	}

	return NULL;
}

void
rspamd_cl_parser_free (struct rspamd_cl_parser *parser)
{
	struct rspamd_cl_stack *stack, *stmp;
	struct rspamd_cl_macro *macro, *mtmp;
	struct rspamd_cl_chunk *chunk, *ctmp;
	struct rspamd_cl_pubkey *key, *ktmp;

	if (parser->top_obj != NULL) {
		rspamd_cl_obj_unref (parser->top_obj);
	}

	LL_FOREACH_SAFE (parser->stack, stack, stmp) {
		g_slice_free1 (sizeof (struct rspamd_cl_stack), stack);
	}
	HASH_ITER (hh, parser->macroes, macro, mtmp) {
		g_slice_free1 (sizeof (struct rspamd_cl_macro), macro);
	}
	LL_FOREACH_SAFE (parser->chunks, chunk, ctmp) {
		g_slice_free1 (sizeof (struct rspamd_cl_chunk), chunk);
	}
	LL_FOREACH_SAFE (parser->keys, key, ktmp) {
		g_slice_free1 (sizeof (struct rspamd_cl_pubkey), key);
	}

	g_slice_free1 (sizeof (struct rspamd_cl_parser), parser);
}

gboolean
rspamd_cl_pubkey_add (struct rspamd_cl_parser *parser, const guchar *key, gsize len, GError **err)
{
	struct rspamd_cl_pubkey *nkey;
#ifndef HAVE_OPENSSL
	g_set_error (err, RCL_ERROR, RSPAMD_CL_EINTERNAL, "cannot check signatures without openssl");
	return FALSE;
#else
	BIO *mem;

	mem = BIO_new_mem_buf ((void *)key, len);
	nkey = g_slice_alloc0 (sizeof (struct rspamd_cl_pubkey));
	nkey->key = PEM_read_bio_PUBKEY (mem, &nkey->key, NULL, NULL);
	BIO_free (mem);
	if (nkey->key == NULL) {
		g_slice_free1 (sizeof (struct rspamd_cl_pubkey), nkey);
		g_set_error (err, RCL_ERROR, RSPAMD_CL_ESSL, "%s",
				ERR_error_string (ERR_get_error (), NULL));
		return FALSE;
	}
	LL_PREPEND (parser->keys, nkey);
#endif
	return TRUE;
}

#ifdef CURL_FOUND
struct rspamd_cl_curl_cbdata {
	guchar *buf;
	gsize buflen;
};

static gsize
rspamd_cl_curl_write_callback (gpointer contents, gsize size, gsize nmemb, gpointer ud)
{
	struct rspamd_cl_curl_cbdata *cbdata = ud;
	gsize realsize = size * nmemb;

	cbdata->buf = g_realloc (cbdata->buf, cbdata->buflen + realsize + 1);
	if (cbdata->buf == NULL) {
		return 0;
	}

	memcpy (&(cbdata->buf[cbdata->buflen]), contents, realsize);
	cbdata->buflen += realsize;
	cbdata->buf[cbdata->buflen] = 0;

	return realsize;
}
#endif

/**
 * Fetch a url and save results to the memory buffer
 * @param url url to fetch
 * @param len length of url
 * @param buf target buffer
 * @param buflen target length
 * @return
 */
static gboolean
rspamd_cl_fetch_url (const guchar *url, guchar **buf, gsize *buflen, GError **err)
{

#ifdef HAVE_FETCH_H
	struct url *fetch_url;
	struct url_stat us;
	FILE *in;
	guchar *buf;

	fetch_url = fetchParseURL (url);
	if (fetch_url == NULL) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "invalid URL %s: %s",
				url, strerror (errno));
		return FALSE;
	}
	if ((in = fetchXGet (fetch_url, &us, "")) == NULL) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot fetch URL %s: %s",
				url, strerror (errno));
		fetchFreeURL (fetch_url);
		return FALSE;
	}

	*buflen = us.size;
	*buf = g_malloc (*buflen);
	if (buf == NULL) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot allocate buffer for URL %s: %s",
				url, strerror (errno));
		fclose (in);
		fetchFreeURL (fetch_url);
		return FALSE;
	}

	if (fread (*buf, *buflen, 1, in) != 1) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot read URL %s: %s",
				url, strerror (errno));
		fclose (in);
		fetchFreeURL (fetch_url);
		return FALSE;
	}

	fetchFreeURL (fetch_url);
	return TRUE;
#elif defined(CURL_FOUND)
	CURL *curl;
	gint r;
	struct rspamd_cl_curl_cbdata cbdata;

	curl = curl_easy_init ();
	if (curl == NULL) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EINTERNAL, "CURL interface is broken");
		return FALSE;
	}
	if ((r = curl_easy_setopt (curl, CURLOPT_URL, url)) != CURLE_OK) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "invalid URL %s: %s",
				url, curl_easy_strerror (r));
		curl_easy_cleanup (curl);
		return FALSE;
	}
	curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, rspamd_cl_curl_write_callback);
	cbdata.buf = *buf;
	cbdata.buflen = *buflen;
	curl_easy_setopt (curl, CURLOPT_WRITEDATA, &cbdata);

	if ((r = curl_easy_perform (curl)) != CURLE_OK) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "error fetching URL %s: %s",
				url, curl_easy_strerror (r));
		curl_easy_cleanup (curl);
		if (buf != NULL) {
			g_free (buf);
		}
		return FALSE;
	}
	*buf = cbdata.buf;
	*buflen = cbdata.buflen;

	return TRUE;
#else
	g_set_error (err, RCL_ERROR, RSPAMD_CL_EINTERNAL, "URL support is disabled");
	return FALSE;
#endif
}

/**
 * Fetch a file and save results to the memory buffer
 * @param filename filename to fetch
 * @param len length of filename
 * @param buf target buffer
 * @param buflen target length
 * @return
 */
static gboolean
rspamd_cl_fetch_file (const guchar *filename, guchar **buf, gsize *buflen, GError **err)
{
	gint fd;
	struct stat st;

	if (stat (filename, &st) == -1) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot stat file %s: %s",
				filename, strerror (errno));
		return FALSE;
	}
	if ((fd = open (filename, O_RDONLY)) == -1) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot open file %s: %s",
				filename, strerror (errno));
		return FALSE;
	}
	if ((*buf = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		close (fd);
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot mmap file %s: %s",
				filename, strerror (errno));
		return FALSE;
	}
	*buflen = st.st_size;
	close (fd);

	return TRUE;
}


#ifdef HAVE_OPENSSL
static inline gboolean
rspamd_cl_sig_check (const guchar *data, gsize datalen,
		const guchar *sig, gsize siglen, struct rspamd_cl_parser *parser)
{
	struct rspamd_cl_pubkey *key;
	gchar dig[EVP_MAX_MD_SIZE];
	guint diglen;
	EVP_PKEY_CTX *key_ctx;
	EVP_MD_CTX *sign_ctx = NULL;

	sign_ctx = EVP_MD_CTX_create ();

	LL_FOREACH (parser->keys, key) {
		key_ctx = EVP_PKEY_CTX_new (key->key, NULL);
		if (key_ctx != NULL) {
			if (EVP_PKEY_verify_init (key_ctx) <= 0) {
				EVP_PKEY_CTX_free (key_ctx);
				continue;
			}
			if (EVP_PKEY_CTX_set_rsa_padding (key_ctx, RSA_PKCS1_PADDING) <= 0) {
				EVP_PKEY_CTX_free (key_ctx);
				continue;
			}
			if (EVP_PKEY_CTX_set_signature_md (key_ctx, EVP_sha256 ()) <= 0) {
				EVP_PKEY_CTX_free (key_ctx);
				continue;
			}
			EVP_DigestInit (sign_ctx, EVP_sha256 ());
			EVP_DigestUpdate (sign_ctx, data, datalen);
			EVP_DigestFinal (sign_ctx, dig, &diglen);

			if (EVP_PKEY_verify (key_ctx, sig, siglen, dig, diglen) == 1) {
				EVP_MD_CTX_destroy (sign_ctx);
				EVP_PKEY_CTX_free (key_ctx);
				return TRUE;
			}

			EVP_PKEY_CTX_free (key_ctx);
		}
	}

	EVP_MD_CTX_destroy (sign_ctx);

	return FALSE;
}
#endif

/**
 * Include an url to configuration
 * @param data
 * @param len
 * @param parser
 * @param err
 * @return
 */
static gboolean
rspamd_cl_include_url (const guchar *data, gsize len,
		struct rspamd_cl_parser *parser, gboolean check_signature, GError **err)
{

	gboolean res;
	guchar *buf = NULL, *sigbuf = NULL;
	gsize buflen = 0, siglen = 0;
	struct rspamd_cl_chunk *chunk;
	gchar urlbuf[PATH_MAX];

	rspamd_snprintf (urlbuf, sizeof (urlbuf), "%*s", len, data);

	if (!rspamd_cl_fetch_url (urlbuf, &buf, &buflen, err)) {
		return FALSE;
	}

	if (check_signature) {
#ifdef HAVE_OPENSSL
		/* We need to check signature first */
		rspamd_snprintf (urlbuf, sizeof (urlbuf), "%*s.sig", len, data);
		if (!rspamd_cl_fetch_file (urlbuf, &sigbuf, &siglen, err)) {
			return FALSE;
		}
		if (!rspamd_cl_sig_check (buf, buflen, sigbuf, siglen, parser)) {
			g_set_error (err, RCL_ERROR, RSPAMD_CL_ESSL, "cannot verify url %s: %s",
							urlbuf,
							ERR_error_string (ERR_get_error (), NULL));
			munmap (sigbuf, siglen);
			return FALSE;
		}
		munmap (sigbuf, siglen);
#endif
	}

	res = rspamd_cl_parser_add_chunk (parser, buf, buflen, err);
	if (res == TRUE) {
		/* Remove chunk from the stack */
		chunk = parser->chunks;
		if (chunk != NULL) {
			parser->chunks = chunk->next;
			g_slice_free1 (sizeof (struct rspamd_cl_chunk), chunk);
		}
	}
	g_free (buf);

	return res;
}

/**
 * Include a file to configuration
 * @param data
 * @param len
 * @param parser
 * @param err
 * @return
 */
static gboolean
rspamd_cl_include_file (const guchar *data, gsize len,
		struct rspamd_cl_parser *parser, gboolean check_signature, GError **err)
{
	gboolean res;
	struct rspamd_cl_chunk *chunk;
	guchar *buf = NULL, *sigbuf = NULL;
	gsize buflen, siglen;
	gchar filebuf[PATH_MAX], realbuf[PATH_MAX];

	rspamd_snprintf (filebuf, sizeof (filebuf), "%*s", len, data);
	if (realpath (filebuf, realbuf) == NULL) {
		g_set_error (err, RCL_ERROR, RSPAMD_CL_EIO, "cannot open file %s: %s",
									filebuf,
									strerror (errno));
		return FALSE;
	}

	if (!rspamd_cl_fetch_file (realbuf, &buf, &buflen, err)) {
		return FALSE;
	}

	if (check_signature) {
#ifdef HAVE_OPENSSL
		/* We need to check signature first */
		rspamd_snprintf (filebuf, sizeof (filebuf), "%s.sig", realbuf);
		if (!rspamd_cl_fetch_file (filebuf, &sigbuf, &siglen, err)) {
			return FALSE;
		}
		if (!rspamd_cl_sig_check (buf, buflen, sigbuf, siglen, parser)) {
			g_set_error (err, RCL_ERROR, RSPAMD_CL_ESSL, "cannot verify file %s: %s",
							filebuf,
							ERR_error_string (ERR_get_error (), NULL));
			munmap (sigbuf, siglen);
			return FALSE;
		}
		munmap (sigbuf, siglen);
#endif
	}

	res = rspamd_cl_parser_add_chunk (parser, buf, buflen, err);
	if (res == TRUE) {
		/* Remove chunk from the stack */
		chunk = parser->chunks;
		if (chunk != NULL) {
			parser->chunks = chunk->next;
			g_slice_free1 (sizeof (struct rspamd_cl_chunk), chunk);
		}
	}
	munmap (buf, buflen);

	return res;
}

/**
 * Handle include macro
 * @param data include data
 * @param len length of data
 * @param ud user data
 * @param err error ptr
 * @return
 */
gboolean
rspamd_cl_include_handler (const guchar *data, gsize len, gpointer ud, GError **err)
{
	struct rspamd_cl_parser *parser = ud;

	if (*data == '/' || *data == '.') {
		/* Try to load a file */
		return rspamd_cl_include_file (data, len, parser, FALSE, err);
	}

	return rspamd_cl_include_url (data, len, parser, FALSE, err);
}

/**
 * Handle includes macro
 * @param data include data
 * @param len length of data
 * @param ud user data
 * @param err error ptr
 * @return
 */
gboolean
rspamd_cl_includes_handler (const guchar *data, gsize len, gpointer ud, GError **err)
{
	struct rspamd_cl_parser *parser = ud;

	if (*data == '/' || *data == '.') {
		/* Try to load a file */
		return rspamd_cl_include_file (data, len, parser, TRUE, err);
	}

	return rspamd_cl_include_url (data, len, parser, TRUE, err);
}

gboolean
rspamd_cl_parser_add_file (struct rspamd_cl_parser *parser, const gchar *filename,
		GError **err)
{
	guchar *buf;
	gsize len;
	gboolean ret;

	if (!rspamd_cl_fetch_file (filename, &buf, &len, err)) {
		return FALSE;
	}

	ret = rspamd_cl_parser_add_chunk (parser, buf, len, err);

	munmap (buf, len);

	return ret;
}
