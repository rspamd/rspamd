/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "config.h"
#include "images.h"
#include "task.h"
#include "message.h"
#include "libserver/html/html.h"

#define msg_debug_images(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_images_log_id, "images", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(images)

#ifdef USABLE_GD
#include "gd.h"
#include "hash.h"
#include <math.h>

#define RSPAMD_NORMALIZED_DIM 64

static rspamd_lru_hash_t *images_hash = NULL;
#endif

static const guint8 png_signature[] = {137, 80, 78, 71, 13, 10, 26, 10};
static const guint8 jpg_sig1[] = {0xff, 0xd8};
static const guint8 jpg_sig_jfif[] = {0xff, 0xe0};
static const guint8 jpg_sig_exif[] = {0xff, 0xe1};
static const guint8 gif_signature[] = {'G', 'I', 'F', '8'};
static const guint8 bmp_signature[] = {'B', 'M'};

static bool process_image (struct rspamd_task *task, struct rspamd_mime_part *part);


bool
rspamd_images_process_mime_part_maybe (struct rspamd_task *task,
											struct rspamd_mime_part *part)
{
	if (part->part_type == RSPAMD_MIME_PART_UNDEFINED) {
		if (part->detected_type &&
			strcmp (part->detected_type, "image") == 0 &&
			part->parsed_data.len > 0) {

			return process_image (task, part);
		}
	}

	return false;
}

void
rspamd_images_process (struct rspamd_task *task)
{
	guint i;
	struct rspamd_mime_part *part;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		rspamd_images_process_mime_part_maybe (task, part);
	}

}

static enum rspamd_image_type
detect_image_type (rspamd_ftok_t *data)
{
	if (data->len > sizeof (png_signature) / sizeof (png_signature[0])) {
		if (memcmp (data->begin, png_signature, sizeof (png_signature)) == 0) {
			return IMAGE_TYPE_PNG;
		}
	}
	if (data->len > 10) {
		if (memcmp (data->begin, jpg_sig1, sizeof (jpg_sig1)) == 0) {
			if (memcmp (data->begin + 2, jpg_sig_jfif, sizeof (jpg_sig_jfif)) == 0 ||
					memcmp (data->begin + 2, jpg_sig_exif, sizeof (jpg_sig_exif)) == 0) {
				return IMAGE_TYPE_JPG;
			}
		}
	}
	if (data->len > sizeof (gif_signature) / sizeof (gif_signature[0])) {
		if (memcmp (data->begin, gif_signature, sizeof (gif_signature)) == 0) {
			return IMAGE_TYPE_GIF;
		}
	}
	if (data->len > sizeof (bmp_signature) / sizeof (bmp_signature[0])) {
		if (memcmp (data->begin, bmp_signature, sizeof (bmp_signature)) == 0) {
			return IMAGE_TYPE_BMP;
		}
	}

	return IMAGE_TYPE_UNKNOWN;
}


static struct rspamd_image *
process_png_image (rspamd_mempool_t *pool, rspamd_ftok_t *data)
{
	struct rspamd_image *img;
	guint32 t;
	const guint8 *p;

	if (data->len < 24) {
		msg_info_pool ("bad png detected (maybe striped)");
		return NULL;
	}

	/* In png we should find iHDR section and get data from it */
	/* Skip signature and read header section */
	p = data->begin + 12;
	if (memcmp (p, "IHDR", 4) != 0) {
		msg_info_pool ("png doesn't begins with IHDR section");
		return NULL;
	}

	img = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_PNG;
	img->data = data;

	p += 4;
	memcpy (&t, p, sizeof (guint32));
	img->width = ntohl (t);
	p += 4;
	memcpy (&t, p, sizeof (guint32));
	img->height = ntohl (t);

	return img;
}

static struct rspamd_image *
process_jpg_image (rspamd_mempool_t *pool, rspamd_ftok_t *data)
{
	const guint8 *p, *end;
	guint16 h, w;
	struct rspamd_image *img;

	img = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_JPG;
	img->data = data;

	p = data->begin;
	end = p + data->len - 8;
	p += 2;

	while (p < end) {
		if (p[0] == 0xFF && p[1] != 0xFF) {
			guint len = p[2] * 256 + p[3];

			p ++;

			if (*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3 ||
					*p == 0xc9 || *p == 0xca || *p == 0xcb) {
				memcpy (&h, p + 4, sizeof (guint16));
				h = p[4] * 0xff + p[5];
				img->height = h;
				w = p[6] * 0xff + p[7];
				img->width = w;

				return img;
			}


			p += len;
		}
		else {
			p++;
		}
	}

	return NULL;
}

static struct rspamd_image *
process_gif_image (rspamd_mempool_t *pool, rspamd_ftok_t *data)
{
	struct rspamd_image *img;
	const guint8 *p;
	guint16 t;

	if (data->len < 10) {
		msg_info_pool ("bad gif detected (maybe striped)");
		return NULL;
	}

	img = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_GIF;
	img->data = data;

	p = data->begin + 6;
	memcpy (&t, p,	   sizeof (guint16));
	img->width = GUINT16_FROM_LE (t);
	memcpy (&t, p + 2, sizeof (guint16));
	img->height = GUINT16_FROM_LE (t);

	return img;
}

static struct rspamd_image *
process_bmp_image (rspamd_mempool_t *pool, rspamd_ftok_t *data)
{
	struct rspamd_image *img;
	gint32 t;
	const guint8 *p;

	if (data->len < 28) {
		msg_info_pool ("bad bmp detected (maybe striped)");
		return NULL;
	}

	img = rspamd_mempool_alloc0 (pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_BMP;
	img->data = data;
	p = data->begin + 18;
	memcpy (&t, p,	   sizeof (gint32));
	img->width = abs (GINT32_FROM_LE (t));
	memcpy (&t, p + 4, sizeof (gint32));
	img->height = abs (GINT32_FROM_LE (t));

	return img;
}

#ifdef USABLE_GD
/*
 * DCT from Emil Mikulic.
 * http://unix4lyfe.org/dct/
 */
static void
rspamd_image_dct_block (gint pixels[8][8], gdouble *out)
{
	gint i;
	gint rows[8][8];

	static const gint c1 = 1004 /* cos(pi/16) << 10 */,
			s1 = 200 /* sin(pi/16) */,
			c3 = 851 /* cos(3pi/16) << 10 */,
			s3 = 569 /* sin(3pi/16) << 10 */,
			r2c6 = 554 /* sqrt(2)*cos(6pi/16) << 10 */,
			r2s6 = 1337 /* sqrt(2)*sin(6pi/16) << 10 */,
			r2 = 181; /* sqrt(2) << 7*/

	gint x0, x1, x2, x3, x4, x5, x6, x7, x8;

	/* transform rows */
	for (i = 0; i < 8; i++) {
		x0 = pixels[0][i];
		x1 = pixels[1][i];
		x2 = pixels[2][i];
		x3 = pixels[3][i];
		x4 = pixels[4][i];
		x5 = pixels[5][i];
		x6 = pixels[6][i];
		x7 = pixels[7][i];

		/* Stage 1 */
		x8 = x7 + x0;
		x0 -= x7;
		x7 = x1 + x6;
		x1 -= x6;
		x6 = x2 + x5;
		x2 -= x5;
		x5 = x3 + x4;
		x3 -= x4;

		/* Stage 2 */
		x4 = x8 + x5;
		x8 -= x5;
		x5 = x7 + x6;
		x7 -= x6;
		x6 = c1 * (x1 + x2);
		x2 = (-s1 - c1) * x2 + x6;
		x1 = (s1 - c1) * x1 + x6;
		x6 = c3 * (x0 + x3);
		x3 = (-s3 - c3) * x3 + x6;
		x0 = (s3 - c3) * x0 + x6;

		/* Stage 3 */
		x6 = x4 + x5;
		x4 -= x5;
		x5 = r2c6 * (x7 + x8);
		x7 = (-r2s6 - r2c6) * x7 + x5;
		x8 = (r2s6 - r2c6) * x8 + x5;
		x5 = x0 + x2;
		x0 -= x2;
		x2 = x3 + x1;
		x3 -= x1;

		/* Stage 4 and output */
		rows[i][0] = x6;
		rows[i][4] = x4;
		rows[i][2] = x8 >> 10;
		rows[i][6] = x7 >> 10;
		rows[i][7] = (x2 - x5) >> 10;
		rows[i][1] = (x2 + x5) >> 10;
		rows[i][3] = (x3 * r2) >> 17;
		rows[i][5] = (x0 * r2) >> 17;
	}

	/* transform columns */
	for (i = 0; i < 8; i++) {
		x0 = rows[0][i];
		x1 = rows[1][i];
		x2 = rows[2][i];
		x3 = rows[3][i];
		x4 = rows[4][i];
		x5 = rows[5][i];
		x6 = rows[6][i];
		x7 = rows[7][i];

		/* Stage 1 */
		x8 = x7 + x0;
		x0 -= x7;
		x7 = x1 + x6;
		x1 -= x6;
		x6 = x2 + x5;
		x2 -= x5;
		x5 = x3 + x4;
		x3 -= x4;

		/* Stage 2 */
		x4 = x8 + x5;
		x8 -= x5;
		x5 = x7 + x6;
		x7 -= x6;
		x6 = c1 * (x1 + x2);
		x2 = (-s1 - c1) * x2 + x6;
		x1 = (s1 - c1) * x1 + x6;
		x6 = c3 * (x0 + x3);
		x3 = (-s3 - c3) * x3 + x6;
		x0 = (s3 - c3) * x0 + x6;

		/* Stage 3 */
		x6 = x4 + x5;
		x4 -= x5;
		x5 = r2c6 * (x7 + x8);
		x7 = (-r2s6 - r2c6) * x7 + x5;
		x8 = (r2s6 - r2c6) * x8 + x5;
		x5 = x0 + x2;
		x0 -= x2;
		x2 = x3 + x1;
		x3 -= x1;

		/* Stage 4 and output */
		out[i * 8] = (double) ((x6 + 16) >> 3);
		out[i * 8 + 1] = (double) ((x4 + 16) >> 3);
		out[i * 8 + 2] = (double) ((x8 + 16384) >> 13);
		out[i * 8 + 3] = (double) ((x7 + 16384) >> 13);
		out[i * 8 + 4] = (double) ((x2 - x5 + 16384) >> 13);
		out[i * 8 + 5] = (double) ((x2 + x5 + 16384) >> 13);
		out[i * 8 + 6] = (double) (((x3 >> 8) * r2 + 8192) >> 12);
		out[i * 8 + 7] = (double) (((x0 >> 8) * r2 + 8192) >> 12);
	}
}

struct rspamd_image_cache_entry {
	guchar digest[64];
	guchar dct[RSPAMD_DCT_LEN / NBBY];
};

static void
rspamd_image_cache_entry_dtor (gpointer p)
{
	struct rspamd_image_cache_entry *entry = p;
	g_free (entry);
}

static guint32
rspamd_image_dct_hash (gconstpointer p)
{
	return rspamd_cryptobox_fast_hash (p, rspamd_cryptobox_HASHBYTES,
			rspamd_hash_seed ());
}

static gboolean
rspamd_image_dct_equal (gconstpointer a, gconstpointer b)
{
	return memcmp (a, b, rspamd_cryptobox_HASHBYTES) == 0;
}

static void
rspamd_image_create_cache (struct rspamd_config *cfg)
{
	images_hash = rspamd_lru_hash_new_full (cfg->images_cache_size, NULL,
			rspamd_image_cache_entry_dtor,
			rspamd_image_dct_hash, rspamd_image_dct_equal);
}

static gboolean
rspamd_image_check_hash (struct rspamd_task *task, struct rspamd_image *img)
{
	struct rspamd_image_cache_entry *found;

	if (images_hash == NULL) {
		rspamd_image_create_cache (task->cfg);
	}

	found = rspamd_lru_hash_lookup (images_hash, img->parent->digest,
			task->tv.tv_sec);

	if (found) {
		/* We need to decompress */
		img->dct = g_malloc (RSPAMD_DCT_LEN / NBBY);
		rspamd_mempool_add_destructor (task->task_pool, g_free,
				img->dct);
		/* Copy as found could be destroyed by LRU */
		memcpy (img->dct, found->dct, RSPAMD_DCT_LEN / NBBY);
		img->is_normalized = TRUE;

		return TRUE;
	}

	return FALSE;
}

static void
rspamd_image_save_hash (struct rspamd_task *task, struct rspamd_image *img)
{
	struct rspamd_image_cache_entry *found;

	if (img->is_normalized) {
		found = rspamd_lru_hash_lookup (images_hash, img->parent->digest,
				task->tv.tv_sec);

		if (!found) {
			found = g_malloc0 (sizeof (*found));
			memcpy (found->dct, img->dct, RSPAMD_DCT_LEN / NBBY);
			memcpy (found->digest, img->parent->digest, sizeof (found->digest));

			rspamd_lru_hash_insert (images_hash, found->digest, found,
					task->tv.tv_sec, 0);
		}
	}
}

#endif

void
rspamd_image_normalize (struct rspamd_task *task, struct rspamd_image *img)
{
#ifdef USABLE_GD
	gdImagePtr src = NULL, dst = NULL;
	guint i, j, k, l;
	gdouble *dct;

	if (img->data->len == 0 || img->data->len > G_MAXINT32) {
		return;
	}

	if (img->height <= RSPAMD_NORMALIZED_DIM ||
			img->width <= RSPAMD_NORMALIZED_DIM) {
		return;
	}

	if (img->data->len > task->cfg->max_pic_size) {
		return;
	}

	if (rspamd_image_check_hash (task, img)) {
		return;
	}

	switch (img->type) {
	case IMAGE_TYPE_JPG:
		src = gdImageCreateFromJpegPtr (img->data->len, (void *)img->data->begin);
		break;
	case IMAGE_TYPE_PNG:
		src = gdImageCreateFromPngPtr (img->data->len, (void *)img->data->begin);
		break;
	case IMAGE_TYPE_GIF:
		src = gdImageCreateFromGifPtr (img->data->len, (void *)img->data->begin);
		break;
	case IMAGE_TYPE_BMP:
		src = gdImageCreateFromBmpPtr (img->data->len, (void *)img->data->begin);
		break;
	default:
		return;
	}

	if (src == NULL) {
		msg_info_task ("cannot load image of type %s from %T",
				rspamd_image_type_str (img->type), img->filename);
	}
	else {
		gdImageSetInterpolationMethod (src, GD_BILINEAR_FIXED);

		dst = gdImageScale (src, RSPAMD_NORMALIZED_DIM, RSPAMD_NORMALIZED_DIM);
		gdImageGrayScale (dst);
		gdImageDestroy (src);

		img->is_normalized = TRUE;
		dct = g_malloc0 (sizeof (gdouble) * RSPAMD_DCT_LEN);
		img->dct = g_malloc0 (RSPAMD_DCT_LEN / NBBY);
		rspamd_mempool_add_destructor (task->task_pool, g_free,
				img->dct);

		/*
		 * Split message into blocks:
		 *
		 * ****
		 * ****
		 *
		 * Get sum of saturation values, and set bit if sum is > avg
		 * Then go further
		 *
		 * ****
		 * ****
		 *
		 * and repeat this algorithm.
		 *
		 * So on each iteration we move by 16 pixels and calculate 2 elements of
		 * signature
		 */
		for (i = 0; i < RSPAMD_NORMALIZED_DIM; i += 8) {
			for (j = 0; j < RSPAMD_NORMALIZED_DIM; j += 8) {
				gint p[8][8];

				for (k = 0; k < 8; k ++) {
					p[k][0] = gdImageGetPixel (dst, i + k, j);
					p[k][1] = gdImageGetPixel (dst, i + k, j + 1);
					p[k][2] = gdImageGetPixel (dst, i + k, j + 2);
					p[k][3] = gdImageGetPixel (dst, i + k, j + 3);
					p[k][4] = gdImageGetPixel (dst, i + k, j + 4);
					p[k][5] = gdImageGetPixel (dst, i + k, j + 5);
					p[k][6] = gdImageGetPixel (dst, i + k, j + 6);
					p[k][7] = gdImageGetPixel (dst, i + k, j + 7);
				}

				rspamd_image_dct_block (p,
						dct + i * RSPAMD_NORMALIZED_DIM + j);

				gdouble avg = 0.0;

				for (k = 0; k < 8; k ++) {
					for (l = 0; l < 8; l ++) {
						gdouble x = *(dct +
								i * RSPAMD_NORMALIZED_DIM + j + k * 8 + l);
						avg += (x - avg) / (gdouble)(k * 8 + l + 1);
					}

				}


				for (k = 0; k < 8; k ++) {
					for (l = 0; l < 8; l ++) {
						guint idx = i * RSPAMD_NORMALIZED_DIM + j + k * 8 + l;

						if (dct[idx] >= avg) {
							setbit (img->dct, idx);
						}
					}
				}


			}
		}

		gdImageDestroy (dst);
		g_free (dct);
		rspamd_image_save_hash (task, img);
	}
#endif
}

struct rspamd_image*
rspamd_maybe_process_image (rspamd_mempool_t *pool,
							rspamd_ftok_t *data)
{
	enum rspamd_image_type type;
	struct rspamd_image *img = NULL;

	if ((type = detect_image_type (data)) != IMAGE_TYPE_UNKNOWN) {
		switch (type) {
		case IMAGE_TYPE_PNG:
			img = process_png_image (pool, data);
			break;
		case IMAGE_TYPE_JPG:
			img = process_jpg_image (pool, data);
			break;
		case IMAGE_TYPE_GIF:
			img = process_gif_image (pool, data);
			break;
		case IMAGE_TYPE_BMP:
			img = process_bmp_image (pool, data);
			break;
		default:
			img = NULL;
			break;
		}
	}

	return img;
}

static bool
process_image (struct rspamd_task *task, struct rspamd_mime_part *part)
{
	struct rspamd_image *img;

	img = rspamd_maybe_process_image (task->task_pool, &part->parsed_data);

	if (img != NULL) {
		msg_debug_images ("detected %s image of size %ud x %ud",
			rspamd_image_type_str (img->type),
			img->width, img->height);

		if (part->cd) {
			img->filename = &part->cd->filename;
		}

		img->parent = part;

		part->part_type = RSPAMD_MIME_PART_IMAGE;
		part->specific.img = img;

		return true;
	}

	return false;
}

const gchar *
rspamd_image_type_str (enum rspamd_image_type type)
{
	switch (type) {
	case IMAGE_TYPE_PNG:
		return "PNG";
		break;
	case IMAGE_TYPE_JPG:
		return "JPEG";
		break;
	case IMAGE_TYPE_GIF:
		return "GIF";
		break;
	case IMAGE_TYPE_BMP:
		return "BMP";
		break;
	default:
		break;
	}

	return "unknown";
}

static void
rspamd_image_process_part (struct rspamd_task *task, struct rspamd_mime_part *part)
{
	struct rspamd_mime_header *rh;
	struct rspamd_mime_text_part *tp;
	struct html_image *himg;
	const gchar *cid;
	guint cid_len, i;
	struct rspamd_image *img;

	img = (struct rspamd_image *)part->specific.img;

	if (img) {
		/* Check Content-Id */
		rh = rspamd_message_get_header_from_hash(part->raw_headers,
				"Content-Id", FALSE);

		if (rh) {
			cid = rh->decoded;

			if (*cid == '<') {
				cid ++;
			}

			cid_len = strlen (cid);

			if (cid_len > 0) {
				if (cid[cid_len - 1] == '>') {
					cid_len --;
				}

				PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, tp) {
					if (IS_TEXT_PART_HTML (tp) && tp->html != NULL) {
						himg = rspamd_html_find_embedded_image(tp->html, cid, cid_len);

						if (himg != NULL) {
							img->html_image = himg;
							himg->embedded_image = img;

							msg_debug_images ("found linked image by cid: <%s>",
									cid);

							if (himg->height == 0) {
								himg->height = img->height;
							}

							if (himg->width == 0) {
								himg->width = img->width;
							}
						}
					}
				}
			}
		}
	}
}

void
rspamd_images_link (struct rspamd_task *task)
{
	struct rspamd_mime_part *part;
	guint i;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		if (part->part_type == RSPAMD_MIME_PART_IMAGE) {
			rspamd_image_process_part (task, part);
		}
	}
}