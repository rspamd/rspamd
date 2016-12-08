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
#include "html.h"

#ifdef WITH_GD
#include "gd.h"
#include <math.h>

#define RSPAMD_NORMALIZED_DIM rspamd_cryptobox_HASHBYTES / 8
#endif

static const guint8 png_signature[] = {137, 80, 78, 71, 13, 10, 26, 10};
static const guint8 jpg_sig1[] = {0xff, 0xd8};
static const guint8 jpg_sig_jfif[] = {0xff, 0xe0};
static const guint8 jpg_sig_exif[] = {0xff, 0xe1};
static const guint8 gif_signature[] = {'G', 'I', 'F', '8'};
static const guint8 bmp_signature[] = {'B', 'M'};

static void process_image (struct rspamd_task *task, struct rspamd_mime_part *part);


void
rspamd_images_process (struct rspamd_task *task)
{
	guint i;
	struct rspamd_mime_part *part;

	for (i = 0; i < task->parts->len; i ++) {
		part = g_ptr_array_index (task->parts, i);
		if (g_mime_content_type_is_type (part->type, "image", "*") &&
				part->content->len > 0) {
			process_image (task, part);
		}
	}

}

static enum rspamd_image_type
detect_image_type (GByteArray *data)
{
	if (data->len > sizeof (png_signature) / sizeof (png_signature[0])) {
		if (memcmp (data->data, png_signature, sizeof (png_signature)) == 0) {
			return IMAGE_TYPE_PNG;
		}
	}
	if (data->len > 10) {
		if (memcmp (data->data, jpg_sig1, sizeof (jpg_sig1)) == 0) {
			if (memcmp (data->data + 2, jpg_sig_jfif, sizeof (jpg_sig_jfif)) == 0 ||
					memcmp (data->data + 2, jpg_sig_exif, sizeof (jpg_sig_exif)) == 0) {
				return IMAGE_TYPE_JPG;
			}
		}
	}
	if (data->len > sizeof (gif_signature) / sizeof (gif_signature[0])) {
		if (memcmp (data->data, gif_signature, sizeof (gif_signature)) == 0) {
			return IMAGE_TYPE_GIF;
		}
	}
	if (data->len > sizeof (bmp_signature) / sizeof (bmp_signature[0])) {
		if (memcmp (data->data, bmp_signature, sizeof (bmp_signature)) == 0) {
			return IMAGE_TYPE_BMP;
		}
	}

	return IMAGE_TYPE_UNKNOWN;
}


static struct rspamd_image *
process_png_image (struct rspamd_task *task, GByteArray *data)
{
	struct rspamd_image *img;
	guint32 t;
	guint8 *p;

	if (data->len < 24) {
		msg_info_task ("bad png detected (maybe striped)");
		return NULL;
	}

	/* In png we should find iHDR section and get data from it */
	/* Skip signature and read header section */
	p = data->data + 12;
	if (memcmp (p, "IHDR", 4) != 0) {
		msg_info_task ("png doesn't begins with IHDR section");
		return NULL;
	}

	img = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct rspamd_image));
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
process_jpg_image (struct rspamd_task *task, GByteArray *data)
{
	guint8 *p, *end;
	guint16 h, w;
	struct rspamd_image *img;

	img = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_JPG;
	img->data = data;

	p = data->data;
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
process_gif_image (struct rspamd_task *task, GByteArray *data)
{
	struct rspamd_image *img;
	guint8 *p;
	guint16 t;

	if (data->len < 10) {
		msg_info_task ("bad gif detected (maybe striped)");
		return NULL;
	}

	img = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_GIF;
	img->data = data;

	p = data->data + 6;
	memcpy (&t, p,	   sizeof (guint16));
	img->width = GUINT16_FROM_LE (t);
	memcpy (&t, p + 2, sizeof (guint16));
	img->height = GUINT16_FROM_LE (t);

	return img;
}

static struct rspamd_image *
process_bmp_image (struct rspamd_task *task, GByteArray *data)
{
	struct rspamd_image *img;
	gint32 t;
	guint8 *p;

	if (data->len < 28) {
		msg_info_task ("bad bmp detected (maybe striped)");
		return NULL;
	}

	img = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_BMP;
	img->data = data;
	p = data->data + 18;
	memcpy (&t, p,	   sizeof (gint32));
	img->width = abs (GINT32_FROM_LE (t));
	memcpy (&t, p + 4, sizeof (gint32));
	img->height = abs (GINT32_FROM_LE (t));

	return img;
}

static void
rspamd_image_normalize (struct rspamd_task *task, struct rspamd_image *img)
{
#ifdef WITH_GD
	gdImagePtr src = NULL, dst = NULL;
	guint nw, nh, i, j, b = 0;
	gdouble avg, sum;
	guchar sig[rspamd_cryptobox_HASHBYTES];

	if (img->data->len == 0 || img->data->len > G_MAXINT32) {
		return;
	}

	if (img->height <= RSPAMD_NORMALIZED_DIM ||
			img->width <= RSPAMD_NORMALIZED_DIM) {
		return;
	}

	switch (img->type) {
	case IMAGE_TYPE_JPG:
		src = gdImageCreateFromJpegPtr (img->data->len, img->data->data);
		break;
	case IMAGE_TYPE_PNG:
		src = gdImageCreateFromPngPtr (img->data->len, img->data->data);
		break;
	case IMAGE_TYPE_GIF:
		src = gdImageCreateFromGifPtr (img->data->len, img->data->data);
		break;
	case IMAGE_TYPE_BMP:
		src = gdImageCreateFromBmpPtr (img->data->len, img->data->data);
		break;
	default:
		return;
	}

	if (src == NULL) {
		msg_info_task ("cannot load image of type %s from %s",
				rspamd_image_type_str (img->type), img->filename);
	}
	else {
		gdImageSetInterpolationMethod (src, GD_BILINEAR_FIXED);

		nw = RSPAMD_NORMALIZED_DIM;
		nh = RSPAMD_NORMALIZED_DIM;

		dst = gdImageScale (src, nw, nh);
		gdImageGrayScale (dst);
		gdImageDestroy (src);

		img->normalized_data = g_array_sized_new (FALSE, FALSE, sizeof (gint),
				nh * nw);

		avg = 0;

		/* Calculate moving average */
		for (i = 0; i < nh; i ++) {
			for (j = 0; j < nw; j ++) {
				gint px = gdImageGetPixel (dst, j, i);
				avg += (px - avg) / (gdouble)(i * nh + j + 1);

				g_array_append_val (img->normalized_data, px);
			}
		}

		/*
		 * Split message into blocks:
		 *
		 * ****
		 * ****
		 *
		 * Get sum of saturation values, and set bit if sum is > avg * 4
		 * Then go further
		 *
		 * ****
		 * ****
		 *
		 * and repeat this algorithm.
		 *
		 * So on each iteration we move by 16 pixels and calculate 2 bits of signature
		 * hence, we produce ({64} / {4}) ^ 2 * 2 == 512 bits
		 */
		for (i = 0; i < nh; i += 4) {
			for (j = 0; j < nw; j += 4) {
				gint p[8];

				p[0] = g_array_index (img->normalized_data, gint, i * nh + j);
				p[1] = g_array_index (img->normalized_data, gint, i * nh + j + 1);
				p[2] = g_array_index (img->normalized_data, gint, i * nh + j + 2);
				p[3] = g_array_index (img->normalized_data, gint, i * nh + j + 3);
				p[4] = g_array_index (img->normalized_data, gint, (i + 1) * nh + j);
				p[5] = g_array_index (img->normalized_data, gint, (i + 1) * nh + j + 1);
				p[6] = g_array_index (img->normalized_data, gint, (i + 1) * nh + j + 2);
				p[7] = g_array_index (img->normalized_data, gint, (i + 1) * nh + j + 3);
				sum = p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];

				if (fabs (sum) >= fabs (avg * 8)) {
					setbit (sig, b);
				}
				else {
					clrbit (sig, b);
				}
				b ++;

				p[0] = g_array_index (img->normalized_data, gint, (i + 2) * nh + j);
				p[1] = g_array_index (img->normalized_data, gint, (i + 2) * nh + j + 1);
				p[2] = g_array_index (img->normalized_data, gint, (i + 2) * nh + j + 2);
				p[3] = g_array_index (img->normalized_data, gint, (i + 2) * nh + j + 3);
				p[4] = g_array_index (img->normalized_data, gint, (i + 3) * nh + j);
				p[5] = g_array_index (img->normalized_data, gint, (i + 3) * nh + j + 1);
				p[6] = g_array_index (img->normalized_data, gint, (i + 3) * nh + j + 2);
				p[7] = g_array_index (img->normalized_data, gint, (i + 3) * nh + j + 3);

				sum = p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];

				if (fabs (sum) >= fabs (avg * 8)) {
					setbit (sig, b);
				}
				else {
					clrbit (sig, b);
				}
				b ++;
			}
		}

		msg_debug_task ("avg: %.0f, sig: %32xs, bits: %d", avg, sig, b);

		gdImageDestroy (dst);
		rspamd_mempool_add_destructor (task->task_pool, rspamd_array_free_hard,
				img->normalized_data);
	}
#endif
}

static void
process_image (struct rspamd_task *task, struct rspamd_mime_part *part)
{
	enum rspamd_image_type type;
	struct rspamd_image *img = NULL;
	struct raw_header *rh;
	struct rspamd_mime_text_part *tp;
	struct html_image *himg;
	const gchar *cid, *html_cid;
	guint cid_len, i, j;
	GPtrArray *ar;

	if ((type = detect_image_type (part->content)) != IMAGE_TYPE_UNKNOWN) {
		switch (type) {
		case IMAGE_TYPE_PNG:
			img = process_png_image (task, part->content);
			break;
		case IMAGE_TYPE_JPG:
			img = process_jpg_image (task, part->content);
			break;
		case IMAGE_TYPE_GIF:
			img = process_gif_image (task, part->content);
			break;
		case IMAGE_TYPE_BMP:
			img = process_bmp_image (task, part->content);
			break;
		default:
			img = NULL;
			break;
		}
	}

	if (img != NULL) {
		debug_task ("detected %s image of size %ud x %ud in message <%s>",
			rspamd_image_type_str (img->type),
			img->width, img->height,
			task->message_id);
		img->filename = part->filename;
		img->parent = part;
		rspamd_image_normalize (task, img);
		part->flags |= RSPAMD_MIME_PART_IMAGE;
		part->specific_data = img;

		/* Check Content-Id */
		ar = rspamd_message_get_header_from_hash (part->raw_headers,
				task->task_pool, "Content-Id", FALSE);

		if (ar != NULL && ar->len > 0) {
			rh = g_ptr_array_index (ar, 0);
			cid = rh->decoded;

			if (*cid == '<') {
				cid ++;
			}

			cid_len = strlen (cid);

			if (cid_len > 0) {
				if (cid[cid_len - 1] == '>') {
					cid_len --;
				}

				for (i = 0; i < task->text_parts->len; i ++) {
					tp = g_ptr_array_index (task->text_parts, i);

					if (IS_PART_HTML (tp) && tp->html != NULL &&
							tp->html->images != NULL) {
						for (j = 0; j < tp->html->images->len; j ++) {
							himg = g_ptr_array_index (tp->html->images, j);

							if ((himg->flags & RSPAMD_HTML_FLAG_IMAGE_EMBEDDED) &&
									himg->src) {
								html_cid = himg->src;

								if (strncmp (html_cid, "cid:", 4) == 0) {
									html_cid += 4;
								}

								if (strlen (html_cid) == cid_len &&
										memcmp (html_cid, cid, cid_len) == 0) {
									img->html_image = himg;

									debug_task ("found linked image by cid: <%s>",
											cid);
								}
							}
						}
					}
				}

			}

		}
	}
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
