/* Copyright (c) 2010, Vsevolod Stakhov
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
#include "images.h"
#include "rspamd.h"
#include "message.h"
#include "html.h"

static const guint8 png_signature[] = {137, 80, 78, 71, 13, 10, 26, 10};
static const guint8 jpg_sig1[] = {0xff, 0xd8};
static const guint8 jpg_sig2[] = {'J', 'F', 'I', 'F'};
static const guint8 gif_signature[] = {'G', 'I', 'F', '8'};
static const guint8 bmp_signature[] = {'B', 'M'};

static void process_image (struct rspamd_task *task, struct mime_part *part);


void
rspamd_images_process (struct rspamd_task *task)
{
	guint i;
	struct mime_part *part;

	for (i = 0; i < task->parts->len; i ++) {
		part = g_ptr_array_index (task->parts, i);
		if (g_mime_content_type_is_type (part->type, "image",
			"*") && part->content->len > 0) {
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
			if (memcmp (data->data + 6, jpg_sig2, sizeof (jpg_sig2)) == 0) {
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
		msg_info_task ("bad png detected (maybe striped): <%s>", task->message_id);
		return NULL;
	}

	/* In png we should find iHDR section and get data from it */
	/* Skip signature and read header section */
	p = data->data + 12;
	if (memcmp (p, "IHDR", 4) != 0) {
		msg_info_task ("png doesn't begins with IHDR section", task->message_id);
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
	guint8 *p;
	guint16 t;
	gsize remain;
	struct rspamd_image *img;

	img = rspamd_mempool_alloc0 (task->task_pool, sizeof (struct rspamd_image));
	img->type = IMAGE_TYPE_JPG;
	img->data = data;

	p = data->data;
	remain = data->len;
	/* In jpeg we should find any data stream (ff c0 .. ff c3) and extract its height and width */
	while (remain--) {
		if (*p == 0xFF && remain > 8 &&
			(*(p + 1) >= 0xC0 && *(p + 1) <= 0xC3)) {
			memcpy (&t, p + 5, sizeof (guint16));
			img->height = ntohs (t);
			memcpy (&t, p + 7, sizeof (guint16));
			img->width = ntohs (t);
			return img;
		}
		p++;
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
		msg_info_task ("bad gif detected (maybe striped): <%s>", task->message_id);
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
		msg_info_task ("bad bmp detected (maybe striped): <%s>", task->message_id);
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
process_image (struct rspamd_task *task, struct mime_part *part)
{
	enum rspamd_image_type type;
	struct rspamd_image *img = NULL;
	struct raw_header *rh;
	struct mime_text_part *tp;
	struct html_image *himg;
	const gchar *cid, *html_cid;
	guint cid_len, i, j;

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
		task->images = g_list_prepend (task->images, img);

		/* Check Content-Id */
		rh = g_hash_table_lookup (part->raw_headers, "Content-Id");

		if (rh != NULL) {
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
