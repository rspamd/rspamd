#ifndef IMAGES_H_
#define IMAGES_H_

#include "config.h"

struct html_image;
struct rspamd_task;
struct rspamd_mime_part;

enum rspamd_image_type {
	IMAGE_TYPE_PNG = 0,
	IMAGE_TYPE_JPG,
	IMAGE_TYPE_GIF,
	IMAGE_TYPE_BMP,
	IMAGE_TYPE_UNKNOWN
};

struct rspamd_image {
	struct rspamd_mime_part *parent;
	GByteArray *data;
	const gchar *filename;
	struct html_image *html_image;
	enum rspamd_image_type type;
	guint32 width;
	guint32 height;
};

/*
 * Process images from a worker task
 */
void rspamd_images_process (struct rspamd_task *task);

/*
 * Get textual representation of an image's type
 */
const gchar * rspamd_image_type_str (enum rspamd_image_type type);

#endif /* IMAGES_H_ */
