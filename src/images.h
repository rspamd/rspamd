#ifndef IMAGES_H_
#define IMAGES_H_

#include "config.h"
#include "main.h"

enum known_image_types {
	IMAGE_TYPE_PNG,
	IMAGE_TYPE_JPG,
	IMAGE_TYPE_GIF,
	IMAGE_TYPE_BMP,
	IMAGE_TYPE_UNKNOWN = 9000
};

struct rspamd_image {
	enum known_image_types type;
	GByteArray *data;
	guint32 width;
	guint32 height;
	const char *filename;
};

void process_images (struct worker_task *task);
const char *image_type_str (enum known_image_types type);

#endif /* IMAGES_H_ */
