#ifndef IMAGES_H_
#define IMAGES_H_

#include "config.h"
#include "fstring.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct html_image;
struct rspamd_task;
struct rspamd_mime_part;

#define RSPAMD_DCT_LEN (64 * 64)

enum rspamd_image_type {
	IMAGE_TYPE_PNG = 0,
	IMAGE_TYPE_JPG,
	IMAGE_TYPE_GIF,
	IMAGE_TYPE_BMP,
	IMAGE_TYPE_UNKNOWN
};

struct rspamd_image {
	struct rspamd_mime_part *parent;
	rspamd_ftok_t *data;
	rspamd_ftok_t *filename;
	struct html_image *html_image;
	enum rspamd_image_type type;
	guint32 width;
	guint32 height;
	gboolean is_normalized;
	guchar *dct;
};

/*
 * Process images from a worker task
 */
void rspamd_images_process (struct rspamd_task *task);

/**
 * Process image if possible in a single mime part
 * @param task
 * @param part
 * @return
 */
bool rspamd_images_process_mime_part_maybe (struct rspamd_task *task,
		struct rspamd_mime_part *part);

/*
 * Link embedded images to the HTML parts
 */
void rspamd_images_link (struct rspamd_task *task);

/**
 * Processes image in raw data
 * @param task
 * @param data
 * @return
 */
struct rspamd_image *rspamd_maybe_process_image (rspamd_mempool_t *pool,
												 rspamd_ftok_t *data);

/*
 * Get textual representation of an image's type
 */
const gchar *rspamd_image_type_str (enum rspamd_image_type type);

void rspamd_image_normalize (struct rspamd_task *task, struct rspamd_image *img);

#ifdef  __cplusplus
}
#endif

#endif /* IMAGES_H_ */
