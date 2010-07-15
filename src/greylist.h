#ifndef RSPAMD_GREYLIST_H
#define RSPAMD_GREYLIST_H

#include "config.h"

#define CHECKSUM_SIZE 16
/* 5 minutes */
#define DEFAULT_GREYLIST_TIME 300
/* 2 days */
#define DEFAULT_EXPIRE_TIME 60 * 60 * 24 * 2

/**
 * Item in storage
 */
struct rspamd_grey_item {
	time_t age;					/**< age of checksum			*/
	guint8 data[CHECKSUM_SIZE];	/**< checksum of triplet		*/
};

/**
 * Protocol command that is used to work with greylist storage
 */
struct rspamd_grey_command {
	enum {
		GREY_CMD_ADD = 0,
		GREY_CMD_CHECK,
		GREY_CMD_DEL
	} cmd;
	gint version;
	guint8 data[CHECKSUM_SIZE];
};

/**
 * Reply packet
 */
struct rspamd_grey_reply {
	enum {
		GREY_OK = 0,
		GREY_GREYLISTED,
		GREY_EXPIRED,
		GREY_NOT_FOUND,
		GREY_ERR
	} reply;
};

typedef void (*greylist_cb_t) (gboolean greylisted, struct worker_task *task, gpointer ud);

#endif
