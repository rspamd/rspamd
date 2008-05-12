#ifndef MIME_H
#define MIME_H

#include "fstring.h"
#ifndef OWN_QUEUE_H
#include <sys/queue.h>
#else
#include "queue.h"
#endif

/*
 * Header types. If we reach 31, we must group the headers we need to
 * remember at the beginning, or we should use fd_set bit sets.
 */
#define HDR_APPARENTLY_TO		1
#define HDR_BCC				2
#define HDR_CC				3
#define HDR_CONTENT_LENGTH		4
#define HDR_CONTENT_TRANSFER_ENCODING	5
#define HDR_CONTENT_TYPE		6
#define HDR_DATE			7
#define HDR_DELIVERED_TO		8
#define HDR_ERRORS_TO			9
#define HDR_FROM			10
#define HDR_MESSAGE_ID			11
#define HDR_RECEIVED			12
#define HDR_REPLY_TO			13
#define HDR_RESENT_BCC			14
#define HDR_RESENT_CC			15
#define HDR_RESENT_DATE			16
#define HDR_RESENT_FROM			17
#define HDR_RESENT_MESSAGE_ID		18
#define HDR_RESENT_REPLY_TO		19
#define HDR_RESENT_SENDER		20
#define HDR_RESENT_TO			21
#define HDR_RETURN_PATH			22
#define HDR_RETURN_RECEIPT_TO		23
#define HDR_SENDER			24
#define HDR_TO				25
#define HDR_MAIL_FOLLOWUP_TO		26
#define HDR_CONTENT_DESCRIPTION		27
#define HDR_CONTENT_DISPOSITION		28
#define HDR_CONTENT_ID			29
#define HDR_MIME_VERSION		30
#define HDR_DISP_NOTIFICATION		31

#define URL_A				1
#define URL_IMG				2

/*
 * Headers:
 * name - header name
 * value - decoded, translated to utf8 and normalized version
 * type - type of header in case of known headers
 */
typedef struct mime_header_s {
	f_str_t *name;
	f_str_t *value;
	int type;
	LIST_ENTRY (mime_header_s) next;
} mime_header_t;

/*
 * Body part:
 * data - content of this part, translated to utf, decoded, normalized and deHTMLed
 * type - content-type of this part
 * encoding - original encoding of body part
 */
typedef struct mime_body_part_s {
	f_str_t *data;
	f_str_t *type;
	f_str_t *encoding;
	LIST_ENTRY (mime_body_part_s) next;
} mime_body_part_t;

/*
 * Image and A urls:
 * url - normalized and decoded url
 * caption - decoded caption for this url (if any)
 * type - image or a references
 */
typedef struct mime_url_s {
	f_str_t *url;
	f_str_t *caption;
	int type;
} mime_url_t;

typedef struct mime_ctx_s {
	LIST_HEAD (headersl, mime_header_s) headers;
	LIST_HEAD (bodypartsl, mime_body_part_s) parts;
	f_str_t *cur_content_type;
	f_str_t *cur_encoding;
} mime_ctx_t;

#endif
