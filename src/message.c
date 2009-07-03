/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "html.h"
#include "modules.h"

GByteArray*
strip_html_tags (struct worker_task *task, memory_pool_t *pool, struct mime_text_part *part, GByteArray *src, int *stateptr)
{
	uint8_t *tbuf = NULL, *p, *tp = NULL, *rp, *tbegin = NULL, c, lc;
	int br, i = 0, depth = 0, in_q = 0;
	int state = 0;
	GByteArray *buf;
	GNode *level_ptr = NULL;

	if (stateptr)
		state = *stateptr;
	
	buf = g_byte_array_sized_new (src->len);
	g_byte_array_append (buf, src->data, src->len);

	c = *src->data;
	lc = '\0';
	p = src->data;
	rp = buf->data;
	br = 0;

	while (i < src->len) {
		switch (c) {
			case '\0':
				break;
			case '<':
				if (g_ascii_isspace(*(p + 1))) {
					goto reg_char;
				}
				if (state == 0) {
					lc = '<';
					tbegin = p + 1;
					state = 1;
				} else if (state == 1) {
					depth++;
				}
				break;

			case '(':
				if (state == 2) {
					if (lc != '"' && lc != '\'') {
						lc = '(';
						br++;
					}
				} else if (state == 0) {
					*(rp++) = c;
				}
				break;	

			case ')':
				if (state == 2) {
					if (lc != '"' && lc != '\'') {
						lc = ')';
						br--;
					}
				} else if (state == 0) {
					*(rp++) = c;
				}
				break;	

			case '>':
				if (depth) {
					depth--;
					break;
				}

				if (in_q) {
					break;
				}

				switch (state) {
					case 1: /* HTML/XML */
						lc = '>';
						in_q = state = 0;
						*p = '\0';
						add_html_node (task, pool, part, tbegin, &level_ptr);
						*p = '>';
						break;
						
					case 2: /* PHP */
						if (!br && lc != '\"' && *(p-1) == '?') {
							in_q = state = 0;
							tp = tbuf;
						}
						break;
						
					case 3:
						in_q = state = 0;
						tp = tbuf;
						break;

					case 4: /* JavaScript/CSS/etc... */
						if (p >= src->data + 2 && *(p-1) == '-' && *(p-2) == '-') {
							in_q = state = 0;
							tp = tbuf;
						}
						break;

					default:
						*(rp++) = c;
						break;
				}
				break;

			case '"':
			case '\'':
				if (state == 2 && *(p-1) != '\\') {
					if (lc == c) {
						lc = '\0';
					} else if (lc != '\\') {
						lc = c;
					}
				} else if (state == 0) {
					*(rp++) = c;
				}
				if (state && p != src->data && *(p-1) != '\\' && (!in_q || *p == in_q)) {
					if (in_q) {
						in_q = 0;
					} else {
						in_q = *p;
					}
				}
				break;
			
			case '!': 
				/* JavaScript & Other HTML scripting languages */
				if (state == 1 && *(p-1) == '<') { 
					state = 3;
					lc = c;
				} else {
					if (state == 0) {
						*(rp++) = c;
					}
				}
				break;

			case '-':
				if (state == 3 && p >= src->data + 2 && *(p-1) == '-' && *(p-2) == '!') {
					state = 4;
				} else {
					goto reg_char;
				}
				break;

			case '?':

				if (state == 1 && *(p-1) == '<') { 
					br = 0;
					state = 2;
					break;
				}

			case 'E':
			case 'e':
				/* !DOCTYPE exception */
				if (state == 3 && p > src->data + 6
						     && g_ascii_tolower(*(p-1)) == 'p'
					         && g_ascii_tolower(*(p-2)) == 'y'
						     && g_ascii_tolower(*(p-3)) == 't'
						     && g_ascii_tolower(*(p-4)) == 'c'
						     && g_ascii_tolower(*(p-5)) == 'o'
						     && g_ascii_tolower(*(p-6)) == 'd') {
					state = 1;
					break;
				}
				/* fall-through */

			case 'l':

				/* swm: If we encounter '<?xml' then we shouldn't be in
				 * state == 2 (PHP). Switch back to HTML.
				 */

				if (state == 2 && p > src->data + 2 && *(p-1) == 'm' && *(p-2) == 'x') {
					state = 1;
					break;
				}

				/* fall-through */
			default:
reg_char:
				if (state == 0) {
					*(rp++) = c;
				} 
				break;
		}
		i++;
		if (i < src->len) {
			c = *(++p);
		}
	}	
	if (rp < buf->data + src->len) {
		*rp = '\0';
		g_byte_array_set_size (buf, rp - buf->data);
	}
	
	/* Check tag balancing */
	if (level_ptr && level_ptr->data != NULL) {
			part->is_balanced = FALSE;
	}

	if (stateptr) {
		*stateptr = state;
	}

	return buf;
}

static void
free_byte_array_callback (void *pointer)
{
	GByteArray *arr = (GByteArray *)pointer;
	g_byte_array_free (arr, TRUE);
}

static GByteArray *
convert_text_to_utf (struct worker_task *task, GByteArray *part_content, GMimeContentType *type, struct mime_text_part *text_part)
{
	GError *err = NULL;
	gsize read_bytes, write_bytes;
	const char *charset;
	gchar *res_str;
	GByteArray *result_array;

	if (task->cfg->raw_mode) {
		text_part->is_raw = TRUE;
		return part_content;
	}

	if ((charset = g_mime_content_type_get_parameter (type, "charset")) == NULL) {
		text_part->is_raw = TRUE;
		return part_content;
	}
	
	if (g_ascii_strcasecmp (charset, "utf-8") == 0 || g_ascii_strcasecmp (charset, "utf8") == 0) {
		text_part->is_raw = TRUE;
		return part_content;
	}
	
	res_str = g_convert_with_fallback (part_content->data, part_content->len,
									  "UTF-8", charset, NULL,
									  &read_bytes, &write_bytes, &err);
	if (res_str == NULL) {
		msg_warn ("convert_text_to_utf: cannot convert from %s to utf8: %s", charset, err ? err->message : "unknown problem");
		text_part->is_raw = TRUE;
		return part_content;
	}

	result_array = memory_pool_alloc (task->task_pool, sizeof (GByteArray));
	result_array->data = res_str;
	result_array->len = write_bytes + 1;
	memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_free, res_str);
	text_part->is_raw = FALSE;

	return result_array;
}

static void
process_text_part (struct worker_task *task, GByteArray *part_content, GMimeContentType *type)
{
	struct mime_text_part *text_part;

	if (g_mime_content_type_is_type (type, "text", "html") || g_mime_content_type_is_type (type, "text", "xhtml")) {
		msg_debug ("mime_foreach_callback: got urls from text/html part");

		text_part = memory_pool_alloc (task->task_pool, sizeof (struct mime_text_part));
		text_part->orig = convert_text_to_utf (task, part_content, type, text_part);
		text_part->is_html = TRUE;
		text_part->is_balanced = TRUE;
		text_part->html_nodes = NULL;

		text_part->html_urls = g_tree_new ( (GCompareFunc)g_ascii_strcasecmp);
		text_part->urls = g_tree_new ( (GCompareFunc)g_ascii_strcasecmp);

		text_part->content = strip_html_tags (task, task->task_pool, text_part, part_content, NULL);

		if (text_part->html_nodes == NULL) {
			url_parse_text (task->task_pool, task, text_part, FALSE);
		}
		else {
			url_parse_text (task->task_pool, task, text_part, FALSE);
#if 0
			url_parse_text (task->task_pool, task, text_part, TRUE);
#endif
		}

		text_part->fuzzy = fuzzy_init_byte_array (text_part->content, task->task_pool);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)free_byte_array_callback, text_part->content);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_tree_destroy, text_part->html_urls);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_tree_destroy, text_part->urls);
		task->text_parts = g_list_prepend (task->text_parts, text_part);
	} 
	else if (g_mime_content_type_is_type (type, "text", "plain")) {
		msg_debug ("mime_foreach_callback: got urls from text/plain part");

		text_part = memory_pool_alloc (task->task_pool, sizeof (struct mime_text_part));
		text_part->orig = convert_text_to_utf (task, part_content, type, text_part);
		text_part->content = text_part->orig;
		text_part->is_html = FALSE;
		text_part->fuzzy = fuzzy_init_byte_array (text_part->content, task->task_pool);
		text_part->html_urls = NULL;
		text_part->urls = g_tree_new ( (GCompareFunc)g_ascii_strcasecmp);
		url_parse_text (task->task_pool, task, text_part, FALSE);
		task->text_parts = g_list_prepend (task->text_parts, text_part);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_tree_destroy, text_part->urls);
	}
}

#ifdef GMIME24
static void
mime_foreach_callback (GMimeObject *parent, GMimeObject *part, gpointer user_data)
#else
static void
mime_foreach_callback (GMimeObject *part, gpointer user_data)
#endif
{
	struct worker_task *task = (struct worker_task *)user_data;
	struct mime_part *mime_part;
	GMimeContentType *type;
	GMimeDataWrapper *wrapper;
	GMimeStream *part_stream;
	GByteArray *part_content;
	
	task->parts_count ++;
	
	/* 'part' points to the current part node that g_mime_message_foreach_part() is iterating over */
	
	/* find out what class 'part' is... */
	if (GMIME_IS_MESSAGE_PART (part)) {
		/* message/rfc822 or message/news */
		GMimeMessage *message;
		
		/* g_mime_message_foreach_part() won't descend into
                   child message parts, so if we want to count any
                   subparts of this child message, we'll have to call
                   g_mime_message_foreach_part() again here. */
		
		message = g_mime_message_part_get_message ((GMimeMessagePart *) part);
#ifdef GMIME24
		g_mime_message_foreach (message, mime_foreach_callback, task);
#else
		g_mime_message_foreach_part (message, mime_foreach_callback, task);
#endif
		g_object_unref (message);
	} else if (GMIME_IS_MESSAGE_PARTIAL (part)) {
		/* message/partial */
		
		/* this is an incomplete message part, probably a
                   large message that the sender has broken into
                   smaller parts and is sending us bit by bit. we
                   could save some info about it so that we could
                   piece this back together again once we get all the
                   parts? */
	} else if (GMIME_IS_MULTIPART (part)) {
		/* multipart/mixed, multipart/alternative, multipart/related, multipart/signed, multipart/encrypted, etc... */
		
		/* we'll get to finding out if this is a signed/encrypted multipart later... */
	} else if (GMIME_IS_PART (part)) {
		/* a normal leaf part, could be text/plain or image/jpeg etc */
#ifdef GMIME24
		type = (GMimeContentType *)g_mime_object_get_content_type (GMIME_OBJECT (part));
#else
		type = (GMimeContentType *)g_mime_part_get_content_type (GMIME_PART (part));
#endif
		if (type == NULL) {
			msg_warn ("mime_foreach_callback: type of part is unknown, assume text/plain");
			type = g_mime_content_type_new ("text", "plain");
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_mime_content_type_destroy, type);
		}
		wrapper = g_mime_part_get_content_object (GMIME_PART (part));
		if (wrapper != NULL) {
			part_stream = g_mime_stream_mem_new ();
			if (g_mime_data_wrapper_write_to_stream (wrapper, part_stream) != -1) {
				g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (part_stream), FALSE);
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
				g_object_unref (part_stream);
				mime_part = memory_pool_alloc (task->task_pool, sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				msg_debug ("mime_foreach_callback: found part with content-type: %s/%s", type->type, type->subtype);
				task->parts = g_list_prepend (task->parts, mime_part);
				/* Skip empty parts */
				if (part_content->len > 0) {
					process_text_part (task, part_content, type);
				}
			}
			else {
				msg_warn ("mime_foreach_callback: write to stream failed: %d, %s", errno, strerror (errno));
			}
			g_object_unref (wrapper);
		}
		else {
			msg_warn ("mime_foreach_callback: cannot get wrapper for mime part, type of part: %s/%s", type->type, type->subtype);
		}
	} else {
		g_assert_not_reached ();
	}
}

static void
destroy_message (void *pointer)
{
	GMimeMessage *msg = pointer;

	msg_debug ("destroy_message: freeing pointer %p", msg);
	g_object_unref (msg);
}

int
process_message (struct worker_task *task)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
	GByteArray *tmp;
    
	tmp = memory_pool_alloc (task->task_pool, sizeof (GByteArray));
	tmp->data = task->msg->begin;
	tmp->len = task->msg->len;
	stream = g_mime_stream_mem_new_with_byte_array (tmp);
	/* 
	 * This causes g_mime_stream not to free memory by itself as it is memory allocated by
	 * pool allocator
	 */
	g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (stream), FALSE);

	msg_debug ("process_message: construct mime parser from string length %ld", (long int)task->msg->len);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);

	if (message == NULL) {
		msg_warn ("process_message: cannot construct mime from stream");
		return -1;
	}
	
	task->message = message;
	memory_pool_add_destructor (task->task_pool, (pool_destruct_func)destroy_message, task->message);

#ifdef GMIME24
	g_mime_message_foreach (message, mime_foreach_callback, task);
#else
	g_mime_message_foreach_part (message, mime_foreach_callback, task);
#endif
	
	msg_debug ("process_message: found %d parts in message", task->parts_count);
	if (task->queue_id == NULL) {
		task->queue_id = (char *)g_mime_message_get_message_id (task->message);
	}
	task->message_id = g_mime_message_get_message_id (task->message);
	if (task->message_id == NULL) {
		task->message_id = "undef";
	}

#ifdef GMIME24
	task->raw_headers = g_mime_object_get_headers (GMIME_OBJECT (task->message));
#else
	task->raw_headers = g_mime_message_get_headers (task->message);
#endif

	if (task->raw_headers) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_free, task->raw_headers);
	}

	task->rcpts = g_mime_message_get_all_recipients (message);
	if (task->rcpts) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)internet_address_list_destroy, task->rcpts);
	}
	
	if (task->worker) {
		task->worker->srv->stat->messages_scanned ++;
	}

	/* free the parser (and the stream) */
	g_object_unref (parser);

	return 0;
}

#ifdef GMIME24
static void
mime_learn_foreach_callback (GMimeObject *parent, GMimeObject *part, gpointer user_data)
#else
static void
mime_learn_foreach_callback (GMimeObject *part, gpointer user_data)
#endif
{
	struct controller_session *session = (struct controller_session *)user_data;
	struct mime_part *mime_part;
	GMimeContentType *type;
	GMimeDataWrapper *wrapper;
	GMimeStream *part_stream;
	GByteArray *part_content;
	
	/* 'part' points to the current part node that g_mime_message_foreach_part() is iterating over */
	
	/* find out what class 'part' is... */
	if (GMIME_IS_MESSAGE_PART (part)) {
		/* message/rfc822 or message/news */
		GMimeMessage *message;
		
		/* g_mime_message_foreach_part() won't descend into
                   child message parts, so if we want to count any
                   subparts of this child message, we'll have to call
                   g_mime_message_foreach_part() again here. */
		message = g_mime_message_part_get_message ((GMimeMessagePart *) part);
#ifdef GMIME24
		g_mime_message_foreach (message, mime_learn_foreach_callback, session);
#else
		g_mime_message_foreach_part (message, mime_learn_foreach_callback, session);
#endif
		g_object_unref (message);
	} else if (GMIME_IS_MESSAGE_PARTIAL (part)) {
		/* message/partial */
		
		/* this is an incomplete message part, probably a
                   large message that the sender has broken into
                   smaller parts and is sending us bit by bit. we
                   could save some info about it so that we could
                   piece this back together again once we get all the
                   parts? */
	} else if (GMIME_IS_MULTIPART (part)) {
		/* multipart/mixed, multipart/alternative, multipart/related, multipart/signed, multipart/encrypted, etc... */
		
		/* we'll get to finding out if this is a signed/encrypted multipart later... */
	} else if (GMIME_IS_PART (part)) {
		/* a normal leaf part, could be text/plain or image/jpeg etc */
		wrapper = g_mime_part_get_content_object (GMIME_PART (part));
		if (wrapper != NULL) {
			part_stream = g_mime_stream_mem_new ();
			if (g_mime_data_wrapper_write_to_stream (wrapper, part_stream) != -1) {
				g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (part_stream), FALSE);
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
				g_object_unref (part_stream);
#ifdef GMIME24
				type = (GMimeContentType *)g_mime_object_get_content_type (GMIME_OBJECT (part));
#else
				type = (GMimeContentType *)g_mime_part_get_content_type (GMIME_PART (part));
#endif
				mime_part = memory_pool_alloc (session->session_pool, sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				session->parts = g_list_prepend (session->parts, mime_part);
			}
			g_object_unref (wrapper);
		}
	} else {
		g_assert_not_reached ();
	}
}

int
process_learn (struct controller_session *session)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
	GByteArray *tmp;
    
	tmp = memory_pool_alloc (session->session_pool, sizeof (GByteArray));
	tmp->data = session->learn_buf->begin;
	tmp->len = session->learn_buf->len;
	stream = g_mime_stream_mem_new_with_byte_array (tmp);
	/* 
	 * This causes g_mime_stream not to free memory by itself as it is memory allocated by
	 * pool allocator
	 */
	g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (stream), FALSE);

	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);

	/* unref the stream (parser owns a ref, so this object does not actually get free'd until we destroy the parser) */
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);
	
	memory_pool_add_destructor (session->session_pool, (pool_destruct_func)g_object_unref, message);

#ifdef GMIME24
	g_mime_message_foreach (message, mime_learn_foreach_callback, session);
#else
	g_mime_message_foreach_part (message, mime_learn_foreach_callback, session);
#endif

	/* free the parser (and the stream) */
	g_object_unref (parser);
	
	return 0;
}

/*
 * XXX: remove this function for learning
 */
GByteArray* 
get_next_text_part (memory_pool_t *pool, GList *parts, GList **cur)
{
	struct mime_part *p;

	if (*cur == NULL) {
		*cur = g_list_first (parts);
	}
	else {
		*cur = g_list_next (*cur);
	}
	
	while (*cur) {
		p = (*cur)->data;
		/* For text/plain just return bytes */
		if (g_mime_content_type_is_type (p->type, "text", "plain")) {
			msg_debug ("get_next_text_part: text/plain part");
			return p->content;
		}
#if 0
		else if (g_mime_content_type_is_type (p->type, "text", "html")) {
			msg_debug ("get_next_text_part: try to strip html tags");
			ret = strip_html_tags (p->content, NULL);
			memory_pool_add_destructor (pool, (pool_destruct_func)free_byte_array_callback, ret);
			return ret;
		}
		else if (g_mime_content_type_is_type (p->type, "text", "xhtml")) {
			msg_debug ("get_next_text_part: try to strip html tags");
			ret = strip_html_tags (p->content, NULL);
			memory_pool_add_destructor (pool, (pool_destruct_func)free_byte_array_callback, ret);
			return ret;
		}
#endif
		*cur = g_list_next (*cur);
	}
	
	return NULL;
}

struct raw_header {
    struct raw_header *next;
    char *name;
    char *value;
};			

typedef struct _GMimeHeader {
	GHashTable *hash;
	GHashTable *writers;
	struct raw_header *headers;
} local_GMimeHeader;


/* known header field types */
enum {
	HEADER_FROM = 0,
	HEADER_REPLY_TO,
	HEADER_TO,
	HEADER_CC,
	HEADER_BCC,
	HEADER_SUBJECT,
	HEADER_DATE,
	HEADER_MESSAGE_ID,
	HEADER_UNKNOWN
};

#ifndef GMIME24
static void
header_iterate (memory_pool_t *pool, struct raw_header *h, GList **ret, const char *field)
{
	while (h) {
		if (h->value && !g_strncasecmp (field, h->name, strlen (field))) {
			if (pool != NULL) {
				*ret = g_list_prepend (*ret, memory_pool_strdup (pool, h->value));
			}
			else {
				*ret = g_list_prepend (*ret, g_strdup (h->value));
			}
		}
		h = h->next;
	}
}
#else
static void
header_iterate (memory_pool_t *pool, GMimeHeaderList *ls, GList **ret, const char field)
{
	GMimeHeaderIter *iter;
	const char *name;

	if (g_mime_header_list_get_iter (ls, iter)) {
		while (g_mime_header_iter_is_valid (iter)) {
			name = g_mime_header_iter_get_name (iter);
			if (!g_strncasecmp (field, name, strlen (name))) {
				if (pool != NULL) {
					*ret = g_list_prepend (*ret, memory_pool_strdup (pool, g_mime_header_iter_get_value (iter)));
				}
				else {
					*ret = g_list_prepend (*ret, g_strdup (g_mime_header_iter_get_value (iter)));
				}
			}
			if (!g_mime_header_iter_next (iter)) {
				break;
			}
		}
	}
}
#endif

static GList *
local_message_get_header(memory_pool_t *pool, GMimeMessage *message, const char *field)
{
	GList *gret = NULL;
	GMimeObject *part;
#ifndef GMIME24
	struct raw_header *h;

	if (field == NULL) {
		return NULL;
	}

	h = GMIME_OBJECT(message)->headers->headers;
	header_iterate (pool, h, &gret, field);
	
	if (gret == NULL) {
		/* Try to iterate with mime part headers */
		part = g_mime_message_get_mime_part (message);
		if (part) {
			h = part->headers->headers;
			header_iterate (pool, h, &gret, field);
			g_object_unref (part);
		}
	}

	return gret;
#else
	GMimeHeaderList *ls;

	ls = GMIME_OBJECT(message)->headers;
	header_iterate (pool, ls, &gret, field);
	if (gret == NULL) {
		/* Try to iterate with mime part headers */
		part = g_mime_message_get_mime_part (message);
		if (part) {
			ls = part->headers;
			header_iterate (pool, ls, &gret, field);
			g_object_unref (part);
		}
	}


	return gret;
#endif
}

/**
* g_mime_message_set_date_from_string: Set the message sent-date
* @message: MIME Message
* @string: A string of date
* 
* Set the sent-date on a MIME Message.
**/			 
void
local_mime_message_set_date_from_string (GMimeMessage *message, const gchar *string) 
{
	time_t date;
	int offset = 0;

	date = g_mime_utils_header_decode_date (string, &offset);
	g_mime_message_set_date (message, date, offset); 
}

/*
 * Replacements for standart gmime functions but converting adresses to IA
 */
static const char*
local_message_get_sender (GMimeMessage *message)
{
	char *res;
	const char *from = g_mime_message_get_sender (message);
	InternetAddressList *ia;
	
#ifndef	GMIME24
	ia = internet_address_parse_string (from);
#else
	ia = internet_address_list_parse_string (from);
#endif
	if (!ia) {
		return NULL;
	}
	res = internet_address_list_to_string (ia, FALSE);
	internet_address_list_destroy (ia);
	
	return res;
}

static const char*
local_message_get_reply_to (GMimeMessage *message)
{
	char *res;
	const char *from = g_mime_message_get_reply_to (message);
	InternetAddressList *ia;

#ifndef	GMIME24
	ia = internet_address_parse_string (from);
#else
	ia = internet_address_list_parse_string (from);
#endif
	if (!ia) {
		return NULL;
	}
	res = internet_address_list_to_string (ia, FALSE);
	internet_address_list_destroy (ia);
	
	return res;
}

#ifdef GMIME24

#define ADD_RECIPIENT_TEMPLATE(type,def)														\
static void																						\
local_message_add_recipients_from_string_##type (GMimeMessage *message, const gchar *string, const gchar *value)	\
{																								\
	InternetAddressList *il, *new;																\
																								\
	il = g_mime_message_get_recipients (message, (def));										\
	new = internet_address_list_parse_string (string);											\
	internet_address_list_append (il, new);														\
}																								\

ADD_RECIPIENT_TEMPLATE(to, GMIME_RECIPIENT_TYPE_TO)
ADD_RECIPIENT_TEMPLATE(cc, GMIME_RECIPIENT_TYPE_CC)
ADD_RECIPIENT_TEMPLATE(bcc, GMIME_RECIPIENT_TYPE_BCC)

#define GET_RECIPIENT_TEMPLATE(type,def)														\
static InternetAddressList*																		\
local_message_get_recipients_##type (GMimeMessage *message, const char *unused)					\
{																								\
	return g_mime_message_get_recipients (message, (def));										\
}

GET_RECIPIENT_TEMPLATE(to, GMIME_RECIPIENT_TYPE_TO)
GET_RECIPIENT_TEMPLATE(cc, GMIME_RECIPIENT_TYPE_CC)
GET_RECIPIENT_TEMPLATE(bcc, GMIME_RECIPIENT_TYPE_BCC)

#endif


/* different declarations for different types of set and get functions */
typedef const char *(*GetFunc) (GMimeMessage *message);
typedef InternetAddressList *(*GetRcptFunc) (GMimeMessage *message, const char *type );
typedef GList *(*GetListFunc) (memory_pool_t *pool, GMimeMessage *message, const char *type );
typedef void	 (*SetFunc) (GMimeMessage *message, const char *value);
typedef void	 (*SetListFunc) (GMimeMessage *message, const char *field, const char *value);

/** different types of functions
*
* FUNC_CHARPTR
*	- function with no arguments
*	- get returns char*
*
* FUNC_IA (from Internet Address)
*	- function with additional "field" argument from the fieldfunc table,
*	- get returns Glist*
*
* FUNC_LIST
*	- function with additional "field" argument (given arbitrary header field name)
*	- get returns Glist*
**/
enum {
	FUNC_CHARPTR = 0,
	FUNC_CHARFREEPTR,
	FUNC_IA,
	FUNC_LIST
};

/**
* fieldfunc struct: structure of MIME fields and corresponding get and set
* functions.
**/
static struct {
	char *	name;
	GetFunc	func;
	GetRcptFunc	rcptfunc;
	GetListFunc	getlistfunc;
	SetFunc	setfunc;
	SetListFunc	setlfunc;
	gint		functype;
} fieldfunc[] = {
	{ "From",		local_message_get_sender,					NULL, NULL,	g_mime_message_set_sender, NULL, FUNC_CHARFREEPTR },
	{ "Reply-To",	local_message_get_reply_to, 				NULL, NULL,	g_mime_message_set_reply_to, NULL, FUNC_CHARFREEPTR },
#ifndef GMIME24
	{ "To",	NULL,	(GetRcptFunc)g_mime_message_get_recipients,	NULL, NULL, (SetListFunc)g_mime_message_add_recipients_from_string, FUNC_IA },
	{ "Cc",	NULL,	(GetRcptFunc)g_mime_message_get_recipients,	NULL, NULL, (SetListFunc)g_mime_message_add_recipients_from_string, FUNC_IA },
	{ "Bcc",NULL,	(GetRcptFunc)g_mime_message_get_recipients,	NULL, NULL, (SetListFunc)g_mime_message_add_recipients_from_string, FUNC_IA },
	{ "Date", (GetFunc)g_mime_message_get_date_string, NULL, NULL,			local_mime_message_set_date_from_string,	NULL, FUNC_CHARFREEPTR },
#else
	{ "To",	NULL,	local_message_get_recipients_to,	NULL, NULL, 		local_message_add_recipients_from_string_to, FUNC_IA },
	{ "Cc",	NULL,	local_message_get_recipients_cc,	NULL, NULL, 		local_message_add_recipients_from_string_cc, FUNC_IA },
	{ "Bcc",	NULL,	local_message_get_recipients_bcc,	NULL, NULL, 	local_message_add_recipients_from_string_bcc, FUNC_IA },
	{ "Date",		g_mime_message_get_date_as_string, NULL, NULL,			local_mime_message_set_date_from_string,	NULL, FUNC_CHARFREEPTR },
#endif
	{ "Subject",	g_mime_message_get_subject,		NULL, NULL,				g_mime_message_set_subject,	NULL, FUNC_CHARPTR },
	{ "Message-Id",	g_mime_message_get_message_id,	NULL, NULL,				g_mime_message_set_message_id,	NULL, FUNC_CHARPTR },
#ifndef GMIME24
	{ NULL,	NULL,	NULL,	local_message_get_header,	  NULL,				g_mime_message_add_header, FUNC_LIST }
#else
	{ NULL,	NULL,	NULL,	local_message_get_header,	  NULL,				g_mime_object_append_header, FUNC_LIST }
#endif
};
/**
* message_set_header: set header of any type excluding special (Content- and MIME-Version:)
**/
void
message_set_header (GMimeMessage *message, const char *field, const char *value) 
{
	gint i;

	if (!g_strcasecmp (field, "MIME-Version:") || !g_strncasecmp (field, "Content-", 8)) {
		return;
	}
	for (i=0; i<=HEADER_UNKNOWN; ++i) {
		if (!fieldfunc[i].name || !g_strncasecmp(field, fieldfunc[i].name, strlen(fieldfunc[i].name))) { 
			switch (fieldfunc[i].functype) {
				case FUNC_CHARPTR:
					(*(fieldfunc[i].setfunc))(message, value);
					break;
				case FUNC_IA:
					(*(fieldfunc[i].setlfunc))(message, fieldfunc[i].name, value);
					break;
				case FUNC_LIST:
					(*(fieldfunc[i].setlfunc))(message, field, value);
					break;
			}
			break;
		}		 
	}
}


/**
* message_get_header: returns the list of 'any header' values
* (except of unsupported yet Content- and MIME-Version special headers)
*
* You should free the GList list by yourself.
**/
GList *
message_get_header (memory_pool_t *pool, GMimeMessage *message, const char *field) 
{
	gint		i;
	char *	ret = NULL, *ia_string;
	GList *	gret = NULL;
	InternetAddressList *ia_list = NULL, *ia;

	for (i = 0; i <= HEADER_UNKNOWN; ++i) {
		if (!fieldfunc[i].name || !g_strncasecmp(field, fieldfunc[i].name, strlen(fieldfunc[i].name))) { 
			switch (fieldfunc[i].functype) {
				case FUNC_CHARFREEPTR:
					ret = (char *)(*(fieldfunc[i].func))(message);
					break;
				case FUNC_CHARPTR:
					ret = (char *)(*(fieldfunc[i].func))(message);
					break;
				case FUNC_IA:
					ia_list = (*(fieldfunc[i].rcptfunc))(message, field);
					gret = g_list_alloc();
					ia = ia_list;
#ifndef GMIME24
					while (ia && ia->address) {

						ia_string = internet_address_to_string ((InternetAddress *)ia->address, FALSE);
						memory_pool_add_destructor (pool, (pool_destruct_func)g_free, ia_string);
						gret = g_list_prepend (gret, ia_string);
						ia = ia->next;
					}
#else
					i = internet_address_list_length (ia);
					while (i > 0) {
						ia_string = internet_address_to_string (internet_address_list_get_address (ia, i), FALSE);
						memory_pool_add_destructor (pool, (pool_destruct_func)g_free, ia_string);
						gret = g_list_prepend (gret, ia_string);
						-- i;
					}
#endif
					break;
				case FUNC_LIST:
					gret = (*(fieldfunc[i].getlistfunc))(pool, message, field);
					break;
			}
			break;
		}		 
	}
	if (gret == NULL && ret != NULL) {
		if (pool != NULL) {
			gret = g_list_prepend (gret, memory_pool_strdup (pool, ret));
		}
		else {
			gret = g_list_prepend (gret, g_strdup (ret));
		}
	}
	if (fieldfunc[i].functype == FUNC_CHARFREEPTR && ret) {
		g_free (ret);
	}

	return gret;
}
