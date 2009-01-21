#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>

#include <glib.h>
#include <gmime/gmime.h>

#include "util.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "modules.h"

GByteArray*
strip_html_tags (GByteArray *src, int *stateptr)
{
	uint8_t *tbuf = NULL, *p, *tp = NULL, *rp, c, lc;
	int br, i = 0, depth = 0, in_q = 0;
	int state = 0;
	GByteArray *buf;

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
						     && tolower(*(p-1)) == 'p'
					         && tolower(*(p-2)) == 'y'
						     && tolower(*(p-3)) == 't'
						     && tolower(*(p-4)) == 'c'
						     && tolower(*(p-5)) == 'o'
						     && tolower(*(p-6)) == 'd') {
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
		c = *(++p);
		i++;
	}	
	if (rp < buf->data + src->len) {
		*rp = '\0';
		g_byte_array_set_size (buf, rp - buf->data);
	}

	if (stateptr)
		*stateptr = state;

	return buf;
}

static void
free_byte_array_callback (void *pointer)
{
	GByteArray *arr = (GByteArray *)pointer;
	g_byte_array_free (arr, TRUE);
}

static void
mime_foreach_callback (GMimeObject *part, gpointer user_data)
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
		g_mime_message_foreach_part (message, mime_foreach_callback, task);
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
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
				type = (GMimeContentType *)g_mime_part_get_content_type (GMIME_PART (part));
				mime_part = memory_pool_alloc (task->task_pool, sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				task->parts = g_list_prepend (task->parts, mime_part);
				if (g_mime_content_type_is_type (type, "text", "html")) {
					url_parse_html (task, part_content);
				} 
				else if (g_mime_content_type_is_type (type, "text", "plain")) {
					url_parse_text (task, part_content);
				}
			}
		}
	} else {
		g_assert_not_reached ();
	}
}

int
process_message (struct worker_task *task)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;

	stream = g_mime_stream_mem_new_with_buffer (task->msg->buf->begin, task->msg->buf->len);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);

	/* unref the stream (parser owns a ref, so this object does not actually get free'd until we destroy the parser) */
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);
	
	task->message = message;
	memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_object_unref, task->message);

	/* free the parser (and the stream) */
	g_object_unref (parser);

	g_mime_message_foreach_part (message, mime_foreach_callback, task);
	
	msg_info ("process_message: found %d parts in message", task->parts_count);

	task->worker->srv->stat->messages_scanned ++;

	return 0;
}

static void
mime_learn_foreach_callback (GMimeObject *part, gpointer user_data)
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
		g_mime_message_foreach_part (message, mime_learn_foreach_callback, session);
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
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
				type = (GMimeContentType *)g_mime_part_get_content_type (GMIME_PART (part));
				mime_part = memory_pool_alloc (session->session_pool, sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				session->parts = g_list_prepend (session->parts, mime_part);
			}
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

	stream = g_mime_stream_mem_new_with_buffer (session->learn_buf->buf->begin, session->learn_buf->buf->len);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);

	/* unref the stream (parser owns a ref, so this object does not actually get free'd until we destroy the parser) */
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);
	
	memory_pool_add_destructor (session->session_pool, (pool_destruct_func)g_object_unref, message);

	/* free the parser (and the stream) */
	g_object_unref (parser);

	g_mime_message_foreach_part (message, mime_learn_foreach_callback, session);
	
	return 0;
}

GByteArray* 
get_next_text_part (memory_pool_t *pool, GList *parts, GList **cur)
{
	GByteArray *ret = NULL;
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
		*cur = g_list_next (*cur);
	}
	
	return NULL;
}
