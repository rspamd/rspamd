#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <gmime/gmime.h>

#include "../src/config.h"
#if !defined(HAVE_OWN_QUEUE_H) && defined(HAVE_SYS_QUEUE_H)
#include <sys/queue.h>
#endif
#ifdef HAVE_OWN_QUEUE_H
#include "../src/queue.h"
#endif

#include "../src/main.h"
#include "../src/cfg_file.h"
#include "../src/url.h"
#include "../src/message.h"

static void
mime_foreach_callback (GMimeObject *part, gpointer user_data)
{
	struct worker_task *task = (struct worker_task *)user_data;
	struct mime_part *mime_part;
	GMimeContentType *type;
	GMimeDataWrapper *wrapper;
	GMimeStream *part_stream;
	GByteArray *part_content;
	GMimeMessage *message;
	
	/* 'part' points to the current part node that g_mime_message_foreach_part() is iterating over */
	
	/* find out what class 'part' is... */
	if (GMIME_IS_MESSAGE_PART (part)) {
		/* message/rfc822 or message/news */
		printf ("Message part found\n");
		
		/* g_mime_message_foreach_part() won't descend into
                   child message parts, so if we want to count any
                   subparts of this child message, we'll have to call
                   g_mime_message_foreach_part() again here. */
		
		message = g_mime_message_part_get_message ((GMimeMessagePart *) part);
		g_mime_message_foreach_part (message, mime_foreach_callback, task);
		g_object_unref (message);
	} else if (GMIME_IS_MESSAGE_PARTIAL (part)) {
		/* message/partial */
		printf ("Message/partial part found\n");
		
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
		printf ("Normal part found\n");
		/* a normal leaf part, could be text/plain or image/jpeg etc */
		wrapper = g_mime_part_get_content_object (GMIME_PART (part));
		if (wrapper != NULL) {
			part_stream = g_mime_stream_mem_new ();
			printf ("Get new wrapper object for normal part\n");
			if (g_mime_data_wrapper_write_to_stream (wrapper, part_stream) != -1) {
				printf ("Write wrapper to stream\n");
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
				type = (GMimeContentType *)g_mime_part_get_content_type (GMIME_PART (part));
				mime_part = g_malloc (sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				task->parts =  g_list_prepend (task->parts, mime_part);
				if (g_mime_content_type_is_type (type, "text", "html")) {
					printf ("Found text/html part\n");
					url_parse_html (task, part_content);
				} 
				else if (g_mime_content_type_is_type (type, "text", "plain")) {
					printf ("Found text/plain part\n");
					url_parse_text (task, part_content);
				}
			}
		}
	} else {
		g_assert_not_reached ();
	}
}


int
main (int argc, char **argv)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
	struct worker_task task;
	struct uri *url;
	char *buf = NULL;
	size_t pos = 0, size = 65535;
	
	g_mem_set_vtable(glib_mem_profiler_table);
	g_mime_init (0);
	
	/* Preallocate buffer */
	buf = g_malloc (size);

	while (!feof (stdin)) {
		*(buf + pos) = getchar ();
		pos ++;
		if (pos == size) {
			size *= 2;
			buf = g_realloc (buf, size);
		}
	}

	stream = g_mime_stream_mem_new_with_buffer (buf, pos);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);

	/* unref the stream (parser owns a ref, so this object does not actually get free'd until we destroy the parser) */
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);
	
	task.message = message;
	TAILQ_INIT (&task.urls);

	/* free the parser (and the stream) */
	g_object_unref (parser);

	g_mime_message_foreach_part (message, mime_foreach_callback, &task);

	TAILQ_FOREACH (url, &task.urls, next) {
		printf ("Found url: %s, hostname: %s, data: %s\n", struri (url), url->host, url->data);
	}

}
