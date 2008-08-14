#ifndef RSPAM_PERL_H
#define RSPAM_PERL_H

#include <sys/types.h>
#include <glib.h>

struct uri;

int perl_call_header_filter (const char *function, const char *header_name, const char *header_value);
int perl_call_mime_filter (const char *function, GByteArray *content);
int perl_call_message_filter (const char *function, GByteArray *content);
int perl_call_url_filter (const char *function, struct uri *uri);
int perl_call_chain_filter (const char *function, GArray *results);

#endif
