/* Copyright (c) 2014, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#ifndef TASK_H_
#define TASK_H_

#include "config.h"
#include "http.h"
#include "events.h"
#include "util.h"
#include "mem_pool.h"
#include "dns.h"

enum rspamd_command {
	CMD_CHECK,
	CMD_SYMBOLS,
	CMD_REPORT,
	CMD_REPORT_IFSPAM,
	CMD_SKIP,
	CMD_PING,
	CMD_PROCESS,
	CMD_OTHER
};

enum rspamd_metric_action {
	METRIC_ACTION_REJECT = 0,
	METRIC_ACTION_SOFT_REJECT,
	METRIC_ACTION_REWRITE_SUBJECT,
	METRIC_ACTION_ADD_HEADER,
	METRIC_ACTION_GREYLIST,
	METRIC_ACTION_NOACTION,
	METRIC_ACTION_MAX
};

typedef gint (*protocol_reply_func)(struct rspamd_task *task);

struct custom_command {
	const gchar *name;
	protocol_reply_func func;
};

/**
 * Worker task structure
 */
struct rspamd_task {
	struct rspamd_worker *worker;								/**< pointer to worker object						*/
	enum {
		READ_MESSAGE,
		WAIT_PRE_FILTER,
		WAIT_FILTER,
		WAIT_POST_FILTER,
		WRITE_REPLY,
		CLOSING_CONNECTION
	} state;													/**< current session state							*/
	enum rspamd_command cmd;									/**< command										*/
	struct custom_command *custom_cmd;							/**< custom command if any							*/
	gint sock;													/**< socket descriptor								*/
	gboolean is_mime;                                           /**< if this task is mime task                      */
	gboolean is_json;											/**< output is JSON									*/
	gboolean allow_learn;										/**< allow learning									*/
	gboolean is_skipped;                                        /**< whether message was skipped by configuration   */

	gchar *helo;													/**< helo header value								*/
	gchar *from;													/**< from header value								*/
	gchar *queue_id;												/**< queue id if specified							*/
	const gchar *message_id;										/**< message id										*/
	GList *rcpt;													/**< recipients list								*/
	guint nrcpt;											/**< number of recipients							*/
	rspamd_inet_addr_t from_addr;								/**< from addr for a task							*/
	rspamd_inet_addr_t client_addr;								/**< address of connected socket					*/
	gchar *deliver_to;											/**< address to deliver								*/
	gchar *user;													/**< user to deliver								*/
	gchar *subject;												/**< subject (for non-mime)							*/
	gchar *hostname;											/**< hostname reported by MTA						*/
	GString *msg;												/**< message buffer									*/
	struct rspamd_http_connection *http_conn;					/**< HTTP server connection							*/
	struct rspamd_async_session* s;								/**< async session object							*/
	gint parts_count;											/**< mime parts count								*/
	GMimeMessage *message;										/**< message, parsed with GMime						*/
	GMimeObject *parser_parent_part;							/**< current parent part							*/
	InternetAddressList *rcpts;									/**< list of all recipients 						*/
	GList *parts;												/**< list of parsed parts							*/
	GList *text_parts;											/**< list of text parts								*/
	gchar *raw_headers_str;											/**< list of raw headers							*/
	GList *received;											/**< list of received headers						*/
	GTree *urls;												/**< list of parsed urls							*/
	GTree *emails;												/**< list of parsed emails							*/
	GList *images;												/**< list of images									*/
	GHashTable *raw_headers;									/**< list of raw headers							*/
	GHashTable *results;										/**< hash table of metric_result indexed by
	 *    metric's name									*/
	GHashTable *tokens;											/**< hash table of tokens indexed by tokenizer
	 *    pointer 										*/
	GList *messages;											/**< list of messages that would be reported		*/
	GHashTable *re_cache;										/**< cache for matched or not matched regexps		*/
	struct config_file *cfg;									/**< pointer to config object						*/
	gchar *last_error;											/**< last error										*/
	gint error_code;												/**< code of last error								*/
	rspamd_mempool_t *task_pool;									/**< memory pool for task							*/
#ifdef HAVE_CLOCK_GETTIME
	struct timespec ts;											/**< time of connection								*/
#endif
	struct timeval tv;											/**< time of connection								*/
	guint32 scan_milliseconds;									/**< how much milliseconds passed					*/
	gboolean pass_all_filters;									/**< pass task throught every rule					*/
	gboolean no_log;											/**< do not log or write this task to the history	*/
	guint32 parser_recursion;									/**< for avoiding recursion stack overflow			*/
	gboolean (*fin_callback)(void *arg);						/**< calback for filters finalizing					*/
	void *fin_arg;												/**< argument for fin callback						*/

	guint32 dns_requests;										/**< number of DNS requests per this task			*/

	struct rspamd_dns_resolver *resolver;						/**< DNS resolver									*/
	struct event_base *ev_base;									/**< Event base										*/

	GThreadPool *classify_pool;									/**< A pool of classify threads 					*/

	struct {
		enum rspamd_metric_action action;						/**< Action of pre filters							*/
		gchar *str;												/**< String describing action						*/
	} pre_result;												/**< Result of pre-filters							*/
};

#endif /* TASK_H_ */
