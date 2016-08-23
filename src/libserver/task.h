/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef TASK_H_
#define TASK_H_

#include "config.h"
#include "http.h"
#include "events.h"
#include "util.h"
#include "mem_pool.h"
#include "dns.h"
#include "re_cache.h"

#include <gmime/gmime.h>

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

enum rspamd_task_stage {
	RSPAMD_TASK_STAGE_CONNECT = (1 << 0),
	RSPAMD_TASK_STAGE_ENVELOPE = (1 << 1),
	RSPAMD_TASK_STAGE_READ_MESSAGE = (1 << 2),
	RSPAMD_TASK_STAGE_PRE_FILTERS = (1 << 3),
	RSPAMD_TASK_STAGE_FILTERS = (1 << 4),
	RSPAMD_TASK_STAGE_CLASSIFIERS_PRE = (1 << 5),
	RSPAMD_TASK_STAGE_CLASSIFIERS = (1 << 6),
	RSPAMD_TASK_STAGE_CLASSIFIERS_POST = (1 << 7),
	RSPAMD_TASK_STAGE_COMPOSITES = (1 << 8),
	RSPAMD_TASK_STAGE_POST_FILTERS = (1 << 9),
	RSPAMD_TASK_STAGE_LEARN_PRE = (1 << 10),
	RSPAMD_TASK_STAGE_LEARN = (1 << 11),
	RSPAMD_TASK_STAGE_LEARN_POST = (1 << 12),
	RSPAMD_TASK_STAGE_DONE = (1 << 13),
	RSPAMD_TASK_STAGE_REPLIED = (1 << 14)
};

#define RSPAMD_TASK_PROCESS_ALL (RSPAMD_TASK_STAGE_CONNECT | \
		RSPAMD_TASK_STAGE_ENVELOPE | \
		RSPAMD_TASK_STAGE_READ_MESSAGE | \
		RSPAMD_TASK_STAGE_PRE_FILTERS | \
		RSPAMD_TASK_STAGE_FILTERS | \
		RSPAMD_TASK_STAGE_CLASSIFIERS_PRE | \
		RSPAMD_TASK_STAGE_CLASSIFIERS | \
		RSPAMD_TASK_STAGE_CLASSIFIERS_POST | \
		RSPAMD_TASK_STAGE_COMPOSITES | \
		RSPAMD_TASK_STAGE_POST_FILTERS | \
		RSPAMD_TASK_STAGE_LEARN_PRE | \
		RSPAMD_TASK_STAGE_LEARN | \
		RSPAMD_TASK_STAGE_LEARN_POST | \
		RSPAMD_TASK_STAGE_DONE)
#define RSPAMD_TASK_PROCESS_LEARN (RSPAMD_TASK_STAGE_CONNECT | \
		RSPAMD_TASK_STAGE_ENVELOPE | \
		RSPAMD_TASK_STAGE_READ_MESSAGE | \
		RSPAMD_TASK_STAGE_CLASSIFIERS_PRE | \
		RSPAMD_TASK_STAGE_CLASSIFIERS | \
		RSPAMD_TASK_STAGE_CLASSIFIERS_POST | \
		RSPAMD_TASK_STAGE_LEARN_PRE | \
		RSPAMD_TASK_STAGE_LEARN | \
		RSPAMD_TASK_STAGE_LEARN_POST | \
		RSPAMD_TASK_STAGE_DONE)

#define RSPAMD_TASK_FLAG_MIME (1 << 0)
#define RSPAMD_TASK_FLAG_JSON (1 << 1)
#define RSPAMD_TASK_FLAG_SKIP_EXTRA (1 << 2)
#define RSPAMD_TASK_FLAG_SKIP (1 << 3)
#define RSPAMD_TASK_FLAG_EXT_URLS (1 << 4)
#define RSPAMD_TASK_FLAG_SPAMC (1 << 5)
#define RSPAMD_TASK_FLAG_PASS_ALL (1 << 6)
#define RSPAMD_TASK_FLAG_NO_LOG (1 << 7)
#define RSPAMD_TASK_FLAG_NO_IP (1 << 8)
#define RSPAMD_TASK_FLAG_HAS_CONTROL (1 << 9)
#define RSPAMD_TASK_FLAG_PROCESSING (1 << 10)
#define RSPAMD_TASK_FLAG_GTUBE (1 << 11)
#define RSPAMD_TASK_FLAG_FILE (1 << 12)
#define RSPAMD_TASK_FLAG_NO_STAT (1 << 13)
#define RSPAMD_TASK_FLAG_UNLEARN (1 << 14)
#define RSPAMD_TASK_FLAG_ALREADY_LEARNED (1 << 15)
#define RSPAMD_TASK_FLAG_LEARN_SPAM (1 << 16)
#define RSPAMD_TASK_FLAG_LEARN_HAM (1 << 17)
#define RSPAMD_TASK_FLAG_LEARN_AUTO (1 << 18)
#define RSPAMD_TASK_FLAG_BROKEN_HEADERS (1 << 19)
#define RSPAMD_TASK_FLAG_HAS_SPAM_TOKENS (1 << 20)
#define RSPAMD_TASK_FLAG_HAS_HAM_TOKENS (1 << 21)
#define RSPAMD_TASK_FLAG_EMPTY (1 << 22)
#define RSPAMD_TASK_FLAG_LOCAL_CLIENT (1 << 23)

#define RSPAMD_TASK_IS_SKIPPED(task) (((task)->flags & RSPAMD_TASK_FLAG_SKIP))
#define RSPAMD_TASK_IS_JSON(task) (((task)->flags & RSPAMD_TASK_FLAG_JSON))
#define RSPAMD_TASK_IS_SPAMC(task) (((task)->flags & RSPAMD_TASK_FLAG_SPAMC))
#define RSPAMD_TASK_IS_PROCESSED(task) (((task)->processed_stages & RSPAMD_TASK_STAGE_DONE))
#define RSPAMD_TASK_IS_CLASSIFIED(task) (((task)->processed_stages & RSPAMD_TASK_STAGE_CLASSIFIERS))
#define RSPAMD_TASK_IS_EMPTY(task) (((task)->flags & RSPAMD_TASK_FLAG_EMPTY))

struct rspamd_email_address;


/**
 * Worker task structure
 */
struct rspamd_task {
	struct rspamd_worker *worker;					/**< pointer to worker object						*/
	guint processed_stages;							/**< bits of stages that are processed				*/
	enum rspamd_command cmd;						/**< command										*/
	gint sock;										/**< socket descriptor								*/
	guint flags;									/**< Bit flags										*/
	guint32 dns_requests;							/**< number of DNS requests per this task			*/
	gulong message_len;								/**< Message length									*/
	gchar *helo;									/**< helo header value								*/
	gchar *queue_id;								/**< queue id if specified							*/
	const gchar *message_id;						/**< message id										*/
	rspamd_inet_addr_t *from_addr;					/**< from addr for a task							*/
	rspamd_inet_addr_t *client_addr;				/**< address of connected socket					*/
	gchar *deliver_to;								/**< address to deliver								*/
	gchar *user;									/**< user to deliver								*/
	gchar *subject;									/**< subject (for non-mime)							*/
	gchar *hostname;								/**< hostname reported by MTA						*/
	GHashTable *request_headers;					/**< HTTP headers in a request						*/
	GHashTable *reply_headers;						/**< Custom reply headers							*/
	rspamd_ftok_t msg;								/**< message buffer									*/
	struct rspamd_http_connection *http_conn;		/**< HTTP server connection							*/
	struct rspamd_async_session * s;				/**< async session object							*/
	GMimeMessage *message;							/**< message, parsed with GMime						*/
	GPtrArray *parts;								/**< list of parsed parts							*/
	GPtrArray *text_parts;							/**< list of text parts								*/
	struct {
		const gchar *begin;
		gsize len;
		const gchar *body_start;
	} raw_headers_content;				/**< list of raw headers							*/
	GPtrArray *received;							/**< list of received headers						*/
	GHashTable *urls;								/**< list of parsed urls							*/
	GHashTable *emails;								/**< list of parsed emails							*/
	GHashTable *raw_headers;						/**< list of raw headers							*/
	GHashTable *results;							/**< hash table of metric_result indexed by
													 *    metric's name									*/
	GPtrArray *tokens;								/**< statistics tokens */

	InternetAddressList *rcpt_mime;
	GPtrArray *rcpt_envelope;						/**< array of rspamd_email_address					*/
	InternetAddressList *from_mime;
	struct rspamd_email_address *from_envelope;

	GList *messages;								/**< list of messages that would be reported		*/
	struct rspamd_re_runtime *re_rt;				/**< regexp runtime									*/
	GPtrArray *stat_runtimes;						/**< backend runtime							*/
	struct rspamd_config *cfg;						/**< pointer to config object						*/
	GError *err;
	rspamd_mempool_t *task_pool;					/**< memory pool for task							*/
	double time_real;
	double time_virtual;
	struct timeval tv;
	gboolean (*fin_callback)(struct rspamd_task *task, void *arg);
													/**< calback for filters finalizing					*/
	void *fin_arg;									/**< argument for fin callback						*/

	struct rspamd_dns_resolver *resolver;			/**< DNS resolver									*/
	struct event_base *ev_base;						/**< Event base										*/
	struct event timeout_ev;						/**< Global task timeout							*/
	struct event *guard_ev;							/**< Event for input sanity guard 					*/

	gpointer checkpoint;							/**< Opaque checkpoint data							*/

	struct {
		gint action;								/**< Action of pre filters							*/
		gchar *str;									/**< String describing action						*/
	} pre_result;									/**< Result of pre-filters							*/

	ucl_object_t *settings;							/**< Settings applied to task						*/

	const gchar *classifier;						/**< Classifier to learn (if needed)				*/
	guchar digest[16];
};

/**
 * Construct new task for worker
 */
struct rspamd_task * rspamd_task_new (struct rspamd_worker *worker,
		struct rspamd_config *cfg);
/**
 * Destroy task object and remove its IO dispatcher if it exists
 */
void rspamd_task_free (struct rspamd_task *task);

/**
 * Called if session was restored inside fin callback
 */
void rspamd_task_restore (void *arg);

/**
 * Called if all filters are processed
 * @return TRUE if session should be terminated
 */
gboolean rspamd_task_fin (void *arg);

/**
 * Load HTTP message with body in `msg` to an rspamd_task
 * @param task
 * @param msg
 * @param start
 * @param len
 * @return
 */
gboolean rspamd_task_load_message (struct rspamd_task *task,
	struct rspamd_http_message *msg, const gchar *start, gsize len);

/**
 * Process task
 * @param task task to process
 * @return task has been successfully parsed and processed
 */
gboolean rspamd_task_process (struct rspamd_task *task, guint stages);

/**
 * Return address of sender or NULL
 * @param task
 * @return
 */
struct rspamd_email_address* rspamd_task_get_sender (struct rspamd_task *task);

/**
 * Return addresses in the following precendence:
 * - deliver to
 * - the first smtp recipient
 * - the first mime recipient
 * @param task
 * @return
 */
const gchar *rspamd_task_get_principal_recipient (struct rspamd_task *task);

/**
 * Add a recipient for a task
 * @param task task object
 * @param rcpt string representation of recipient address
 * @return TRUE if an address has been parsed and added
 */
gboolean rspamd_task_add_recipient (struct rspamd_task *task, const gchar *rcpt);

/**
 * Learn specified statfile with message in a task
 * @param task worker's task object
 * @param classifier classifier to learn (or NULL to learn all)
 * @param err pointer to GError
 * @return true if learn succeed
 */
gboolean rspamd_learn_task_spam (struct rspamd_task *task,
	gboolean is_spam,
	const gchar *classifier,
	GError **err);

/**
 * Returns required score for a message (usually reject score)
 * @param task
 * @param m
 * @return
 */
struct metric_result;
gdouble rspamd_task_get_required_score (struct rspamd_task *task,
		struct metric_result *m);

/**
 * Returns the first header as value for a header
 * @param task
 * @param name
 * @return
 */
rspamd_ftok_t * rspamd_task_get_request_header (struct rspamd_task *task,
		const gchar *name);

/**
 * Returns all headers with the specific name
 * @param task
 * @param name
 * @return
 */
GPtrArray* rspamd_task_get_request_header_multiple (struct rspamd_task *task,
		const gchar *name);

/**
 * Adds a new request header to task (name and value should be mapped to fstring)
 * @param task
 * @param name
 * @param value
 */
void rspamd_task_add_request_header (struct rspamd_task *task,
		rspamd_ftok_t *name, rspamd_ftok_t *value);

/**
 * Write log line about the specified task if needed
 */
void rspamd_task_write_log (struct rspamd_task *task);

#endif /* TASK_H_ */
