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
#include "libserver/http/http_connection.h"
#include "async_session.h"
#include "util.h"
#include "mem_pool.h"
#include "dns.h"
#include "re_cache.h"
#include "khash.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum rspamd_command {
	CMD_SKIP = 0,
	CMD_PING,
	CMD_CHECK_SPAMC, /* Legacy spamasassin format */
	CMD_CHECK_RSPAMC, /* Legacy rspamc format (like SA one) */
	CMD_CHECK, /* Legacy check - metric json reply */
	CMD_CHECK_V2, /* Modern check - symbols in json reply  */
};

enum rspamd_task_stage {
	RSPAMD_TASK_STAGE_CONNECT = (1u << 0u),
	RSPAMD_TASK_STAGE_CONNFILTERS = (1u << 1u),
	RSPAMD_TASK_STAGE_READ_MESSAGE = (1u << 2u),
	RSPAMD_TASK_STAGE_PROCESS_MESSAGE = (1u << 3u),
	RSPAMD_TASK_STAGE_PRE_FILTERS = (1u << 4u),
	RSPAMD_TASK_STAGE_FILTERS = (1u << 5u),
	RSPAMD_TASK_STAGE_CLASSIFIERS_PRE = (1u << 6u),
	RSPAMD_TASK_STAGE_CLASSIFIERS = (1u << 7u),
	RSPAMD_TASK_STAGE_CLASSIFIERS_POST = (1u << 8u),
	RSPAMD_TASK_STAGE_COMPOSITES = (1u << 9u),
	RSPAMD_TASK_STAGE_POST_FILTERS = (1u << 10u),
	RSPAMD_TASK_STAGE_LEARN_PRE = (1u << 11u),
	RSPAMD_TASK_STAGE_LEARN = (1u << 12u),
	RSPAMD_TASK_STAGE_LEARN_POST = (1u << 13u),
	RSPAMD_TASK_STAGE_COMPOSITES_POST = (1u << 14u),
	RSPAMD_TASK_STAGE_IDEMPOTENT = (1u << 15u),
	RSPAMD_TASK_STAGE_DONE = (1u << 16u),
	RSPAMD_TASK_STAGE_REPLIED = (1u << 17u)
};

#define RSPAMD_TASK_PROCESS_ALL (RSPAMD_TASK_STAGE_CONNECT | \
        RSPAMD_TASK_STAGE_CONNFILTERS | \
        RSPAMD_TASK_STAGE_READ_MESSAGE | \
        RSPAMD_TASK_STAGE_PRE_FILTERS | \
        RSPAMD_TASK_STAGE_PROCESS_MESSAGE | \
        RSPAMD_TASK_STAGE_FILTERS | \
        RSPAMD_TASK_STAGE_CLASSIFIERS_PRE | \
        RSPAMD_TASK_STAGE_CLASSIFIERS | \
        RSPAMD_TASK_STAGE_CLASSIFIERS_POST | \
        RSPAMD_TASK_STAGE_COMPOSITES | \
        RSPAMD_TASK_STAGE_POST_FILTERS | \
        RSPAMD_TASK_STAGE_LEARN_PRE | \
        RSPAMD_TASK_STAGE_LEARN | \
        RSPAMD_TASK_STAGE_LEARN_POST | \
        RSPAMD_TASK_STAGE_COMPOSITES_POST | \
        RSPAMD_TASK_STAGE_IDEMPOTENT | \
        RSPAMD_TASK_STAGE_DONE)
#define RSPAMD_TASK_PROCESS_LEARN (RSPAMD_TASK_STAGE_CONNECT | \
        RSPAMD_TASK_STAGE_READ_MESSAGE | \
        RSPAMD_TASK_STAGE_PROCESS_MESSAGE | \
        RSPAMD_TASK_STAGE_CLASSIFIERS_PRE | \
        RSPAMD_TASK_STAGE_CLASSIFIERS | \
        RSPAMD_TASK_STAGE_CLASSIFIERS_POST | \
        RSPAMD_TASK_STAGE_LEARN_PRE | \
        RSPAMD_TASK_STAGE_LEARN | \
        RSPAMD_TASK_STAGE_LEARN_POST | \
        RSPAMD_TASK_STAGE_DONE)

#define RSPAMD_TASK_FLAG_MIME (1u << 0u)
#define RSPAMD_TASK_FLAG_SKIP_PROCESS (1u << 1u)
#define RSPAMD_TASK_FLAG_SKIP (1u << 2u)
#define RSPAMD_TASK_FLAG_PASS_ALL (1u << 3u)
#define RSPAMD_TASK_FLAG_NO_LOG (1u << 4u)
#define RSPAMD_TASK_FLAG_NO_IP (1u << 5u)
#define RSPAMD_TASK_FLAG_PROCESSING (1u << 6u)
#define RSPAMD_TASK_FLAG_GTUBE (1u << 7u)
#define RSPAMD_TASK_FLAG_FILE (1u << 8u)
#define RSPAMD_TASK_FLAG_NO_STAT (1u << 9u)
#define RSPAMD_TASK_FLAG_UNLEARN (1u << 10u)
#define RSPAMD_TASK_FLAG_ALREADY_LEARNED (1u << 11u)
#define RSPAMD_TASK_FLAG_LEARN_SPAM (1u << 12u)
#define RSPAMD_TASK_FLAG_LEARN_HAM (1u << 13u)
#define RSPAMD_TASK_FLAG_LEARN_AUTO (1u << 14u)
#define RSPAMD_TASK_FLAG_BROKEN_HEADERS (1u << 15u)
#define RSPAMD_TASK_FLAG_HAS_SPAM_TOKENS (1u << 16u)
#define RSPAMD_TASK_FLAG_HAS_HAM_TOKENS (1u << 17u)
#define RSPAMD_TASK_FLAG_EMPTY (1u << 18u)
#define RSPAMD_TASK_FLAG_PROFILE (1u << 19u)
#define RSPAMD_TASK_FLAG_GREYLISTED (1u << 20u)
#define RSPAMD_TASK_FLAG_OWN_POOL (1u << 21u)
#define RSPAMD_TASK_FLAG_SSL (1u << 22u)
#define RSPAMD_TASK_FLAG_BAD_UNICODE (1u << 23u)
#define RSPAMD_TASK_FLAG_MESSAGE_REWRITE (1u << 24u)
#define RSPAMD_TASK_FLAG_MAX_SHIFT (24u)


/* Request has a JSON control block */
#define RSPAMD_TASK_PROTOCOL_FLAG_HAS_CONTROL (1u << 0u)
/* Request has been done by a local client */
#define RSPAMD_TASK_PROTOCOL_FLAG_LOCAL_CLIENT (1u << 1u)
/* Request has been sent via milter */
#define RSPAMD_TASK_PROTOCOL_FLAG_MILTER (1u << 2u)
/* Compress protocol reply */
#define RSPAMD_TASK_PROTOCOL_FLAG_COMPRESSED (1u << 3u)
/* Include all URLs */
#define RSPAMD_TASK_PROTOCOL_FLAG_EXT_URLS (1u << 4u)
/* Client allows body block (including headers in no FLAG_MILTER) */
#define RSPAMD_TASK_PROTOCOL_FLAG_BODY_BLOCK (1u << 5u)
/* Emit groups information */
#define RSPAMD_TASK_PROTOCOL_FLAG_GROUPS (1u << 6u)
#define RSPAMD_TASK_PROTOCOL_FLAG_MAX_SHIFT (6u)

#define RSPAMD_TASK_IS_SKIPPED(task) (((task)->flags & RSPAMD_TASK_FLAG_SKIP))
#define RSPAMD_TASK_IS_SPAMC(task) (((task)->cmd == CMD_CHECK_SPAMC))
#define RSPAMD_TASK_IS_PROCESSED(task) (((task)->processed_stages & RSPAMD_TASK_STAGE_DONE))
#define RSPAMD_TASK_IS_CLASSIFIED(task) (((task)->processed_stages & RSPAMD_TASK_STAGE_CLASSIFIERS))
#define RSPAMD_TASK_IS_EMPTY(task) (((task)->flags & RSPAMD_TASK_FLAG_EMPTY))
#define RSPAMD_TASK_IS_PROFILING(task) (((task)->flags & RSPAMD_TASK_FLAG_PROFILE))
#define RSPAMD_TASK_IS_MIME(task) (((task)->flags & RSPAMD_TASK_FLAG_MIME))

struct rspamd_email_address;
struct rspamd_lang_detector;
enum rspamd_newlines_type;
struct rspamd_message;

struct rspamd_task_data_storage {
	const gchar *begin;
	gsize len;
	gchar *fpath;
};

struct rspamd_request_header_chain {
	rspamd_ftok_t *hdr;
	struct rspamd_request_header_chain *next;
};

__KHASH_TYPE (rspamd_req_headers_hash, rspamd_ftok_t *, struct rspamd_request_header_chain *)

/**
 * Worker task structure
 */
struct rspamd_task {
	struct rspamd_worker *worker;                    /**< pointer to worker object						*/
	enum rspamd_command cmd;                        /**< command										*/
	gint sock;                                      /**< socket descriptor								*/
	guint32 dns_requests;                           /**< number of DNS requests per this task			*/
	guint32 flags;                                  /**< Bit flags										*/
	guint32 protocol_flags;
	guint32 processed_stages;                            /**< bits of stages that are processed			*/
	gchar *helo;                                    /**< helo header value								*/
	gchar *queue_id;                                /**< queue id if specified							*/
	rspamd_inet_addr_t *from_addr;                    /**< from addr for a task							*/
	rspamd_inet_addr_t *client_addr;                /**< address of connected socket					*/
	gchar *deliver_to;                                /**< address to deliver								*/
	gchar *user;                                    /**< user to deliver								*/
	const gchar *hostname;                            /**< hostname reported by MTA						*/
	khash_t(rspamd_req_headers_hash) *request_headers; /**< HTTP headers in a request						*/
	struct rspamd_task_data_storage msg;            /**< message buffer									*/
	struct rspamd_http_connection *http_conn;        /**< HTTP server connection							*/
	struct rspamd_async_session *s;                /**< async session object							*/
	struct rspamd_scan_result *result;            /**< Metric result									*/
	GHashTable *lua_cache;                            /**< cache of lua objects							*/
	GPtrArray *tokens;                                /**< statistics tokens */
	GArray *meta_words;                                /**< rspamd_stat_token_t produced from meta headers
														(e.g. Subject) */

	GPtrArray *rcpt_envelope;                        /**< array of rspamd_email_address					*/
	struct rspamd_email_address *from_envelope;
	struct rspamd_email_address *from_envelope_orig;

	ucl_object_t *messages;                            /**< list of messages that would be reported		*/
	struct rspamd_re_runtime *re_rt;                /**< regexp runtime									*/
	GPtrArray *stat_runtimes;                        /**< backend runtime							*/
	struct rspamd_config *cfg;                        /**< pointer to config object						*/
	GError *err;
	rspamd_mempool_t *task_pool;                    /**< memory pool for task							*/
	double time_real_finish;
	ev_tstamp task_timestamp;

	gboolean (*fin_callback) (struct rspamd_task *task, void *arg);
	/**< callback for filters finalizing					*/
	void *fin_arg;                                    /**< argument for fin callback						*/

	struct rspamd_dns_resolver *resolver;            /**< DNS resolver									*/
	struct ev_loop *event_loop;                        /**< Event base										*/
	struct ev_timer timeout_ev;                        /**< Global task timeout							*/
	struct ev_io guard_ev;                            /**< Event for input sanity guard 					*/

	gpointer checkpoint;                            /**< Opaque checkpoint data							*/
	ucl_object_t *settings;                            /**< Settings applied to task						*/
	struct rspamd_config_settings_elt *settings_elt;    /**< preprocessed settings id elt				*/

	const gchar *classifier;                        /**< Classifier to learn (if needed)				*/
	struct rspamd_lang_detector *lang_det;            /**< Languages detector								*/
	struct rspamd_message *message;
};

/**
 * Construct new task for worker
 */
struct rspamd_task *rspamd_task_new (struct rspamd_worker *worker,
									 struct rspamd_config *cfg,
									 rspamd_mempool_t *pool,
									 struct rspamd_lang_detector *lang_det,
									 struct ev_loop *event_loop,
									 gboolean debug_mem);

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
								   struct rspamd_http_message *msg,
								   const gchar *start, gsize len);

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
struct rspamd_email_address *rspamd_task_get_sender (struct rspamd_task *task);

/**
 * Return addresses in the following precedence:
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
struct rspamd_scan_result;

gdouble rspamd_task_get_required_score (struct rspamd_task *task,
										struct rspamd_scan_result *m);

/**
 * Returns the first header as value for a header
 * @param task
 * @param name
 * @return
 */
rspamd_ftok_t *rspamd_task_get_request_header (struct rspamd_task *task,
											   const gchar *name);

/**
 * Returns all headers with the specific name
 * @param task
 * @param name
 * @return
 */
struct rspamd_request_header_chain *rspamd_task_get_request_header_multiple (
		struct rspamd_task *task,
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

/**
 * Set profiling value for a specific key
 * @param task
 * @param key
 * @param value
 */
void rspamd_task_profile_set (struct rspamd_task *task, const gchar *key,
							  gdouble value);

/**
 * Get value for a specific profiling key
 * @param task
 * @param key
 * @return
 */
gdouble *rspamd_task_profile_get (struct rspamd_task *task, const gchar *key);

/**
 * Sets finishing time for a task if not yet set
 * @param task
 * @return
 */
gboolean rspamd_task_set_finish_time (struct rspamd_task *task);

/**
 * Returns task processing stage name
 * @param stg
 * @return
 */
const gchar *rspamd_task_stage_name (enum rspamd_task_stage stg);

/*
 * Called on forced timeout
 */
void rspamd_task_timeout (EV_P_ ev_timer *w, int revents);

/*
 * Called on unexpected IO error (e.g. ECONNRESET)
 */
void rspamd_worker_guard_handler (EV_P_ ev_io *w, int revents);

#ifdef  __cplusplus
}
#endif

#endif /* TASK_H_ */
