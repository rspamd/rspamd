/**
 * @file buffer.h
 * Implements buffered IO
 */

#ifndef RSPAMD_BUFFER_H
#define RSPAMD_BUFFER_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"

typedef gboolean (*dispatcher_read_callback_t)(f_str_t *in, void *user_data);
typedef gboolean (*dispatcher_write_callback_t)(void *user_data);
typedef void (*dispatcher_err_callback_t)(GError *err, void *user_data);

/**
 * Types of IO handling
 */
enum io_policy {
	BUFFER_LINE,													/**< call handler when we have line ready */
	BUFFER_CHARACTER,												/**< call handler when we have some characters */
	BUFFER_ANY														/**< call handler whenever we got data in buffer */
};

/**
 * Buffer structure
 */
typedef struct rspamd_buffer_s {
	f_str_t *data;													/**< buffer logic			*/
	gchar *pos;														/**< current position		*/
} rspamd_buffer_t;

typedef struct rspamd_io_dispatcher_s {
	rspamd_buffer_t *in_buf;										/**< input buffer			*/
	GQueue *out_buffers;											/**< out buffers chain		*/
	struct timeval *tv;												/**< io timeout				*/
	struct event *ev;												/**< libevent io event		*/
	memory_pool_t *pool;											/**< where to store data	*/
	enum io_policy policy;											/**< IO policy				*/
	size_t nchars;													/**< how many chars to read	*/
	gint fd;															/**< descriptor				*/
	guint32 peer_addr;												/**< address of peer for debugging */
	gboolean wanna_die;												/**< if dispatcher should be stopped */
	dispatcher_read_callback_t read_callback;						/**< read callback			*/
	dispatcher_write_callback_t write_callback;						/**< write callback			*/
	dispatcher_err_callback_t err_callback;							/**< error callback			*/
	void *user_data;												/**< user's data for callbacks */
	off_t offset;													/**< for sendfile use		*/
	size_t file_size;
	gint sendfile_fd;
	gboolean in_sendfile;											/**< whether buffer is in sendfile mode */
	gboolean strip_eol;												/**< strip or not line ends in BUFFER_LINE policy */
	gboolean is_restored;											/**< call a callback when dispatcher is restored */
	struct event_base *ev_base;										/**< event base for io operations */
#ifndef HAVE_SENDFILE
	void *map;
#endif
} rspamd_io_dispatcher_t;

/**
 * Creates rspamd IO dispatcher for specified descriptor
 * @param fd descriptor to IO
 * @param policy IO policy
 * @param read_cb read callback handler
 * @param write_cb write callback handler
 * @param err_cb error callback handler
 * @param tv IO timeout
 * @param user_data pointer to user's data
 * @return new dispatcher object or NULL in case of failure
 */
rspamd_io_dispatcher_t* rspamd_create_dispatcher (struct event_base *base, gint fd,
												  enum io_policy policy,
												  dispatcher_read_callback_t read_cb,
												  dispatcher_write_callback_t write_cb,
												  dispatcher_err_callback_t err_cb,
												  struct timeval *tv,
												  void *user_data);

/**
 * Set new policy for dispatcher
 * @param d pointer to dispatcher's object
 * @param policy IO policy
 * @param nchars number of characters in buffer for character policy
 */
void rspamd_set_dispatcher_policy (rspamd_io_dispatcher_t *d, 
												  enum io_policy policy,
												  size_t nchars);

/**
 * Write data when it would be possible
 * @param d pointer to dispatcher's object
 * @param data data to write
 * @param len length of data
 */
gboolean rspamd_dispatcher_write (rspamd_io_dispatcher_t *d,
												  void *data,
												  size_t len, gboolean delayed, gboolean allocated) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Send specified descriptor to dispatcher
 * @param d pointer to dispatcher's object
 * @param fd descriptor of file
 * @param len length of data
 */
gboolean rspamd_dispatcher_sendfile (rspamd_io_dispatcher_t *d, gint fd, size_t len) G_GNUC_WARN_UNUSED_RESULT;

/**
 * Pause IO events on dispatcher
 * @param d pointer to dispatcher's object
 */
void rspamd_dispatcher_pause (rspamd_io_dispatcher_t *d);

/**
 * Restore IO events on dispatcher
 * @param d pointer to dispatcher's object
 */
void rspamd_dispatcher_restore (rspamd_io_dispatcher_t *d);

/**
 * Frees dispatcher object
 * @param dispatcher pointer to dispatcher's object
 */
void rspamd_remove_dispatcher (rspamd_io_dispatcher_t *dispatcher);

#endif
