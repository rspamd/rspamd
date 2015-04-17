#ifndef RSPAMD_UTIL_H
#define RSPAMD_UTIL_H

#include "config.h"
#include "mem_pool.h"
#include "printf.h"
#include "fstring.h"
#include "ucl.h"
#include "addr.h"

struct rspamd_config;
struct rspamd_main;
struct workq;

/**
 * Create generic socket
 * @param af address family
 * @param type socket type
 * @param protocol socket protocol
 * @param async set non-blocking on a socket
 * @return socket FD or -1 in case of error
 */
gint rspamd_socket_create (gint af, gint type, gint protocol, gboolean async);
/*
 * Create socket and bind or connect it to specified address and port
 */
gint rspamd_socket_tcp (struct addrinfo *, gboolean is_server, gboolean async);
/*
 * Create socket and bind or connect it to specified address and port
 */
gint rspamd_socket_udp (struct addrinfo *, gboolean is_server, gboolean async);

/*
 * Create and bind or connect unix socket
 */
gint rspamd_socket_unix (const gchar *,
	struct sockaddr_un *,
	gint type,
	gboolean is_server,
	gboolean async);

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param type type of socket (SO_STREAM or SO_DGRAM)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
gint rspamd_socket (const gchar *credits, guint16 port, gint type,
	gboolean async, gboolean is_server, gboolean try_resolve);

/**
 * Make a universal sockets
 * @param credits host, ip or path to unix socket (several items may be separated by ',')
 * @param port port (used for network sockets)
 * @param type type of socket (SO_STREAM or SO_DGRAM)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
GList * rspamd_sockets_list (const gchar *credits,
	guint16 port,
	gint type,
	gboolean async,
	gboolean is_server,
	gboolean try_resolve);
/*
 * Create socketpair
 */
gint rspamd_socketpair (gint pair[2]);

/*
 * Write pid to file
 */
gint rspamd_write_pid (struct rspamd_main *);

/*
 * Make specified socket non-blocking
 */
gint rspamd_socket_nonblocking (gint);
/*
 * Make specified socket blocking
 */
gint rspamd_socket_blocking (gint);

/*
 * Poll a sync socket for specified events
 */
gint rspamd_socket_poll (gint fd, gint timeout, short events);

/*
 * Init signals
 */
#ifdef HAVE_SA_SIGINFO
void rspamd_signals_init (struct sigaction *sa, void (*sig_handler)(gint,
	siginfo_t *,
	void *));
#else
void rspamd_signals_init (struct sigaction *sa, void (*sig_handler)(gint));
#endif

/*
 * Send specified signal to each worker
 */
void rspamd_pass_signal (GHashTable *, gint );
/*
 * Convert string to lowercase
 */
void rspamd_str_lc (gchar *str, guint size);
void rspamd_str_lc_utf8 (gchar *str, guint size);

#ifndef HAVE_SETPROCTITLE
/*
 * Process title utility functions
 */
gint init_title (gint argc, gchar *argv[], gchar *envp[]);
gint setproctitle (const gchar *fmt, ...);
#endif

#ifndef HAVE_PIDFILE
/*
 * Pidfile functions from FreeBSD libutil code
 */
typedef struct rspamd_pidfh_s {
	gint pf_fd;
#ifdef HAVE_PATH_MAX
	gchar pf_path[PATH_MAX + 1];
#elif defined(HAVE_MAXPATHLEN)
	gchar pf_path[MAXPATHLEN + 1];
#else
	gchar pf_path[1024 + 1];
#endif
	dev_t pf_dev;
	ino_t pf_ino;
} rspamd_pidfh_t;
rspamd_pidfh_t * rspamd_pidfile_open (const gchar *path,
	mode_t mode,
	pid_t *pidptr);
gint rspamd_pidfile_write (rspamd_pidfh_t *pfh);
gint rspamd_pidfile_close (rspamd_pidfh_t *pfh);
gint rspamd_pidfile_remove (rspamd_pidfh_t *pfh);
#else
typedef struct pidfh rspamd_pidfh_t;
#define rspamd_pidfile_open pidfile_open
#define rspamd_pidfile_write pidfile_write
#define rspamd_pidfile_close pidfile_close
#define rspamd_pidfile_remove pidfile_remove
#endif

/*
 * Replace %r with rcpt value and %f with from value, new string is allocated in pool
 */
gchar * resolve_stat_filename (rspamd_mempool_t *pool,
	gchar *pattern,
	gchar *rcpt,
	gchar *from);
#ifdef HAVE_CLOCK_GETTIME
/*
 * Calculate check time with specified resolution of timer
 */
const gchar * calculate_check_time (struct timeval *tv,
	struct timespec *begin,
	gint resolution,
	guint32 *scan_ms);
#else
const gchar * calculate_check_time (struct timeval *begin,
	gint resolution,
	guint32 *scan_ms);
#endif

/*
 * File locking functions
 */
gboolean rspamd_file_lock (gint fd, gboolean async);
gboolean rspamd_file_unlock (gint fd, gboolean async);

/*
 * Hash table utility functions for case insensitive hashing
 */
guint rspamd_strcase_hash (gconstpointer key);
gboolean rspamd_strcase_equal (gconstpointer v, gconstpointer v2);

/*
 * Hash table utility functions for case sensitive hashing
 */
guint rspamd_str_hash (gconstpointer key);
gboolean rspamd_str_equal (gconstpointer v, gconstpointer v2);


/*
 * Hash table utility functions for hashing fixed strings
 */
guint rspamd_fstring_icase_hash (gconstpointer key);
gboolean rspamd_fstring_icase_equal (gconstpointer v, gconstpointer v2);

/*
 * Google perf-tools initialization function
 */
void gperf_profiler_init (struct rspamd_config *cfg, const gchar *descr);

/*
 * Workarounds for older versions of glib
 */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void g_ptr_array_unref (GPtrArray *array);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 14))
void g_queue_clear (GQueue *queue);
#endif


/**
 * Copy src to dest limited to len, in compare with standart strlcpy(3) rspamd strlcpy does not
 * traverse the whole string and it is possible to use it for non NULL terminated strings. This is
 * more like memccpy(dst, src, size, '\0')
 *
 * @param dst destination string
 * @param src source string
 * @param siz length of destination buffer
 * @return bytes copied
 */
gsize rspamd_strlcpy (gchar *dst, const gchar *src, gsize siz);

/**
 * Lowercase strlcpy variant
 * @param dst
 * @param src
 * @param siz
 * @return
 */
gsize rspamd_strlcpy_tolower (gchar *dst, const gchar *src, gsize siz);

/*
 * Convert milliseconds to timeval fields
 */
#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = \
									  ((msec) - (tv)->tv_sec * 1000) * 1000; \
} while (0)
#define double_to_tv(dbl, tv) do { (tv)->tv_sec = (int)(dbl); (tv)->tv_usec = \
									   ((dbl) - (int)(dbl)) * 1000 * 1000; \
} while (0)
#define tv_to_msec(tv) ((tv)->tv_sec * 1000LLU + (tv)->tv_usec / 1000LLU)
#define ts_to_usec(ts) ((ts)->tv_sec * 1000000LLU +							\
	(ts)->tv_nsec / 1000LLU)

guint rspamd_url_hash (gconstpointer u);

/* Compare two emails for building emails hash */
gboolean rspamd_emails_cmp (gconstpointer a, gconstpointer b);

/* Compare two urls for building emails hash */
gboolean rspamd_urls_cmp (gconstpointer a, gconstpointer b);

/*
 * Find string find in string s ignoring case
 */
gchar * rspamd_strncasestr (const gchar *s, const gchar *find, gint len);

/*
 * Try to convert string of length to long
 */
gboolean rspamd_strtol (const gchar *s, gsize len, glong *value);

/*
 * Try to convert string of length to unsigned long
 */
gboolean rspamd_strtoul (const gchar *s, gsize len, gulong *value);

/**
 * Try to allocate a file on filesystem (using fallocate or posix_fallocate)
 * @param fd descriptor
 * @param offset offset of file
 * @param len length to allocate
 * @return -1 in case of failure
 */
gint rspamd_fallocate (gint fd, off_t offset, off_t len);

/**
 * Utils for working with threads to be compatible with all glib versions
 */
typedef struct rspamd_mutex_s {
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	GMutex mtx;
#else
	GStaticMutex mtx;
#endif
} rspamd_mutex_t;

typedef struct rspamd_rwlock_s {
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	GRWLock rwlock;
#else
	GStaticRWLock rwlock;
#endif
} rspamd_rwlock_t;


/**
 * Create new mutex
 * @return mutex or NULL
 */
rspamd_mutex_t * rspamd_mutex_new (void);

/**
 * Lock mutex
 * @param mtx
 */
void rspamd_mutex_lock (rspamd_mutex_t *mtx);

/**
 * Unlock mutex
 * @param mtx
 */
void rspamd_mutex_unlock (rspamd_mutex_t *mtx);

/**
 * Clear rspamd mutex
 * @param mtx
 */
void rspamd_mutex_free (rspamd_mutex_t *mtx);

/**
 * Create new rwloc
 * @return
 */
rspamd_rwlock_t * rspamd_rwlock_new (void);

/**
 * Lock rwlock for writing
 * @param mtx
 */
void rspamd_rwlock_writer_lock (rspamd_rwlock_t *mtx);

/**
 * Lock rwlock for reading
 * @param mtx
 */
void rspamd_rwlock_reader_lock (rspamd_rwlock_t *mtx);

/**
 * Unlock rwlock from writing
 * @param mtx
 */
void rspamd_rwlock_writer_unlock (rspamd_rwlock_t *mtx);

/**
 * Unlock rwlock from reading
 * @param mtx
 */
void rspamd_rwlock_reader_unlock (rspamd_rwlock_t *mtx);

/**
 * Free rwlock
 * @param mtx
 */
void rspamd_rwlock_free (rspamd_rwlock_t *mtx);

static inline void
rspamd_cond_wait (GCond *cond, rspamd_mutex_t *mtx)
{
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION > 30))
	g_cond_wait (cond, &mtx->mtx);
#else
	g_cond_wait (cond, g_static_mutex_get_mutex (&mtx->mtx));
#endif
}

/**
 * Create new named thread
 * @param name name pattern
 * @param func function to start
 * @param data data to pass to function
 * @param err error pointer
 * @return new thread object that can be joined
 */
GThread * rspamd_create_thread (const gchar *name,
	GThreadFunc func,
	gpointer data,
	GError **err);

/**
 * Deep copy of one hash table to another
 * @param src source hash
 * @param dst destination hash
 * @param key_copy_func function called to copy or modify keys (or NULL)
 * @param value_copy_func function called to copy or modify values (or NULL)
 * @param ud user data for copy functions
 */
void rspamd_hash_table_copy (GHashTable *src, GHashTable *dst,
	gpointer (*key_copy_func)(gconstpointer data, gpointer ud),
	gpointer (*value_copy_func)(gconstpointer data, gpointer ud),
	gpointer ud);

/**
 * Utility function to provide mem_pool copy for rspamd_hash_table_copy function
 * @param data string to copy
 * @param ud memory pool to use
 * @return
 */
gpointer rspamd_str_pool_copy (gconstpointer data, gpointer ud);

/**
 * Read passphrase from tty
 * @param buf buffer to fill with a password
 * @param size size of the buffer
 * @param rwflag unused flag
 * @param key unused key
 * @return size of password read
 */
gint rspamd_read_passphrase (gchar *buf, gint size, gint rwflag, gpointer key);

/**
 * Emit UCL object to gstring
 * @param obj object to emit
 * @param emit_type emitter type
 * @param target target string
 */
void rspamd_ucl_emit_gstring (ucl_object_t *obj,
	enum ucl_emitter emit_type,
	GString *target);

/**
 * Encode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 encoding of a specified string
 */
gchar * rspamd_encode_base32 (const guchar *in, gsize inlen);

/**
 * Decode string using base32 encoding
 * @param in input
 * @param inlen input length
 * @return freshly allocated base32 decoded value or NULL if input is invalid
 */
guchar* rspamd_decode_base32 (const gchar *in, gsize inlen, gsize *outlen);

/**
 * Portably return the current clock ticks as seconds
 * @return
 */
gdouble rspamd_get_ticks (void);

/**
 * Special utility to help array freeing in rspamd_mempool
 * @param p
 */
void rspamd_ptr_array_free_hard (gpointer p);

/**
 * Special utility to help array freeing in rspamd_mempool
 * @param p
 */
void rspamd_array_free_hard (gpointer p);

/**
 * Initialize rspamd libraries
 */
void rspamd_init_libs (void);

#endif
