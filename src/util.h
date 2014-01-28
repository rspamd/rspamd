#ifndef RSPAMD_UTIL_H
#define RSPAMD_UTIL_H

#include "config.h"
#include "mem_pool.h"
#include "radix.h"
#include "statfile.h"
#include "printf.h"
#include "fstring.h"
#include "ucl.h"

struct config_file;
struct rspamd_main;
struct workq;
struct statfile;
struct classifier_config;

/**
 * Union that is used for storing sockaddrs
 */
union sa_union {
	struct sockaddr_storage ss;
	struct sockaddr sa;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
	struct sockaddr_un su;
};

/*
 * Create socket and bind or connect it to specified address and port
 */
gint make_tcp_socket (struct addrinfo *, gboolean is_server, gboolean async);
/*
 * Create socket and bind or connect it to specified address and port
 */
gint make_udp_socket (struct addrinfo *, gboolean is_server, gboolean async);
/*
 * Accept from socket
 */
gint accept_from_socket (gint listen_sock, struct sockaddr *addr, socklen_t *len);
/*
 * Create and bind or connect unix socket
 */
gint make_unix_socket (const gchar *, struct sockaddr_un *, gint type, gboolean is_server, gboolean async);

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param type type of socket (SO_STREAM or SO_DGRAM)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
gint make_universal_socket (const gchar *credits, guint16 port, gint type,
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
GList* make_universal_sockets_list (const gchar *credits, guint16 port, gint type,
		gboolean async, gboolean is_server, gboolean try_resolve);
/*
 * Create socketpair
 */
gint make_socketpair (gint pair[2]);

/*
 * Write pid to file
 */
gint write_pid (struct rspamd_main *);

/*
 * Make specified socket non-blocking
 */
gint make_socket_nonblocking (gint);
/*
 * Make specified socket blocking
 */
gint make_socket_blocking (gint);

/*
 * Poll a sync socket for specified events
 */
gint poll_sync_socket (gint fd, gint timeout, short events);

/*
 * Init signals
 */
#ifdef HAVE_SA_SIGINFO
void init_signals (struct sigaction *sa, void (*sig_handler)(gint, siginfo_t *, void *));
#else
void init_signals (struct sigaction *sa, void (*sig_handler)(gint));
#endif

/*
 * Send specified signal to each worker
 */
void pass_signal_worker (GHashTable *, gint );
/*
 * Convert string to lowercase
 */
void convert_to_lowercase (gchar *str, guint size);

#ifndef HAVE_SETPROCTITLE
/*
 * Process title utility functions
 */
gint init_title(gint argc, gchar *argv[], gchar *envp[]);
gint setproctitle(const gchar *fmt, ...);
#endif

#ifndef HAVE_PIDFILE
/*
 * Pidfile functions from FreeBSD libutil code
 */
typedef struct rspamd_pidfh_s {
	gint pf_fd;
#ifdef HAVE_PATH_MAX
	gchar    pf_path[PATH_MAX + 1];
#elif defined(HAVE_MAXPATHLEN)
	gchar    pf_path[MAXPATHLEN + 1];
#else
	gchar    pf_path[1024 + 1];
#endif
 	dev_t pf_dev;
 	ino_t   pf_ino;
} rspamd_pidfh_t;
rspamd_pidfh_t *rspamd_pidfile_open(const gchar *path, mode_t mode, pid_t *pidptr);
gint rspamd_pidfile_write(rspamd_pidfh_t *pfh);
gint rspamd_pidfile_close(rspamd_pidfh_t *pfh);
gint rspamd_pidfile_remove(rspamd_pidfh_t *pfh);
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
gchar* resolve_stat_filename (memory_pool_t *pool, gchar *pattern, gchar *rcpt, gchar *from);
#ifdef HAVE_CLOCK_GETTIME
/*
 * Calculate check time with specified resolution of timer
 */
const gchar* calculate_check_time (struct timeval *tv, struct timespec *begin, gint resolution, guint32 *scan_ms);
#else
const gchar* calculate_check_time (struct timeval *begin, gint resolution, guint32 *scan_ms);
#endif

/*
 * File locking functions
 */
gboolean lock_file (gint fd, gboolean async);
gboolean unlock_file (gint fd, gboolean async);

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
guint fstr_strcase_hash (gconstpointer key);
gboolean fstr_strcase_equal (gconstpointer v, gconstpointer v2);

/*
 * Google perf-tools initialization function
 */
void gperf_profiler_init (struct config_file *cfg, const gchar *descr);

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
#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = ((msec) - (tv)->tv_sec * 1000) * 1000; } while(0)
#define double_to_tv(dbl, tv) do { (tv)->tv_sec = (int)(dbl); (tv)->tv_usec = ((dbl) - (int)(dbl))*1000*1000; } while(0)
#define tv_to_msec(tv) (tv)->tv_sec * 1000 + (tv)->tv_usec / 1000

/* Compare two emails for building emails tree */
gint compare_email_func (gconstpointer a, gconstpointer b);

/* Compare two urls for building emails tree */
gint compare_url_func (gconstpointer a, gconstpointer b);

/*
 * Find string find in string s ignoring case
 */
gchar* rspamd_strncasestr (const gchar *s, const gchar *find, gint len);

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
 * Return worker's control structure by its type
 * @param type
 * @return worker's control structure or NULL
 */
extern worker_t* get_worker_by_type (GQuark type);

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
rspamd_mutex_t* rspamd_mutex_new (void);

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
rspamd_rwlock_t* rspamd_rwlock_new (void);

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
GThread* rspamd_create_thread (const gchar *name, GThreadFunc func, gpointer data, GError **err);

/**
 * Return 32bit murmur hash value for specified input
 * @param in input data
 * @param len length of the input data
 * @code
 *  MurmurHash3 was created by Austin Appleby  in 2008. The cannonical
 *  implementations are in C++ and placed in the public.
 *
 *    https://sites.google.com/site/murmurhash/
 *
 *  Seungyoung Kim has ported it's cannonical implementation to C language
 *  in 2012 and published it as a part of qLibc component.
 * @endcode
 * @return
 */
guint32 murmur32_hash (const guint8 *in, gsize len);

/**
 * Return 32bit murmur hash value for specified input
 * @param in input data
 * @param len length of the input data
 * @param out array of 2 guint64 variables
 * @code
 *  MurmurHash3 was created by Austin Appleby  in 2008. The cannonical
 *  implementations are in C++ and placed in the public.
 *
 *    https://sites.google.com/site/murmurhash/
 *
 *  Seungyoung Kim has ported it's cannonical implementation to C language
 *  in 2012 and published it as a part of qLibc component.
 * @endcode
 * @return
 */
void murmur128_hash (const guint8 *in, gsize len, guint64 out[]);

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
 * Parse ipv4 address with optional mask in CIDR format
 * @param line cidr notation of ipv4 address
 * @param ina destination address
 * @param mask destination mask
 * @return
 */
gboolean parse_ipmask_v4 (const char *line, struct in_addr *ina, int *mask);

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
 * Seed glib prng using openssl if possible
 */
void rspamd_prng_seed (void);

/**
 * Generate random bytes using the most suitable generator
 * @param buf
 * @param buflen
 */
void rspamd_random_bytes (gchar *buf, gsize buflen);

/**
 * Check whether specified ip is valid (not INADDR_ANY or INADDR_NONE) for ipv4 or ipv6
 * @param ptr pointer to struct in_addr or struct in6_addr
 * @param af address family (AF_INET or AF_INET6)
 * @return TRUE if the address is valid
 */
gboolean rspamd_ip_is_valid (void *ptr, int af);

/**
 * Emit UCL object to gstring
 * @param obj object to emit
 * @param emit_type emitter type
 * @param target target string
 */
void rspamd_ucl_emit_gstring (ucl_object_t *obj, enum ucl_emitter emit_type, GString *target);

#endif
