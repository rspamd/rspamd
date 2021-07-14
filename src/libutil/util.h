#ifndef RSPAMD_UTIL_H
#define RSPAMD_UTIL_H

#include "config.h"
#include "mem_pool.h"
#include "printf.h"
#include "fstring.h"
#include "addr.h"
#include "str_util.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "contrib/libev/ev.h"
#include <time.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_config;

enum rspamd_exception_type {
	RSPAMD_EXCEPTION_NEWLINE = 0,
	RSPAMD_EXCEPTION_URL,
	RSPAMD_EXCEPTION_GENERIC,
};
/**
 * Structure to point exception in text from processing
 */
struct rspamd_process_exception {
	goffset pos;
	guint len;
	gpointer ptr;
	enum rspamd_exception_type type;
};

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


/*
 * Create socketpair
 */
gboolean rspamd_socketpair (gint pair[2], gint af);

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

void rspamd_signals_init (struct sigaction *sa, void (*sig_handler) (gint,
																	 siginfo_t *,
																	 void *));

#else
void rspamd_signals_init (struct sigaction *sa, void (*sig_handler)(gint));
#endif

#ifndef HAVE_SETPROCTITLE

/*
 * Process title utility functions
 */
gint init_title (rspamd_mempool_t *pool, gint argc, gchar *argv[], gchar *envp[]);

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

rspamd_pidfh_t *rspamd_pidfile_open (const gchar *path,
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
gchar *resolve_stat_filename (rspamd_mempool_t *pool,
							  gchar *pattern,
							  gchar *rcpt,
							  gchar *from);

const gchar *
rspamd_log_check_time (gdouble start, gdouble end, gint resolution);

/*
 * File locking functions
 */
gboolean rspamd_file_lock (gint fd, gboolean async);

gboolean rspamd_file_unlock (gint fd, gboolean async);

/*
 * Workarounds for older versions of glib
 */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void g_ptr_array_unref (GPtrArray *array);
gboolean g_int64_equal (gconstpointer v1, gconstpointer v2);
guint g_int64_hash (gconstpointer v);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 14))
void g_queue_clear (GQueue *queue);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 32))
void g_queue_free_full (GQueue *queue, GDestroyNotify free_func);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 40))
void g_ptr_array_insert (GPtrArray *array, gint index_, gpointer data);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 30))
GPtrArray* g_ptr_array_new_full (guint reserved_size,
		GDestroyNotify element_free_func);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 32))
const gchar *g_environ_getenv (gchar **envp, const gchar *variable);
#endif

/*
 * Convert milliseconds to timeval fields
 */
#define msec_to_tv(msec, tv) do { (tv)->tv_sec = (msec) / 1000; (tv)->tv_usec = \
                                      ((msec) - (tv)->tv_sec * 1000) * 1000; \
} while (0)
#define double_to_tv(dbl, tv) do { (tv)->tv_sec = (int)(dbl); (tv)->tv_usec = \
                                       ((dbl) - (int)(dbl)) * 1000 * 1000; \
} while (0)
#define double_to_ts(dbl, ts) do { (ts)->tv_sec = (int)(dbl); (ts)->tv_nsec = \
                                       ((dbl) - (int)(dbl)) * 1e9; \
} while (0)
#define tv_to_msec(tv) ((tv)->tv_sec * 1000LLU + (tv)->tv_usec / 1000LLU)
#define tv_to_double(tv) ((double)(tv)->tv_sec + (tv)->tv_usec / 1.0e6)
#define ts_to_usec(ts) ((ts)->tv_sec * 1000000LLU +                            \
    (ts)->tv_nsec / 1000LLU)
#define ts_to_double(tv) ((double)(tv)->tv_sec + (tv)->tv_nsec / 1.0e9)

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


/**
 * Create new mutex
 * @return mutex or NULL
 */
rspamd_mutex_t *rspamd_mutex_new (void);

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
 * Deep copy of one hash table to another
 * @param src source hash
 * @param dst destination hash
 * @param key_copy_func function called to copy or modify keys (or NULL)
 * @param value_copy_func function called to copy or modify values (or NULL)
 * @param ud user data for copy functions
 */
void rspamd_hash_table_copy (GHashTable *src, GHashTable *dst,
							 gpointer (*key_copy_func) (gconstpointer data, gpointer ud),
							 gpointer (*value_copy_func) (gconstpointer data, gpointer ud),
							 gpointer ud);


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
 * Portably return the current clock ticks as seconds
 * @return
 */
gdouble rspamd_get_ticks (gboolean rdtsc_ok);

/**
 * Portably return the current virtual clock ticks as seconds
 * @return
 */
gdouble rspamd_get_virtual_ticks (void);


/**
 * Return the real timestamp as unixtime
 */
gdouble rspamd_get_calendar_ticks (void);

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
 * Special utility to help GString freeing in rspamd_mempool
 * @param p
 */
void rspamd_gstring_free_hard (gpointer p);

/**
 * Special utility to help GError freeing in rspamd_mempool
 * @param p
 */
void rspamd_gerror_free_maybe (gpointer p);

/**
 * Special utility to help GString freeing (without freeing the memory segment) in rspamd_mempool
 * @param p
 */
void rspamd_gstring_free_soft (gpointer p);


/**
 * Returns some statically initialized random hash seed
 * @return hash seed
 */
guint64 rspamd_hash_seed (void);

/**
 * Returns random hex string of the specified length
 * @param buf
 * @param len
 */
void rspamd_random_hex (guchar *buf, guint64 len);

/**
 * Returns
 * @param pattern pattern to create (should end with some number of X symbols), modified by this function
 * @return
 */
gint rspamd_shmem_mkstemp (gchar *pattern);

/**
 * Return jittered time value
 */
gdouble rspamd_time_jitter (gdouble in, gdouble jitter);

/**
 * Return random double in range [0..1)
 * @return
 */
gdouble rspamd_random_double (void);

/**
 * Return random double in range [0..1) using xoroshiro128+ algorithm (not crypto secure)
 * @return
 */
gdouble rspamd_random_double_fast (void);
gdouble rspamd_random_double_fast_seed (guint64 seed[4]);
guint64 rspamd_random_uint64_fast (void);

/**
 * Seed fast rng
 */
void rspamd_random_seed_fast (void);

/**
 * Constant time version of memcmp
 */
gboolean rspamd_constant_memcmp (const void *a, const void *b, gsize len);

/**
 * Open file without following symlinks or special stuff
 * @param fname filename
 * @param oflags open flags
 * @param mode mode to open
 * @return fd or -1 in case of error
 */
int rspamd_file_xopen (const char *fname, int oflags, guint mode,
					   gboolean allow_symlink);

/**
 * Map file without following symlinks or special stuff
 * @param fname filename
 * @param mode mode to open
 * @param size target size (must NOT be NULL)
 * @return pointer to memory (should be freed using munmap) or NULL in case of error
 */
gpointer rspamd_file_xmap (const char *fname, guint mode, gsize *size,
						   gboolean allow_symlink);

/**
 * Map named shared memory segment
 * @param fname filename
 * @param mode mode to open
 * @param size target size (must NOT be NULL)
 * @return pointer to memory (should be freed using munmap) or NULL in case of error
 */
gpointer rspamd_shmem_xmap (const char *fname, guint mode,
							gsize *size);

/**
 * Normalize probabilities using polynomial function
 * @param x probability (bias .. 1)
 * @return
 */
gdouble rspamd_normalize_probability (gdouble x, gdouble bias);

/**
 * Converts struct tm to time_t
 * @param tm
 * @param tz timezone in format (hours * 100) + minutes
 * @return
 */
guint64 rspamd_tm_to_time (const struct tm *tm, glong tz);

/**
 * Splits unix timestamp into struct tm using GMT timezone
 * @param ts
 * @param dest
 */
void rspamd_gmtime (gint64 ts, struct tm *dest);

/**
 * Split unix timestamp into struct tm using local timezone
 * @param ts
 * @param dest
 */
void rspamd_localtime (gint64 ts, struct tm *dest);

#define PTR_ARRAY_FOREACH(ar, i, cur) for ((i) = 0; (ar) != NULL && (i) < (ar)->len && (((cur) = (__typeof__(cur))g_ptr_array_index((ar), (i))) || 1); ++(i))

/**
 * Compresses the input string using gzip+zlib. Old string is replaced and freed
 * if compressed. If not compressed it is untouched.
 * @param in
 * @return TRUE if a string has been compressed
 */
gboolean rspamd_fstring_gzip (rspamd_fstring_t **in);

/**
 * Perform globbing searching for the specified path. Allow recursion,
 * returns an error if maximum nesting is reached.
 * @param pattern
 * @param recursive
 * @param err
 * @return GPtrArray of gchar *, elements are freed when array is freed
 */
GPtrArray *rspamd_glob_path (const gchar *dir,
							 const gchar *pattern,
							 gboolean recursive,
							 GError **err);

struct rspamd_counter_data {
	float mean;
	float stddev;
	guint64 number;
};

/**
 * Sets counter's data using exponential moving average
 * @param cd counter
 * @param value new counter value
 * @param alpha decay coefficient (0..1)
 * @return new counter value
 */
float rspamd_set_counter_ema (struct rspamd_counter_data *cd,
							   float value,
							   float alpha);

/**
 * Sets counter's data using flat moving average
 * @param cd counter
 * @param value new counter value
 * @return new counter value
 */
double rspamd_set_counter (struct rspamd_counter_data *cd,
						   gdouble value);

/**
 * Shuffle elements in an array inplace
 * @param ar
 */
void rspamd_ptr_array_shuffle (GPtrArray *ar);

enum rspamd_pbkdf_version_id {
	RSPAMD_PBKDF_ID_V1 = 1,
	RSPAMD_PBKDF_ID_V2 = 2,
	RSPAMD_PBKDF_ID_MAX
};

struct rspamd_controller_pbkdf {
	const char *name;
	const char *alias;
	const char *description;
	int type; /* enum rspamd_cryptobox_pbkdf_type */
	gint id;
	guint complexity;
	gsize salt_len;
	gsize key_len;
};

extern const struct rspamd_controller_pbkdf pbkdf_list[];

#ifdef  __cplusplus
}
#endif

#endif
