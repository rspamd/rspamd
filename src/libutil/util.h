/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

#include <time.h>

#ifdef __cplusplus
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
	unsigned int len;
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
int rspamd_socket_create(int af, int type, int protocol, gboolean async);

/*
 * Create socket and bind or connect it to specified address and port
 */
int rspamd_socket_tcp(struct addrinfo *, gboolean is_server, gboolean async);

/*
 * Create socket and bind or connect it to specified address and port
 */
int rspamd_socket_udp(struct addrinfo *, gboolean is_server, gboolean async);

/*
 * Create and bind or connect unix socket
 */
int rspamd_socket_unix(const char *,
					   struct sockaddr_un *,
					   int type,
					   gboolean is_server,
					   gboolean async);

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param type type of socket (SO_STREAM or SO_DGRAM)
 * @param async make this socket async
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
int rspamd_socket(const char *credits, uint16_t port, int type,
				  gboolean async, gboolean is_server, gboolean try_resolve);


/*
 * Create socketpair
 */
gboolean rspamd_socketpair(int pair[2], int af);

/*
 * Make specified socket non-blocking
 */
int rspamd_socket_nonblocking(int);

/*
 * Make specified socket blocking
 */
int rspamd_socket_blocking(int);

/*
 * Poll a sync socket for specified events
 */
int rspamd_socket_poll(int fd, int timeout, short events);

/*
 * Init signals
 */
#ifdef HAVE_SA_SIGINFO

void rspamd_signals_init(struct sigaction *sa, void (*sig_handler)(int,
																   siginfo_t *,
																   void *));

#else
void rspamd_signals_init(struct sigaction *sa, void (*sig_handler)(int));
#endif

/*
 * Process title utility functions
 */
int rspamd_init_title(rspamd_mempool_t *pool, int argc, char *argv[], char *envp[]);
int rspamd_setproctitle(const char *fmt, ...);

#ifndef HAVE_PIDFILE
/*
 * Pidfile functions from FreeBSD libutil code
 */
typedef struct rspamd_pidfh_s {
	int pf_fd;
#ifdef HAVE_PATH_MAX
	char pf_path[PATH_MAX + 1];
#elif defined(HAVE_MAXPATHLEN)
	char pf_path[MAXPATHLEN + 1];
#else
	char pf_path[1024 + 1];
#endif
	dev_t pf_dev;
	ino_t pf_ino;
} rspamd_pidfh_t;

rspamd_pidfh_t *rspamd_pidfile_open(const char *path,
									mode_t mode,
									pid_t *pidptr);

int rspamd_pidfile_write(rspamd_pidfh_t *pfh);

int rspamd_pidfile_close(rspamd_pidfh_t *pfh);

int rspamd_pidfile_remove(rspamd_pidfh_t *pfh);

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
char *resolve_stat_filename(rspamd_mempool_t *pool,
							char *pattern,
							char *rcpt,
							char *from);

const char *
rspamd_log_check_time(double start, double end, int resolution);

/*
 * File locking functions
 */
gboolean rspamd_file_lock(int fd, gboolean async);

gboolean rspamd_file_unlock(int fd, gboolean async);

/*
 * Workarounds for older versions of glib
 */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 22))
void g_ptr_array_unref(GPtrArray *array);
gboolean g_int64_equal(gconstpointer v1, gconstpointer v2);
unsigned int g_int64_hash(gconstpointer v);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 14))
void g_queue_clear(GQueue *queue);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 32))
void g_queue_free_full(GQueue *queue, GDestroyNotify free_func);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 40))
void g_ptr_array_insert(GPtrArray *array, int index_, gpointer data);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 30))
GPtrArray *g_ptr_array_new_full(unsigned int reserved_size,
								GDestroyNotify element_free_func);
#endif
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 32))
const char *g_environ_getenv(char **envp, const char *variable);
#endif

/*
 * Convert milliseconds to timeval fields
 */
#define msec_to_tv(msec, tv)                       \
	do {                                           \
		(tv)->tv_sec = (msec) / 1000;              \
		(tv)->tv_usec =                            \
			((msec) - (tv)->tv_sec * 1000) * 1000; \
	} while (0)
#define double_to_tv(dbl, tv)                    \
	do {                                         \
		(tv)->tv_sec = (int) (dbl);              \
		(tv)->tv_usec =                          \
			((dbl) - (int) (dbl)) * 1000 * 1000; \
	} while (0)
#define double_to_ts(dbl, ts)            \
	do {                                 \
		(ts)->tv_sec = (int) (dbl);      \
		(ts)->tv_nsec =                  \
			((dbl) - (int) (dbl)) * 1e9; \
	} while (0)
#define tv_to_msec(tv) ((tv)->tv_sec * 1000LLU + (tv)->tv_usec / 1000LLU)
#define tv_to_double(tv) ((double) (tv)->tv_sec + (tv)->tv_usec / 1.0e6)
#define ts_to_usec(ts) ((ts)->tv_sec * 1000000LLU + \
						(ts)->tv_nsec / 1000LLU)
#define ts_to_double(tv) ((double) (tv)->tv_sec + (tv)->tv_nsec / 1.0e9)

/**
 * Try to allocate a file on filesystem (using fallocate or posix_fallocate)
 * @param fd descriptor
 * @param offset offset of file
 * @param len length to allocate
 * @return -1 in case of failure
 */
int rspamd_fallocate(int fd, off_t offset, off_t len);

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
rspamd_mutex_t *rspamd_mutex_new(void);

/**
 * Lock mutex
 * @param mtx
 */
void rspamd_mutex_lock(rspamd_mutex_t *mtx);

/**
 * Unlock mutex
 * @param mtx
 */
void rspamd_mutex_unlock(rspamd_mutex_t *mtx);

/**
 * Clear rspamd mutex
 * @param mtx
 */
void rspamd_mutex_free(rspamd_mutex_t *mtx);

/**
 * Deep copy of one hash table to another
 * @param src source hash
 * @param dst destination hash
 * @param key_copy_func function called to copy or modify keys (or NULL)
 * @param value_copy_func function called to copy or modify values (or NULL)
 * @param ud user data for copy functions
 */
void rspamd_hash_table_copy(GHashTable *src, GHashTable *dst,
							gpointer (*key_copy_func)(gconstpointer data, gpointer ud),
							gpointer (*value_copy_func)(gconstpointer data, gpointer ud),
							gpointer ud);


/**
 * Read passphrase from tty
 * @param buf buffer to fill with a password
 * @param size size of the buffer
 * @param echo turn echo on or off
 * @param key unused key
 * @return size of password read
 */
#define rspamd_read_passphrase(buf, size, echo, key) (rspamd_read_passphrase_with_prompt("Enter passphrase: ", (buf), (size), (echo), (key)))

/**
 * Read passphrase from tty with prompt
 * @param prompt prompt to use
 * @param buf buffer to fill with a password
 * @param size size of the buffer
 * @param echo turn echo on or off
 * @param key unused key
 * @return
 */
int rspamd_read_passphrase_with_prompt(const char *prompt, char *buf, int size, bool echo, gpointer key);

/**
 * Portably return the current clock ticks as seconds
 * @return
 */
double rspamd_get_ticks(gboolean rdtsc_ok);

/**
 * Portably return the current virtual clock ticks as seconds
 * @return
 */
double rspamd_get_virtual_ticks(void);


/**
 * Return the real timestamp as unixtime
 */
double rspamd_get_calendar_ticks(void);

/**
 * Special utility to help array freeing in rspamd_mempool
 * @param p
 */
void rspamd_ptr_array_free_hard(gpointer p);

/**
 * Special utility to help array freeing in rspamd_mempool
 * @param p
 */
void rspamd_array_free_hard(gpointer p);

/**
 * Special utility to help GString freeing in rspamd_mempool
 * @param p
 */
void rspamd_gstring_free_hard(gpointer p);

/**
 * Special utility to help GError freeing in rspamd_mempool
 * @param p
 */
void rspamd_gerror_free_maybe(gpointer p);

/**
 * Special utility to help GString freeing (without freeing the memory segment) in rspamd_mempool
 * @param p
 */
void rspamd_gstring_free_soft(gpointer p);


/**
 * Returns some statically initialized random hash seed
 * @return hash seed
 */
uint64_t rspamd_hash_seed(void);

/**
 * Returns random hex string of the specified length
 * @param buf
 * @param len
 */
void rspamd_random_hex(char *buf, uint64_t len);

/**
 * Returns
 * @param pattern pattern to create (should end with some number of X symbols), modified by this function
 * @return
 */
int rspamd_shmem_mkstemp(char *pattern);

/**
 * Return jittered time value
 */
double rspamd_time_jitter(double in, double jitter);

/**
 * Return random double in range [0..1)
 * @return
 */
double rspamd_random_double(void);

/**
 * Return random double in range [0..1) using xoroshiro128+ algorithm (not crypto secure)
 * @return
 */
double rspamd_random_double_fast(void);
double rspamd_random_double_fast_seed(uint64_t *seed);
uint64_t rspamd_random_uint64_fast_seed(uint64_t *seed);
uint64_t rspamd_random_uint64_fast(void);

/**
 * Seed fast rng
 */
void rspamd_random_seed_fast(void);

/**
 * Constant time version of memcmp
 */
gboolean rspamd_constant_memcmp(const void *a, const void *b, gsize len);

/**
 * Open file without following symlinks or special stuff
 * @param fname filename
 * @param oflags open flags
 * @param mode mode to open
 * @return fd or -1 in case of error
 */
int rspamd_file_xopen(const char *fname, int oflags, unsigned int mode,
					  gboolean allow_symlink);

/**
 * Map file without following symlinks or special stuff
 * @param fname filename
 * @param mode mode to open
 * @param size target size (must NOT be NULL)
 * @return pointer to memory (should be freed using munmap) or NULL in case of error
 */
gpointer rspamd_file_xmap(const char *fname, unsigned int mode, gsize *size,
						  gboolean allow_symlink);

/**
 * Map named shared memory segment
 * @param fname filename
 * @param mode mode to open
 * @param size target size (must NOT be NULL)
 * @return pointer to memory (should be freed using munmap) or NULL in case of error
 */
gpointer rspamd_shmem_xmap(const char *fname, unsigned int mode,
						   gsize *size);

/**
 * Normalize probabilities using polynomial function
 * @param x probability (bias .. 1)
 * @return
 */
double rspamd_normalize_probability(double x, double bias);

/**
 * Converts struct tm to time_t
 * @param tm
 * @param tz timezone in format (hours * 100) + minutes
 * @return
 */
uint64_t rspamd_tm_to_time(const struct tm *tm, glong tz);

/**
 * Splits unix timestamp into struct tm using GMT timezone
 * @param ts
 * @param dest
 */
void rspamd_gmtime(int64_t ts, struct tm *dest);

/**
 * Split unix timestamp into struct tm using local timezone
 * @param ts
 * @param dest
 */
void rspamd_localtime(int64_t ts, struct tm *dest);

#define PTR_ARRAY_FOREACH(ar, i, cur) for ((i) = 0; (ar) != NULL && (i) < (ar)->len && (((cur) = (__typeof__(cur)) g_ptr_array_index((ar), (i))) || 1); ++(i))

/**
 * Compresses the input string using gzip+zlib. Old string is replaced and freed
 * if compressed.
 * @param in
 * @return TRUE if a string has been compressed
 */
gboolean rspamd_fstring_gzip(rspamd_fstring_t **in);

/**
 * Compresses the input string using gzip+zlib. Old string is replaced and freed
 * if compressed. If not compressed it is untouched.
 * @param in
 * @return TRUE if a string has been compressed
 */
gboolean rspamd_fstring_gunzip(rspamd_fstring_t **in);

/**
 * Perform globbing searching for the specified path. Allow recursion,
 * returns an error if maximum nesting is reached.
 * @param pattern
 * @param recursive
 * @param err
 * @return GPtrArray of char *, elements are freed when array is freed
 */
GPtrArray *rspamd_glob_path(const char *dir,
							const char *pattern,
							gboolean recursive,
							GError **err);

struct rspamd_counter_data {
	float mean;
	float stddev;
	uint64_t number;
};

/**
 * Sets counter's data using exponential moving average
 * @param cd counter
 * @param value new counter value
 * @param alpha decay coefficient (0..1)
 * @return new counter value
 */
float rspamd_set_counter_ema(struct rspamd_counter_data *cd,
							 float value,
							 float alpha);

/**
 * Sets counter's data using flat moving average
 * @param cd counter
 * @param value new counter value
 * @return new counter value
 */
double rspamd_set_counter(struct rspamd_counter_data *cd,
						  double value);

/**
 * Shuffle elements in an array inplace
 * @param ar
 */
void rspamd_ptr_array_shuffle(GPtrArray *ar);

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
	int id;
	unsigned int complexity;
	gsize salt_len;
	gsize key_len;
};

extern const struct rspamd_controller_pbkdf pbkdf_list[];

/**
 * Sum array of floats using Kahan sum algorithm
 * @param ar
 * @param nelts
 * @return
 */
float rspamd_sum_floats(float *ar, gsize *nelts);

/**
 * Normalize file path removing dot sequences and repeating '/' symbols as
 * per rfc3986#section-5.2
 * @param path
 * @param len
 * @param nlen
 */
void rspamd_normalize_path_inplace(char *path, unsigned int len, gsize *nlen);

#ifdef __cplusplus
}
#endif

#endif
