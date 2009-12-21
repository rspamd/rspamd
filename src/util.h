#ifndef RSPAMD_UTIL_H
#define RSPAMD_UTIL_H

#include "config.h"
#include "mem_pool.h"
#include "radix.h"
#include "statfile.h"

struct config_file;
struct rspamd_main;
struct workq;
struct statfile;
struct classifier_config;

/* Create socket and bind or connect it to specified address and port */
int make_tcp_socket (struct in_addr *, u_short, gboolean is_server, gboolean async);
/* Create socket and bind or connect it to specified address and port */
int make_udp_socket (struct in_addr *, u_short, gboolean is_server, gboolean async);
/* Accept from socket */
int accept_from_socket (int listen_sock, struct sockaddr *addr, socklen_t *len);
/* Create and bind or connect unix socket */
int make_unix_socket (const char *, struct sockaddr_un *, gboolean is_server);
/* Write pid to file */
int write_pid (struct rspamd_main *);
/* Make specified socket non-blocking */
int make_socket_nonblocking (int);
int make_socket_blocking (int);
/* Poll sync socket for specified events */
int poll_sync_socket (int fd, int timeout, short events);
/* Init signals */
#ifdef HAVE_SA_SIGINFO
void init_signals (struct sigaction *sa, void (*sig_handler)(int, siginfo_t *, void *));
#else
void init_signals (struct sigaction *sa, sighandler_t);
#endif
/* Send specified signal to each worker */
void pass_signal_worker (GHashTable *, int );
/* Convert string to lowercase */
void convert_to_lowercase (char *str, unsigned int size);

#ifndef HAVE_SETPROCTITLE
int init_title(int argc, char *argv[], char *envp[]);
int setproctitle(const char *fmt, ...);
#endif

#ifndef HAVE_PIDFILE
struct pidfh {
	int pf_fd;
#ifdef HAVE_PATH_MAX
	char    pf_path[PATH_MAX + 1];
#elif defined(HAVE_MAXPATHLEN)
	char    pf_path[MAXPATHLEN + 1];
#else
	char    pf_path[1024 + 1];
#endif
 	__dev_t pf_dev;
 	ino_t   pf_ino;
};
struct pidfh *pidfile_open(const char *path, mode_t mode, pid_t *pidptr);
int pidfile_write(struct pidfh *pfh);
int pidfile_close(struct pidfh *pfh);
int pidfile_remove(struct pidfh *pfh);
#endif

/* Replace %r with rcpt value and %f with from value, new string is allocated in pool */
char* resolve_stat_filename (memory_pool_t *pool, char *pattern, char *rcpt, char *from);
const char* calculate_check_time (struct timespec *begin, int resolution);

double set_counter (const char *name, long int value);

gboolean lock_file (int fd, gboolean async);
gboolean unlock_file (int fd, gboolean async);

guint rspamd_strcase_hash (gconstpointer key);
gboolean rspamd_strcase_equal (gconstpointer v, gconstpointer v2);

void gperf_profiler_init (struct config_file *cfg, const char *descr);

#ifdef RSPAMD_MAIN
stat_file_t* get_statfile_by_symbol (statfile_pool_t *pool, struct classifier_config *ccf, 
		const char *symbol, struct statfile **st, gboolean try_create);
#endif

int rspamd_sprintf (u_char *buf, const char *fmt, ...);
int rspamd_snprintf (u_char *buf, size_t max, const char *fmt, ...);
u_char *rspamd_vsnprintf (u_char *buf, size_t max, const char *fmt, va_list args);

#endif
