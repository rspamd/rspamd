#ifndef RSPAMD_UTIL_H
#define RSPAMD_UTIL_H

#include "config.h"
#include "mem_pool.h"

struct config_file;
struct rspamd_main;
struct workq;

/* Create socket and bind or connect it to specified address and port */
int make_tcp_socket (struct in_addr *, u_short, gboolean is_server);
/* Accept from socket */
int accept_from_socket (int listen_sock, struct sockaddr *addr, socklen_t *len);
/* Create and bind or connect unix socket */
int make_unix_socket (const char *, struct sockaddr_un *, gboolean is_server);
/* Write pid to file */
int write_pid (struct rspamd_main *);
/* Make specified socket non-blocking */
int event_make_socket_nonblocking(int);
/* Init signals */
void init_signals (struct sigaction *, sig_t);
/* Send specified signal to each worker */
void pass_signal_worker (struct workq *, int );
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

void rspamd_set_logger (GLogFunc func, struct config_file *cfg);
int open_log (struct config_file *cfg);
void close_log (struct config_file *cfg);
int reopen_log (struct config_file *cfg);
void rspamd_log_function (GLogLevelFlags log_level, const char *fmt, ...);
void syslog_log_function (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer arg);
void file_log_function (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer arg);

/* Replace %r with rcpt value and %f with from value, new string is allocated in pool */
char* resolve_stat_filename (memory_pool_t *pool, char *pattern, char *rcpt, char *from);
const char* calculate_check_time (struct timespec *begin, int resolution);

void set_counter (const char *name, long int value);

gboolean parse_host_list (memory_pool_t *pool, GHashTable *tbl, const char *filename);
gboolean maybe_parse_host_list (memory_pool_t *pool, GHashTable *tbl, const char *filename);


#endif
