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
#include "config.h"
#include "rspamd.h"
#include "libserver/maps/map.h"
#include "lua/lua_common.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "ottery.h"
#include "cryptobox.h"
#include "utlist.h"
#include "unix-std.h"
/* pwd and grp */
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_NFTW
#include <ftw.h>
#endif

#include <signal.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#include "sqlite3.h"
#include "contrib/libev/ev.h"

/* 2 seconds to fork new process in place of dead one */
#define SOFT_FORK_TIME 2

/* 10 seconds after getting termination signal to terminate all workers with SIGKILL */
#define TERMINATION_INTERVAL (0.2)

static gboolean load_rspamd_config (struct rspamd_main *rspamd_main,
									struct rspamd_config *cfg,
									gboolean init_modules,
									enum rspamd_post_load_options opts,
									gboolean reload);
static void rspamd_cld_handler (EV_P_ ev_child *w,
								struct rspamd_main *rspamd_main,
								struct rspamd_worker *wrk);

/* Control socket */
static gint control_fd;
static ev_io control_ev;
static struct rspamd_stat old_stat;
static ev_timer stat_ev;

static gboolean valgrind_mode = FALSE;

/* Cmdline options */
static gboolean no_fork = FALSE;
static gboolean show_version = FALSE;
static gchar **cfg_names = NULL;
static gchar *rspamd_user = NULL;
static gchar *rspamd_group = NULL;
static gchar *rspamd_pidfile = NULL;
static gboolean is_debug = FALSE;
static gboolean is_insecure = FALSE;
static GHashTable *ucl_vars = NULL;
static gchar **lua_env = NULL;
static gboolean skip_template = FALSE;

static gint term_attempts = 0;

/* List of active listen sockets indexed by worker type */
static GHashTable *listen_sockets = NULL;

/* Defined in modules.c */
extern module_t *modules[];
extern worker_t *workers[];

/* Command line options */
static gboolean rspamd_parse_var (const gchar *option_name,
								  const gchar *value, gpointer data,
								  GError **error);
static GOptionEntry entries[] =
{
	{ "no-fork", 'f', 0, G_OPTION_ARG_NONE, &no_fork,
	  "Do not daemonize main process", NULL },
	{ "config", 'c', 0, G_OPTION_ARG_FILENAME_ARRAY, &cfg_names,
	  "Specify config file(s)", NULL },
	{ "user", 'u', 0, G_OPTION_ARG_STRING, &rspamd_user,
	  "User to run rspamd as", NULL },
	{ "group", 'g', 0, G_OPTION_ARG_STRING, &rspamd_group,
	  "Group to run rspamd as", NULL },
	{ "pid", 'p', 0, G_OPTION_ARG_STRING, &rspamd_pidfile, "Path to pidfile",
	  NULL },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &is_debug, "Force debug output",
	  NULL },
	{ "insecure", 'i', 0, G_OPTION_ARG_NONE, &is_insecure,
	  "Ignore running workers as privileged users (insecure)", NULL },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &show_version,
	  "Show version and exit", NULL },
	{"var", 0, 0, G_OPTION_ARG_CALLBACK, (gpointer)&rspamd_parse_var,
			"Redefine/define environment variable", NULL},
	{"skip-template", 'T', 0, G_OPTION_ARG_NONE, &skip_template,
			"Do not apply Jinja templates", NULL},
	{"lua-env", '\0', 0, G_OPTION_ARG_FILENAME_ARRAY, &lua_env,
			"Load lua environment from the specified files", NULL},
	{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};

static gboolean
rspamd_parse_var (const gchar *option_name,
						const gchar *value, gpointer data,
						GError **error)
{
	gchar *k, *v, *t;

	t = strchr (value, '=');

	if (t != NULL) {
		k = g_strdup (value);
		t = k + (t - value);
		v = g_strdup (t + 1);
		*t = '\0';

		if (ucl_vars == NULL) {
			ucl_vars = g_hash_table_new_full (rspamd_strcase_hash,
					rspamd_strcase_equal, g_free, g_free);
		}

		g_hash_table_insert (ucl_vars, k, v);
	}
	else {
		g_set_error (error, g_quark_try_string ("main"), EINVAL,
				"Bad variable format: %s", value);
		return FALSE;
	}

	return TRUE;
}

static void
read_cmd_line (gint *argc, gchar ***argv, struct rspamd_config *cfg)
{
	GError *error = NULL;
	GOptionContext *context;
	guint cfg_num;

	context = g_option_context_new ("- run rspamd daemon");
#if defined(GIT_VERSION) && GIT_VERSION == 1
	g_option_context_set_summary (context,
		"Summary:\n  Rspamd daemon version " RVERSION "-git\n  Git id: " RID);
#else
	g_option_context_set_summary (context,
		"Summary:\n  Rspamd daemon version " RVERSION);
#endif
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, argc, argv, &error)) {
		fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_option_context_free (context);
		exit (EXIT_FAILURE);
	}

	cfg->rspamd_user = rspamd_user;
	cfg->rspamd_group = rspamd_group;
	cfg_num = cfg_names != NULL ? g_strv_length (cfg_names) : 0;

	if (cfg_num == 0) {
		cfg->cfg_name = FIXED_CONFIG_FILE;
	}
	else {
		cfg->cfg_name = cfg_names[0];
		g_assert (cfg_num == 1);
	}

	cfg->pid_file = rspamd_pidfile;
	g_option_context_free (context);
}

static int
rspamd_write_pid (struct rspamd_main *main)
{
	pid_t pid;

	if (main->cfg->pid_file == NULL) {
		return -1;
	}
	main->pfh = rspamd_pidfile_open (main->cfg->pid_file, 0644, &pid);

	if (main->pfh == NULL) {
		return -1;
	}

	if (main->is_privilleged) {
		/* Force root user as owner of pid file */
#ifdef HAVE_PIDFILE_FILENO
		if (fchown (pidfile_fileno (main->pfh), 0, 0) == -1) {
#else
		if (fchown (main->pfh->pf_fd, 0, 0) == -1) {
#endif
		}
	}

	rspamd_pidfile_write (main->pfh);

	return 0;
}

/* Detect privilleged mode */
static void
detect_priv (struct rspamd_main *rspamd_main)
{
	struct passwd *pwd;
	struct group *grp;
	uid_t euid;

	euid = geteuid ();

	if (euid == 0) {
		if (!rspamd_main->cfg->rspamd_user && !is_insecure) {
			msg_err_main (
				"cannot run rspamd workers as root user, please add -u and -g options to select a proper unprivilleged user or specify --insecure flag");
			exit (EXIT_FAILURE);
		}
		else if (is_insecure) {
			rspamd_main->is_privilleged = TRUE;
			rspamd_main->workers_uid = 0;
			rspamd_main->workers_gid = 0;
		}
		else {
			rspamd_main->is_privilleged = TRUE;
			pwd = getpwnam (rspamd_main->cfg->rspamd_user);
			if (pwd == NULL) {
				msg_err_main ("user specified does not exists (%s), aborting",
					strerror (errno));
				exit (-errno);
			}
			if (rspamd_main->cfg->rspamd_group) {
				grp = getgrnam (rspamd_main->cfg->rspamd_group);
				if (grp == NULL) {
					msg_err_main ("group specified does not exists (%s), aborting",
						strerror (errno));
					exit (-errno);
				}
				rspamd_main->workers_gid = grp->gr_gid;
			}
			else {
				rspamd_main->workers_gid = (gid_t)-1;
			}
			rspamd_main->workers_uid = pwd->pw_uid;
		}
	}
	else {
		rspamd_main->is_privilleged = FALSE;
		rspamd_main->workers_uid = (uid_t)-1;
		rspamd_main->workers_gid = (gid_t)-1;
	}
}

static void
config_logger (rspamd_mempool_t *pool, gpointer ud)
{
	struct rspamd_main *rspamd_main = ud;

	rspamd_main->logger = rspamd_log_open_specific (rspamd_main->server_pool,
			rspamd_main->cfg,
			"main",
			rspamd_main->workers_uid,
			rspamd_main->workers_gid);

	if (rspamd_main->logger == NULL) {
		/*
		 * XXX:
		 * Error has been already logged (in fact,
		 * we might fall back to console logger here)
		 */
		exit (EXIT_FAILURE);
	}

	rspamd_logger_configure_modules (rspamd_main->cfg->debug_modules);
}

static gboolean
reread_config (struct rspamd_main *rspamd_main)
{
	struct rspamd_config *tmp_cfg, *old_cfg;
	gchar *cfg_file;
	int load_opts = RSPAMD_CONFIG_INIT_VALIDATE|RSPAMD_CONFIG_INIT_SYMCACHE|
					RSPAMD_CONFIG_INIT_LIBS|RSPAMD_CONFIG_INIT_URL;

	rspamd_symcache_save (rspamd_main->cfg->cache);
	tmp_cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_DEFAULT);
	tmp_cfg->libs_ctx = rspamd_main->cfg->libs_ctx;
	REF_RETAIN (tmp_cfg->libs_ctx);
	cfg_file = rspamd_mempool_strdup (tmp_cfg->cfg_pool,
			rspamd_main->cfg->cfg_name);
	/* Save some variables */
	tmp_cfg->cfg_name = cfg_file;
	old_cfg = rspamd_main->cfg;
	rspamd_main->cfg = tmp_cfg;
	rspamd_logger_t *old_logger = rspamd_main->logger;

	if (!load_rspamd_config (rspamd_main, tmp_cfg, TRUE, load_opts, TRUE)) {
		rspamd_main->cfg = old_cfg;
		rspamd_main->logger = old_logger;
		msg_err_main ("cannot parse new config file, revert to old one");
		REF_RELEASE (tmp_cfg);

		return FALSE;
	}
	else {
		rspamd_log_close (old_logger);
		msg_info_main ("replacing config");
		REF_RELEASE (old_cfg);
		rspamd_main->cfg->rspamd_user = rspamd_user;
		rspamd_main->cfg->rspamd_group = rspamd_group;
		/* Here, we can do post actions with the existing config */
		/*
		 * As some rules are defined in lua, we need to process them, then init
		 * modules and merely afterwards to init modules
		 */
		rspamd_lua_post_load_config (tmp_cfg);
		rspamd_init_filters (tmp_cfg, true, false);

		/* Do post-load actions */
		rspamd_config_post_load (tmp_cfg,
				load_opts|RSPAMD_CONFIG_INIT_POST_LOAD_LUA|RSPAMD_CONFIG_INIT_PRELOAD_MAPS);
		msg_info_main ("config has been reread successfully");
	}

	return TRUE;
}

struct waiting_worker {
	struct rspamd_main *rspamd_main;
 	struct ev_timer wait_ev;
	struct rspamd_worker_conf *cf;
	guint oldindex;
};

static void
rspamd_fork_delayed_cb (EV_P_ ev_timer *w, int revents)
{
	struct waiting_worker *waiting_worker = (struct waiting_worker *)w->data;

	ev_timer_stop (EV_A_ &waiting_worker->wait_ev);
	rspamd_fork_worker (waiting_worker->rspamd_main, waiting_worker->cf,
			waiting_worker->oldindex,
			waiting_worker->rspamd_main->event_loop,
			rspamd_cld_handler, listen_sockets);
	REF_RELEASE (waiting_worker->cf);
	g_free (waiting_worker);
}

static void
rspamd_fork_delayed (struct rspamd_worker_conf *cf,
		guint index,
		struct rspamd_main *rspamd_main)
{
	struct waiting_worker *nw;

	nw = g_malloc0 (sizeof (*nw));
	nw->cf = cf;
	nw->oldindex = index;
	nw->rspamd_main = rspamd_main;
	REF_RETAIN (cf);
	nw->wait_ev.data = nw;
	ev_timer_init (&nw->wait_ev, rspamd_fork_delayed_cb, SOFT_FORK_TIME, 0.0);
	ev_timer_start (rspamd_main->event_loop, &nw->wait_ev);
}

static GList *
create_listen_socket (GPtrArray *addrs, guint cnt,
		enum rspamd_worker_socket_type listen_type)
{
	GList *result = NULL;
	gint fd;
	guint i;
	static const int listen_opts = RSPAMD_INET_ADDRESS_LISTEN_ASYNC;
	struct rspamd_worker_listen_socket *ls;

	g_ptr_array_sort (addrs, rspamd_inet_address_compare_ptr);
	for (i = 0; i < cnt; i ++) {

		/*
		 * Copy address to avoid reload issues
		 */
		if (listen_type & RSPAMD_WORKER_SOCKET_TCP) {
			fd = rspamd_inet_address_listen (g_ptr_array_index (addrs, i),
					SOCK_STREAM,
					listen_opts, -1);
			if (fd != -1) {
				ls = g_malloc0 (sizeof (*ls));
				ls->addr = rspamd_inet_address_copy (g_ptr_array_index (addrs, i));
				ls->fd = fd;
				ls->type = RSPAMD_WORKER_SOCKET_TCP;
				result = g_list_prepend (result, ls);
			}
		}
		if (listen_type & RSPAMD_WORKER_SOCKET_UDP) {
			fd = rspamd_inet_address_listen (g_ptr_array_index (addrs, i),
					SOCK_DGRAM,
					listen_opts | RSPAMD_INET_ADDRESS_LISTEN_REUSEPORT, -1);
			if (fd != -1) {
				ls = g_malloc0 (sizeof (*ls));
				ls->addr = rspamd_inet_address_copy (g_ptr_array_index (addrs, i));
				ls->fd = fd;
				ls->type = RSPAMD_WORKER_SOCKET_UDP;
				result = g_list_prepend (result, ls);
			}
		}
	}

	return result;
}

static GList *
systemd_get_socket (struct rspamd_main *rspamd_main, const gchar *fdname)
{
	int number, sock, num_passed, flags;
	GList *result = NULL;
	const gchar *e;
	gchar **fdnames;
	gchar *end;
	struct stat st;
	static const int sd_listen_fds_start = 3;   /* SD_LISTEN_FDS_START */
	struct rspamd_worker_listen_socket *ls;

	union {
		struct sockaddr_storage ss;
		struct sockaddr sa;
	} addr_storage;
	socklen_t slen = sizeof (addr_storage);
	gint stype;

	number = strtoul (fdname, &end, 10);
	if (end != NULL && *end != '\0') {
		/* Cannot parse as number, assume a name in LISTEN_FDNAMES. */
		e = getenv ("LISTEN_FDNAMES");
		if (!e) {
			msg_err_main ("cannot get systemd variable 'LISTEN_FDNAMES'");
			errno = ENOENT;
			return NULL;
		}

		fdnames = g_strsplit (e, ":", -1);
		for (number = 0; fdnames[number]; number++) {
			if (!strcmp (fdnames[number], fdname)) {
				break;
			}
		}
		if (!fdnames[number]) {
			number = -1;
		}
		g_strfreev (fdnames);
	}

	if (number < 0) {
		msg_warn_main ("cannot find systemd socket: %s", fdname);
		errno = ENOENT;
		return NULL;
	}

	e = getenv ("LISTEN_FDS");
	if (e != NULL) {
		errno = 0;
		num_passed = strtoul (e, &end, 10);
		if ((end == NULL || *end == '\0') && num_passed > number) {
			sock = number + sd_listen_fds_start;
			if (fstat (sock, &st) == -1) {
				msg_warn_main ("cannot stat systemd descriptor %d", sock);
				return NULL;
			}
			if (!S_ISSOCK (st.st_mode)) {
				msg_warn_main ("systemd descriptor %d is not a socket", sock);
				errno = EINVAL;
				return NULL;
			}
			flags = fcntl (sock, F_GETFD);

			if (flags != -1) {
				(void)fcntl (sock, F_SETFD, flags | FD_CLOEXEC);
			}

			rspamd_socket_nonblocking (sock);

			if (getsockname (sock, &addr_storage.sa, &slen) == -1) {
				msg_warn_main ("cannot get name for systemd descriptor %d: %s",
						sock, strerror (errno));
				errno = EINVAL;
				return NULL;
			}

			ls = g_malloc0 (sizeof (*ls));
			ls->addr = rspamd_inet_address_from_sa (&addr_storage.sa, slen);
			ls->fd = sock;
			ls->is_systemd = true;

			slen = sizeof (stype);
			if (getsockopt (sock, SOL_SOCKET, SO_TYPE, &stype, &slen) != -1) {
				if (stype == SOCK_STREAM) {
					ls->type = RSPAMD_WORKER_SOCKET_TCP;
				}
				else {
					ls->type = RSPAMD_WORKER_SOCKET_UDP;
				}
			}
			else {
				msg_warn_main ("cannot get type for systemd descriptor %d: %s",
						sock, strerror (errno));
				ls->type = RSPAMD_WORKER_SOCKET_TCP;
			}


			result = g_list_prepend (result, ls);
		}
		else if (num_passed <= number) {
			msg_err_main ("systemd LISTEN_FDS does not contain the expected fd: %d",
					num_passed);
			errno = EINVAL;
		}
	}
	else {
		msg_err_main ("cannot get systemd variable 'LISTEN_FDS'");
		errno = ENOENT;
	}

	return result;
}

static void
pass_signal_cb (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_worker *cur = value;
	gint signo = GPOINTER_TO_INT (ud);

	kill (cur->pid, signo);
}

static void
rspamd_pass_signal (GHashTable * workers, gint signo)
{
	g_hash_table_foreach (workers, pass_signal_cb, GINT_TO_POINTER (signo));
}

static inline uintptr_t
make_listen_key (struct rspamd_worker_bind_conf *cf)
{
	rspamd_cryptobox_fast_hash_state_t st;
	guint i, keylen = 0;
	guint8 *key;
	rspamd_inet_addr_t *addr;
	guint16 port;

	rspamd_cryptobox_fast_hash_init (&st, rspamd_hash_seed ());
	if (cf->is_systemd) {
		/* Something like 'systemd:0' or 'systemd:controller'. */
		rspamd_cryptobox_fast_hash_update (&st, cf->name, strlen (cf->name));
	}
	else {
		rspamd_cryptobox_fast_hash_update (&st, cf->name, strlen (cf->name));
		for (i = 0; i < cf->cnt; i ++) {
			addr = g_ptr_array_index (cf->addrs, i);
			key = rspamd_inet_address_get_hash_key (
					addr, &keylen);
			rspamd_cryptobox_fast_hash_update (&st, key, keylen);
			port = rspamd_inet_address_get_port (addr);
			rspamd_cryptobox_fast_hash_update (&st, &port, sizeof (port));
		}
	}

	return rspamd_cryptobox_fast_hash_final (&st);
}

static void
spawn_worker_type (struct rspamd_main *rspamd_main, struct ev_loop *event_loop,
		struct rspamd_worker_conf *cf)
{
	gint i;

	if (cf->count < 0) {
		msg_info_main ("skip spawning of worker %s: disabled in configuration",
			cf->worker->name);

		return;
	}
	if (cf->worker->flags & RSPAMD_WORKER_UNIQUE) {
		if (cf->count > 1) {
			msg_warn_main (
					"cannot spawn more than 1 %s worker, so spawn one",
					cf->worker->name);
		}
		rspamd_fork_worker (rspamd_main, cf, 0, event_loop, rspamd_cld_handler,
				listen_sockets);
	}
	else if (cf->worker->flags & RSPAMD_WORKER_THREADED) {
		rspamd_fork_worker (rspamd_main, cf, 0, event_loop, rspamd_cld_handler,
				listen_sockets);
	}
	else {
		for (i = 0; i < cf->count; i++) {
			rspamd_fork_worker (rspamd_main, cf, i, event_loop,
					rspamd_cld_handler, listen_sockets);
		}
	}
}

static void
spawn_workers (struct rspamd_main *rspamd_main, struct ev_loop *ev_base)
{
	GList *cur, *ls;
	struct rspamd_worker_conf *cf;
	gpointer p;
	guintptr key;
	struct rspamd_worker_bind_conf *bcf;
	gboolean listen_ok = FALSE;
	GPtrArray *seen_mandatory_workers;
	worker_t **cw, *wrk;
	guint i;

	/* Special hack for hs_helper if it's not defined in a config */
	seen_mandatory_workers = g_ptr_array_new ();
	cur = rspamd_main->cfg->workers;

	while (cur) {
		cf = cur->data;
		listen_ok = FALSE;

		if (cf->worker == NULL) {
			msg_err_main ("type of worker is unspecified, skip spawning");
		}
		else {
			if (!cf->enabled || cf->count <= 0) {
				msg_info_main ("worker of type %s(%s) is disabled in the config, "
						"skip spawning", g_quark_to_string (cf->type),
						cf->bind_conf ? cf->bind_conf->name : "none");
				cur = g_list_next (cur);

				continue;
			}

			if (cf->worker->flags & RSPAMD_WORKER_ALWAYS_START) {
				g_ptr_array_add (seen_mandatory_workers, cf->worker);
			}
			if (cf->worker->flags & RSPAMD_WORKER_HAS_SOCKET) {
				LL_FOREACH (cf->bind_conf, bcf) {
					key = make_listen_key (bcf);

					if ((p =
						g_hash_table_lookup (listen_sockets,
								GINT_TO_POINTER (key))) == NULL) {

						if (!bcf->is_systemd) {
							/* Create listen socket */
							ls = create_listen_socket (bcf->addrs, bcf->cnt,
									cf->worker->listen_type);
						}
						else {
							ls = systemd_get_socket (rspamd_main,
									g_ptr_array_index (bcf->addrs, 0));
						}

						if (ls == NULL) {
							msg_err_main ("cannot listen on %s socket %s: %s",
								bcf->is_systemd ? "systemd" : "normal",
								bcf->name,
								strerror (errno));
						}
						else {
							g_hash_table_insert (listen_sockets, (gpointer)key, ls);
							listen_ok = TRUE;
						}
					}
					else {
						/* We had socket for this type of worker */
						ls = p;
						listen_ok = TRUE;
					}
					/* Do not add existing lists as it causes loops */
					if (g_list_position (cf->listen_socks, ls) == -1) {
						cf->listen_socks = g_list_concat (cf->listen_socks, ls);
					}
				}

				if (listen_ok) {
					spawn_worker_type (rspamd_main, ev_base, cf);
				}
				else {
					if (cf->bind_conf == NULL) {
						msg_err_main ("cannot create listen socket for %s",
								g_quark_to_string (cf->type));
					} else {
						msg_err_main ("cannot create listen socket for %s at %s",
								g_quark_to_string (cf->type), cf->bind_conf->name);
					}

					rspamd_hard_terminate (rspamd_main);
					g_assert_not_reached ();
				}
			}
			else {
				spawn_worker_type (rspamd_main, ev_base, cf);
			}
		}

		cur = g_list_next (cur);
	}

	for (cw = workers; *cw != NULL; cw ++) {
		gboolean seen = FALSE;

		wrk = *cw;

		if (wrk->flags & RSPAMD_WORKER_ALWAYS_START) {
			for (i = 0; i < seen_mandatory_workers->len; i ++) {
				if (wrk == g_ptr_array_index (seen_mandatory_workers, i)) {
					seen = TRUE;
					break;
				}
			}

			if (!seen) {
				cf = rspamd_config_new_worker (rspamd_main->cfg, NULL);
				cf->count = 1;
				cf->worker = wrk;
				cf->type = g_quark_from_static_string (wrk->name);

				if (cf->worker->worker_init_func) {
					cf->ctx = cf->worker->worker_init_func (rspamd_main->cfg);
				}

				spawn_worker_type (rspamd_main, ev_base, cf);
			}
		}
	}

	g_ptr_array_free (seen_mandatory_workers, TRUE);
}

static void
kill_old_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;
	struct rspamd_main *rspamd_main;

	rspamd_main = w->srv;

	if (w->state == rspamd_worker_state_wanna_die) {
		w->state = rspamd_worker_state_terminating;
		kill (w->pid, SIGUSR2);
		ev_io_stop (rspamd_main->event_loop, &w->srv_ev);
		g_hash_table_remove_all (w->control_events_pending);
		msg_info_main ("send signal to worker %P", w->pid);
	}
	else if (w->state != rspamd_worker_state_running) {
		msg_info_main ("do not send signal to worker %P, already sent", w->pid);
	}
}

static void
mark_old_workers (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;

	if (w->state == rspamd_worker_state_running) {
		w->state = rspamd_worker_state_wanna_die;
	}

	w->flags |= RSPAMD_WORKER_OLD_CONFIG;
}

static void
rspamd_worker_wait (struct rspamd_worker *w)
{
	struct rspamd_main *rspamd_main;
	rspamd_main = w->srv;

	if (term_attempts < 0) {
		if (w->cf->worker->flags & RSPAMD_WORKER_KILLABLE) {
			if (kill (w->pid, SIGKILL) == -1) {
				if (errno == ESRCH) {
					/* We have actually killed the process */
					return;
				}
			}
			else {
				msg_warn_main ("terminate worker %s(%P) with SIGKILL",
						g_quark_to_string (w->type), w->pid);
			}
		}
		else {
			kill (w->pid, SIGKILL);
			if (errno == ESRCH) {
				/* We have actually killed the process */
				return;
			}
			else {
				msg_err_main ("data corruption warning: terminating "
							  "special worker %s(%P) with SIGKILL",
						g_quark_to_string (w->type), w->pid);
			}
		}
	}
}

static void
hash_worker_wait_callback (gpointer key, gpointer value, gpointer unused)
{
	rspamd_worker_wait ((struct rspamd_worker *)value);
}

struct core_check_cbdata {
	struct rspamd_config *cfg;
	gsize total_count;
	gsize total_size;
};

#ifdef HAVE_NFTW

static struct core_check_cbdata cores_cbdata;

static gint
rspamd_check_core_cb (const gchar *path, const struct stat *st,
		gint flag, struct FTW *ft)
{
	if (S_ISREG (st->st_mode)) {
		cores_cbdata.total_count ++;
		/* Use physical size instead of displayed one */
		cores_cbdata.total_size += st->st_blocks * 512;
	}

	return 0;
}

#endif

static void
rspamd_check_core_limits (struct rspamd_main *rspamd_main)
{
#ifdef HAVE_NFTW
	struct rspamd_config *cfg = rspamd_main->cfg;

	cores_cbdata.cfg = cfg;
	cores_cbdata.total_count = 0;
	cores_cbdata.total_size = 0;

	if (cfg->cores_dir && (cfg->max_cores_count || cfg->max_cores_size)) {
		if (nftw (cfg->cores_dir, rspamd_check_core_cb, 1, FTW_MOUNT|FTW_PHYS)
					== -1) {
			msg_err_main ("nftw failed for path %s: %s", cfg->cores_dir,
					strerror (errno));
		}
		else {
			if (!rspamd_main->cores_throttling) {
				if (cfg->max_cores_size &&
						cores_cbdata.total_size > cfg->max_cores_size) {
					msg_warn_main (
							"enable cores throttling as size of cores in"
									" %s is %Hz, limit is %Hz",
							cfg->cores_dir,
							cores_cbdata.total_size,
							cfg->max_cores_size);
					rspamd_main->cores_throttling = TRUE;
				}
				if (cfg->max_cores_count &&
						cores_cbdata.total_count > cfg->max_cores_count) {
					msg_warn_main (
							"enable cores throttling as count of cores in"
									" %s is %z, limit is %z",
							cfg->cores_dir,
							cores_cbdata.total_count,
							cfg->max_cores_count);
					rspamd_main->cores_throttling = TRUE;
				}
			}
			else {
				if (cfg->max_cores_size &&
						cores_cbdata.total_size < cfg->max_cores_size) {
					msg_info_main (
							"disable cores throttling as size of cores in"
									" %s is now %Hz, limit is %Hz",
							cfg->cores_dir,
							cores_cbdata.total_size,
							cfg->max_cores_size);
					rspamd_main->cores_throttling = FALSE;
				}
				if (cfg->max_cores_count &&
						cores_cbdata.total_count < cfg->max_cores_count) {
					msg_info_main (
							"disable cores throttling as count of cores in"
									" %s is %z, limit is %z",
							cfg->cores_dir,
							cores_cbdata.total_count,
							cfg->max_cores_count);
					rspamd_main->cores_throttling = FALSE;
				}
			}
		}
	}
#endif
}

static void
reopen_log_handler (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_worker *w = value;
	struct rspamd_main *rspamd_main;

	rspamd_main = w->srv;

	if (kill (w->pid, SIGUSR1) == -1) {
		msg_err_main ("kill failed for pid %P: %s", w->pid, strerror (errno));
	}
}

static gboolean
load_rspamd_config (struct rspamd_main *rspamd_main,
		struct rspamd_config *cfg, gboolean init_modules,
		enum rspamd_post_load_options opts,
		gboolean reload)
{
	cfg->compiled_modules = modules;
	cfg->compiled_workers = workers;

	if (!rspamd_config_read (cfg, cfg->cfg_name, config_logger, rspamd_main,
			ucl_vars, skip_template, lua_env)) {
		return FALSE;
	}

	/* Strictly set temp dir */
	if (!cfg->temp_dir) {
		msg_warn_main ("tempdir is not set, trying to use $TMPDIR");
		cfg->temp_dir =
			rspamd_mempool_strdup (cfg->cfg_pool, getenv ("TMPDIR"));

		if (!cfg->temp_dir) {
			msg_warn_main ("$TMPDIR is empty too, using /tmp as default");
			cfg->temp_dir = rspamd_mempool_strdup (cfg->cfg_pool, "/tmp");
		}
	}

	if (!reload) {
		/*
		 * As some rules are defined in lua, we need to process them, then init
		 * modules and merely afterwards to init modules
		 */
		rspamd_lua_post_load_config (cfg);

		if (init_modules) {
			if (!rspamd_init_filters (cfg, reload, false)) {
				return FALSE;
			}
		}

		/* Do post-load actions */
		if (!rspamd_config_post_load (cfg, opts)) {
			return FALSE;
		}
	}

	return TRUE;
}

static void
rspamd_detach_worker (struct rspamd_main *rspamd_main, struct rspamd_worker *wrk)
{
	ev_io_stop (rspamd_main->event_loop, &wrk->srv_ev);
	ev_timer_stop (rspamd_main->event_loop, &wrk->hb.heartbeat_ev);
}

static void
rspamd_attach_worker (struct rspamd_main *rspamd_main, struct rspamd_worker *wrk)
{
	ev_io_start (rspamd_main->event_loop, &wrk->srv_ev);
	ev_timer_start (rspamd_main->event_loop, &wrk->hb.heartbeat_ev);
}

static void
stop_srv_ev (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_worker *cur = (struct rspamd_worker *)value;
	struct rspamd_main *rspamd_main = (struct rspamd_main *)ud;

	rspamd_detach_worker (rspamd_main, cur);
}

static void
start_srv_ev (gpointer key, gpointer value, gpointer ud)
{
	struct rspamd_worker *cur = (struct rspamd_worker *)value;
	struct rspamd_main *rspamd_main = (struct rspamd_main *)ud;

	rspamd_attach_worker (rspamd_main, cur);
}

static void
rspamd_final_timer_handler (EV_P_ ev_timer *w, int revents)
{
	struct rspamd_main *rspamd_main = (struct rspamd_main *)w->data;

	term_attempts--;

	g_hash_table_foreach (rspamd_main->workers, hash_worker_wait_callback,
			NULL);

	if (g_hash_table_size (rspamd_main->workers) == 0) {
		ev_break (rspamd_main->event_loop, EVBREAK_ALL);
	}
}

/* Signal handlers */
static void
rspamd_term_handler (struct ev_loop *loop, ev_signal *w, int revents)
{
	struct rspamd_main *rspamd_main = (struct rspamd_main *)w->data;
	static ev_timer ev_finale;
	ev_tstamp shutdown_ts;

	if (!rspamd_main->wanna_die) {
		rspamd_main->wanna_die = TRUE;
		shutdown_ts = MAX (SOFT_SHUTDOWN_TIME,
				rspamd_main->cfg->task_timeout * 2.0);
		msg_info_main ("catch termination signal, waiting for %d children for %.2f seconds",
				(gint)g_hash_table_size (rspamd_main->workers),
				valgrind_mode ? shutdown_ts * 10 : shutdown_ts);
		/* Stop srv events to avoid false notifications */
		g_hash_table_foreach (rspamd_main->workers, stop_srv_ev, rspamd_main);
		rspamd_pass_signal (rspamd_main->workers, SIGTERM);

		if (control_fd != -1) {
			ev_io_stop (rspamd_main->event_loop, &control_ev);
			close (control_fd);
		}

		if (valgrind_mode) {
			/* Special case if we are likely running with valgrind */
			term_attempts = shutdown_ts / TERMINATION_INTERVAL * 10;
		}
		else {
			term_attempts = shutdown_ts / TERMINATION_INTERVAL;
		}

		ev_finale.data = rspamd_main;
		ev_timer_init (&ev_finale, rspamd_final_timer_handler,
				TERMINATION_INTERVAL, TERMINATION_INTERVAL);
		ev_timer_start (rspamd_main->event_loop, &ev_finale);
	}
}

static void
rspamd_usr1_handler (struct ev_loop *loop, ev_signal *w, int revents)
{
	struct rspamd_main *rspamd_main = (struct rspamd_main *)w->data;

	if (!rspamd_main->wanna_die) {
		rspamd_log_reopen (rspamd_main->logger,
				rspamd_main->cfg,
				rspamd_main->workers_uid,
				rspamd_main->workers_gid);
		msg_info_main ("logging reinitialised");
		g_hash_table_foreach (rspamd_main->workers, reopen_log_handler,
				NULL);
	}
}

static void
rspamd_stat_update_handler (struct ev_loop *loop, ev_timer *w, int revents)
{
	struct rspamd_main *rspamd_main = (struct rspamd_main *)w->data;
	struct rspamd_stat cur_stat;
	gchar proctitle[128];

	memcpy (&cur_stat, rspamd_main->stat, sizeof (cur_stat));

	if (old_stat.messages_scanned > 0 &&
		cur_stat.messages_scanned > old_stat.messages_scanned) {
		gdouble rate = (double)(cur_stat.messages_scanned - old_stat.messages_scanned) /
				w->repeat;
		gdouble old_spam = old_stat.actions_stat[METRIC_ACTION_REJECT] +
				old_stat.actions_stat[METRIC_ACTION_ADD_HEADER] +
				old_stat.actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
		gdouble old_ham = old_stat.actions_stat[METRIC_ACTION_NOACTION];
		gdouble new_spam = cur_stat.actions_stat[METRIC_ACTION_REJECT] +
				cur_stat.actions_stat[METRIC_ACTION_ADD_HEADER] +
				cur_stat.actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
		gdouble new_ham = cur_stat.actions_stat[METRIC_ACTION_NOACTION];

		rspamd_snprintf (proctitle, sizeof (proctitle),
				"main process; %.1f msg/sec, %.1f msg/sec spam, %.1f msg/sec ham",
				rate,
				(new_spam - old_spam) / w->repeat,
				(new_ham - old_ham) / w->repeat);
		setproctitle (proctitle);
	}

	memcpy (&old_stat, &cur_stat, sizeof (cur_stat));
}

static void
rspamd_hup_handler (struct ev_loop *loop, ev_signal *w, int revents)
{
	struct rspamd_main *rspamd_main = (struct rspamd_main *)w->data;

	if (!rspamd_main->wanna_die) {
		msg_info_main ("rspamd "
				RVERSION
				" is requested to reload configuration");
		/* Detach existing workers and stop their heartbeats */
		g_hash_table_foreach (rspamd_main->workers, stop_srv_ev, rspamd_main);

		if (reread_config (rspamd_main)) {
			rspamd_check_core_limits (rspamd_main);
			/* Mark old workers */
			g_hash_table_foreach (rspamd_main->workers, mark_old_workers, NULL);
			msg_info_main ("spawn workers with a new config");
			spawn_workers (rspamd_main, rspamd_main->event_loop);
			msg_info_main ("workers spawning has been finished");
			/* Kill marked */
			msg_info_main ("kill old workers");
			g_hash_table_foreach (rspamd_main->workers, kill_old_workers, NULL);
		}
		else {
			/* Reattach old workers */
			msg_info_main ("restore old workers with a old config");
			g_hash_table_foreach (rspamd_main->workers, start_srv_ev, rspamd_main);
		}
	}
}

/* Called when a dead child has been found */

static void
rspamd_cld_handler (EV_P_ ev_child *w, struct rspamd_main *rspamd_main,
					struct rspamd_worker *wrk)
{
	gboolean need_refork;
	static struct rspamd_control_command cmd;

	/* Turn off locking for logger */
	ev_child_stop (EV_A_ w);

	/* Remove dead child form children list */
	g_hash_table_remove (rspamd_main->workers, GSIZE_TO_POINTER (wrk->pid));
	g_hash_table_remove_all (wrk->control_events_pending);

	if (wrk->srv_pipe[0] != -1) {
		/* Ugly workaround */
		if (wrk->tmp_data) {
			g_free (wrk->tmp_data);
		}

		rspamd_detach_worker (rspamd_main, wrk);
	}

	if (wrk->control_pipe[0] != -1) {
		/* We also need to clean descriptors left */
		close (wrk->control_pipe[0]);
		close (wrk->srv_pipe[0]);
	}

	if (!rspamd_main->wanna_die) {
		cmd.type = RSPAMD_CONTROL_CHILD_CHANGE;
		cmd.cmd.child_change.what = rspamd_child_terminated;
		cmd.cmd.child_change.pid = wrk->pid;
		cmd.cmd.child_change.additional = w->rstatus;
		rspamd_control_broadcast_srv_cmd (rspamd_main, &cmd, wrk->pid);
	}

	need_refork = rspamd_check_termination_clause (wrk->srv, wrk, w->rstatus);

	if (need_refork) {
		/* Fork another worker in replace of dead one */
		msg_info_main ("respawn process %s in lieu of terminated process with pid %P",
				g_quark_to_string (wrk->type),
				wrk->pid);
		rspamd_check_core_limits (rspamd_main);
		rspamd_fork_delayed (wrk->cf, wrk->index, rspamd_main);
	}
	else {
		msg_info_main ("do not respawn process %s after found terminated process with pid %P",
				g_quark_to_string (wrk->type),
				wrk->pid);
	}

	REF_RELEASE (wrk->cf);
	g_hash_table_unref (wrk->control_events_pending);
	g_free (wrk);
}

/* Control socket handler */
static void
rspamd_control_handler (EV_P_ ev_io *w, int revents)
{
	struct rspamd_main *rspamd_main = (struct rspamd_main *)w->data;
	rspamd_inet_addr_t *addr = NULL;
	gint nfd;

	if ((nfd =
				 rspamd_accept_from_socket (w->fd, &addr, NULL, NULL)) == -1) {
		msg_warn_main ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		rspamd_inet_address_free (addr);
		return;
	}

	msg_info_main ("accepted control connection from %s",
			rspamd_inet_address_to_string (addr));

	rspamd_control_process_client_socket (rspamd_main, nfd, addr);
}

static guint
rspamd_spair_hash (gconstpointer p)
{
	return rspamd_cryptobox_fast_hash (p, PAIR_ID_LEN, rspamd_hash_seed ());
}

static gboolean
rspamd_spair_equal (gconstpointer a, gconstpointer b)
{
	return memcmp (a, b, PAIR_ID_LEN) == 0;
}

static void
rspamd_spair_close (gpointer p)
{
	gint *fds = p;

	close (fds[0]);
	close (fds[1]);
	g_free (p);
}

static void
version (void)
{
#if defined(GIT_VERSION) && GIT_VERSION == 1
	rspamd_printf ("Rspamd daemon version " RVERSION "-git." RID "\n");
#else
	rspamd_printf ("Rspamd daemon version " RVERSION "\n");
#endif
}

static gboolean
rspamd_main_daemon (struct rspamd_main *rspamd_main)
{
	int fd;
	pid_t old_pid = getpid ();

	switch (fork ()) {
	case -1:
		msg_err_main ("fork() failed: %s", strerror (errno));
		return FALSE;

	case 0:
		break;

	default:
		/* Old process */
		exit (0);
	}

	rspamd_log_on_fork (g_quark_from_static_string ("main"),
			rspamd_main->cfg,
			rspamd_main->logger);

	if (setsid () == -1) {
		msg_err_main ("setsid () failed: %s", strerror (errno));
		return FALSE;
	}

	umask (0);

	fd = open ("/dev/null", O_RDWR);
	if (fd == -1) {
		msg_err_main ("open(\"/dev/null\") failed: %s", strerror (errno));
		return FALSE;
	}

	if (dup2 (fd, STDIN_FILENO) == -1) {
		msg_err_main ("dup2(STDIN) failed: %s", strerror (errno));
		return FALSE;
	}

	if (dup2 (fd, STDOUT_FILENO) == -1) {
		msg_err_main ("dup2(STDOUT) failed: %s", strerror (errno));
		return FALSE;
	}

	if (fd > STDERR_FILENO) {
		if (close(fd) == -1) {
			msg_err_main ("close() failed: %s", strerror (errno));
			return FALSE;
		}
	}

	msg_info_main ("daemonized successfully; old pid %P, new pid %P; pid file: %s",
			old_pid, getpid (),
			rspamd_main->cfg->pid_file);

	return TRUE;
}

gint
main (gint argc, gchar **argv, gchar **env)
{
	gint i, res = 0;
	struct sigaction signals, sigpipe_act;
	worker_t **pworker;
	GQuark type;
	rspamd_inet_addr_t *control_addr = NULL;
	struct ev_loop *event_loop;
	struct rspamd_main *rspamd_main;
	gboolean skip_pid = FALSE;
	sigset_t control_signals;

	/* Block special signals on loading */
	sigemptyset (&control_signals);
	sigaddset (&control_signals, SIGHUP);
	sigaddset (&control_signals, SIGUSR1);
	sigaddset (&control_signals, SIGUSR2);
	sigprocmask (SIG_BLOCK, &control_signals, NULL);

	rspamd_main = (struct rspamd_main *) g_malloc0 (sizeof (struct rspamd_main));

	rspamd_main->server_pool = rspamd_mempool_new (rspamd_mempool_suggest_size (),
			"main", 0);
	rspamd_main->stat = rspamd_mempool_alloc0_shared (rspamd_main->server_pool,
			sizeof (struct rspamd_stat));
	rspamd_main->cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_DEFAULT);
	rspamd_main->spairs = g_hash_table_new_full (rspamd_spair_hash,
			rspamd_spair_equal, g_free, rspamd_spair_close);
	rspamd_main->start_mtx = rspamd_mempool_get_mutex (rspamd_main->server_pool);

	if (getenv ("VALGRIND") != NULL) {
		valgrind_mode = TRUE;
	}

#ifndef HAVE_SETPROCTITLE
	init_title (rspamd_main->server_pool, argc, argv, env);
#endif

	rspamd_main->cfg->libs_ctx = rspamd_init_libs ();
	memset (&signals, 0, sizeof (struct sigaction));

	read_cmd_line (&argc, &argv, rspamd_main->cfg);

	if (show_version) {
		version ();
		exit (EXIT_SUCCESS);
	}

	if (argc > 0) {
		/* Parse variables */
		for (i = 0; i < argc; i++) {
			if (strchr (argv[i], '=') != NULL) {
				gchar *k, *v, *t;

				k = g_strdup (argv[i]);
				t = strchr (k, '=');
				v = g_strdup (t + 1);
				*t = '\0';

				if (ucl_vars == NULL) {
					ucl_vars = g_hash_table_new_full (rspamd_strcase_hash,
							rspamd_strcase_equal, g_free, g_free);
				}

				g_hash_table_insert (ucl_vars, k, v);
			}
		}
	}

	if (is_debug) {
		rspamd_main->cfg->log_level = G_LOG_LEVEL_DEBUG;
	}
	else {
		rspamd_main->cfg->log_level = G_LOG_LEVEL_MESSAGE;
	}

	type = g_quark_from_static_string ("main");

	/* First set logger to console logger */
	rspamd_main->logger = rspamd_log_open_emergency (rspamd_main->server_pool, 0);
	g_assert (rspamd_main->logger != NULL);

	if (is_debug) {
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_DEBUG);
	}
	else {
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_MESSAGE);
	}

	g_log_set_default_handler (rspamd_glib_log_function, rspamd_main->logger);
	g_set_printerr_handler (rspamd_glib_printerr_function);

	detect_priv (rspamd_main);

	msg_notice_main ("rspamd "
			RVERSION
			" is loading configuration, build id: "
			RID);

	pworker = &workers[0];
	while (*pworker) {
		/* Init string quarks */
		(void) g_quark_from_static_string ((*pworker)->name);
		pworker++;
	}

	/* Init listen sockets hash */
	listen_sockets = g_hash_table_new (g_direct_hash, g_direct_equal);
	sqlite3_initialize ();

	/* Load config */
	if (!load_rspamd_config (rspamd_main, rspamd_main->cfg, TRUE,
			RSPAMD_CONFIG_LOAD_ALL, FALSE)) {
		exit (EXIT_FAILURE);
	}

	/* Override pidfile from configuration by command line argument */
	if (rspamd_pidfile != NULL) {
		rspamd_main->cfg->pid_file = rspamd_pidfile;
	}

	/* Force debug log */
	if (is_debug) {
		rspamd_log_set_log_level (rspamd_main->logger, G_LOG_LEVEL_DEBUG);
	}

	/* Create rolling history */
	rspamd_main->history = rspamd_roll_history_new (rspamd_main->server_pool,
			rspamd_main->cfg->history_rows, rspamd_main->cfg);

	msg_info_main ("rspamd "
			RVERSION
			" is starting, build id: "
			RID);
	rspamd_main->cfg->cfg_name = rspamd_mempool_strdup (
			rspamd_main->cfg->cfg_pool,
			rspamd_main->cfg->cfg_name);
	msg_info_main ("cpu features: %s",
			rspamd_main->cfg->libs_ctx->crypto_ctx->cpu_extensions);
	msg_info_main ("cryptobox configuration: curve25519(libsodium), "
			"chacha20(%s), poly1305(libsodium), siphash(libsodium), blake2(libsodium), base64(%s)",
			rspamd_main->cfg->libs_ctx->crypto_ctx->chacha20_impl,
			rspamd_main->cfg->libs_ctx->crypto_ctx->base64_impl);
	msg_info_main ("libottery prf: %s", ottery_get_impl_name ());

	/* Daemonize */
	if (!no_fork) {
		if (!rspamd_main_daemon (rspamd_main)) {
			exit (EXIT_FAILURE);
		}

		/* Close emergency logger */
		rspamd_log_close (rspamd_log_emergency_logger ());
	}

	/* Write info */
	rspamd_main->pid = getpid ();
	rspamd_main->type = type;

	if (!valgrind_mode) {
		rspamd_set_crash_handler (rspamd_main);
	}

	/* Ignore SIGPIPE as we handle write errors manually */
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction (SIGPIPE, &sigpipe_act, NULL);

	if (rspamd_main->cfg->pid_file == NULL) {
		msg_info_main ("pid file is not specified, skipping writing it");
		skip_pid = TRUE;
	}
	else if (no_fork) {
		msg_info_main ("skip writing pid in no-fork mode");
		skip_pid = TRUE;
	}
	else if (rspamd_write_pid (rspamd_main) == -1) {
		msg_err_main ("cannot write pid file %s", rspamd_main->cfg->pid_file);
		exit (-errno);
	}

	sigprocmask (SIG_BLOCK, &signals.sa_mask, NULL);

	/* Set title */
	setproctitle ("main process");

	/* Open control socket if needed */
	control_fd = -1;
	if (rspamd_main->cfg->control_socket_path) {
		if (!rspamd_parse_inet_address (&control_addr,
				rspamd_main->cfg->control_socket_path,
				strlen (rspamd_main->cfg->control_socket_path),
				RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			msg_err_main ("cannot parse inet address %s",
					rspamd_main->cfg->control_socket_path);
		}
		else {
			control_fd = rspamd_inet_address_listen (control_addr, SOCK_STREAM,
					RSPAMD_INET_ADDRESS_LISTEN_ASYNC, -1);
			if (control_fd == -1) {
				msg_err_main ("cannot open control socket at path: %s",
						rspamd_main->cfg->control_socket_path);
			}
		}
	}

	/* Maybe read roll history */
	if (rspamd_main->cfg->history_file) {
		rspamd_roll_history_load (rspamd_main->history,
			rspamd_main->cfg->history_file);
	}

	/* Init workers hash */
	rspamd_main->workers = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* Unblock control signals */
	sigprocmask (SIG_UNBLOCK, &control_signals, NULL);
	/* Init event base */
	event_loop = ev_default_loop (rspamd_config_ev_backend_get (rspamd_main->cfg));
	rspamd_main->event_loop = event_loop;

	if (event_loop) {
		int loop_type = ev_backend (event_loop);
		gboolean effective_backend;
		const gchar *loop_str;

		loop_str =
				rspamd_config_ev_backend_to_string (loop_type, &effective_backend);

		if (!effective_backend) {
			msg_warn_main ("event loop uses non-optimal backend: %s", loop_str);
		}
		else {
			msg_info_main ("event loop initialised with backend: %s", loop_str);
		}
	}
	else {
		msg_err ("cannot init event loop! exiting");
		exit (EXIT_FAILURE);
	}

	/* Unblock signals */
	sigemptyset (&signals.sa_mask);
	sigprocmask (SIG_SETMASK, &signals.sa_mask, NULL);

	/* Set events for signals */
	ev_signal_init (&rspamd_main->term_ev, rspamd_term_handler, SIGTERM);
	rspamd_main->term_ev.data = rspamd_main;
	ev_signal_start (event_loop, &rspamd_main->term_ev);

	ev_signal_init (&rspamd_main->int_ev, rspamd_term_handler, SIGINT);
	rspamd_main->int_ev.data = rspamd_main;
	ev_signal_start (event_loop, &rspamd_main->int_ev);

	ev_signal_init (&rspamd_main->hup_ev, rspamd_hup_handler, SIGHUP);
	rspamd_main->hup_ev.data = rspamd_main;
	ev_signal_start (event_loop, &rspamd_main->hup_ev);

	ev_signal_init (&rspamd_main->usr1_ev, rspamd_usr1_handler, SIGUSR1);
	rspamd_main->usr1_ev.data = rspamd_main;
	ev_signal_start (event_loop, &rspamd_main->usr1_ev);

	/* Update proctitle according to number of messages processed */
	static const ev_tstamp stat_update_time = 10.0;

	memset (&old_stat, 0, sizeof (old_stat));
	stat_ev.data = rspamd_main;
	ev_timer_init (&stat_ev, rspamd_stat_update_handler,
			stat_update_time, stat_update_time);
	ev_timer_start (event_loop, &stat_ev);

	rspamd_check_core_limits (rspamd_main);
	rspamd_mempool_lock_mutex (rspamd_main->start_mtx);
	spawn_workers (rspamd_main, event_loop);
	rspamd_mempool_unlock_mutex (rspamd_main->start_mtx);

	rspamd_main->http_ctx = rspamd_http_context_create (rspamd_main->cfg,
			event_loop, rspamd_main->cfg->ups_ctx);

	if (control_fd != -1) {
		msg_info_main ("listening for control commands on %s",
				rspamd_inet_address_to_string (control_addr));
		ev_io_init (&control_ev, rspamd_control_handler, control_fd, EV_READ);
		control_ev.data = rspamd_main;
		ev_io_start (event_loop, &control_ev);
	}

	ev_loop (event_loop, 0);

	/* Maybe save roll history */
	if (rspamd_main->cfg->history_file) {
		rspamd_roll_history_save (rspamd_main->history,
			rspamd_main->cfg->history_file);
	}

	if (rspamd_main->cfg->cache) {
		rspamd_symcache_save(rspamd_main->cfg->cache);
	}

	msg_info_main ("terminating...");

	REF_RELEASE (rspamd_main->cfg);
	rspamd_log_close (rspamd_main->logger);
	g_hash_table_unref (rspamd_main->spairs);
	g_hash_table_unref (rspamd_main->workers);
	rspamd_mempool_delete (rspamd_main->server_pool);

	if (!skip_pid) {
		rspamd_pidfile_close (rspamd_main->pfh);
	}

	g_free (rspamd_main);
	ev_unref (event_loop);
	sqlite3_shutdown ();

	if (control_addr) {
		rspamd_inet_address_free (control_addr);
	}

	return (res);
}
