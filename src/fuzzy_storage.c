/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Rspamd fuzzy storage server
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "url.h"
#include "modules.h"
#include "message.h"
#include "fuzzy.h"
#include "bloom.h"
#include "fuzzy_storage.h"

#ifdef WITH_JUDY
#include <Judy.h>
#endif

/* This number is used as limit while comparing two fuzzy hashes, this value can vary from 0 to 100 */
#define LEV_LIMIT 99
/* This number is used as limit while we are making decision to write new hash file or not */
#define MOD_LIMIT 10000
/* This number is used as expire time in seconds for cache items  (2 days) */
#define DEFAULT_EXPIRE 172800L
/* Resync value in seconds */
#define SYNC_TIMEOUT 60
/* Number of hash buckets */
#define BUCKETS 1024
/* Number of insuccessfull bind retries */
#define MAX_RETRIES 40
/* Weight of hash to consider it frequent */
#define DEFAULT_FREQUENT_SCORE 100
/* Magic sequence for hashes file */
#define FUZZY_FILE_MAGIC "rsh"
/* Current version of fuzzy hash file format */
#define CURRENT_FUZZY_VERSION 1

static GQueue                  *hashes[BUCKETS];
static GQueue                  *frequent;
#ifdef WITH_JUDY
static gpointer                 jtree;
static gboolean                 use_judy = FALSE;
#endif
static bloom_filter_t          *bf;

/* Number of cache modifications */
static uint32_t                 mods = 0;
/* Frequent score number */
static uint32_t                 frequent_score = DEFAULT_FREQUENT_SCORE;
/* For evtimer */
static struct timeval           tmv;
static struct event             tev;
static struct rspamd_stat      *server_stat;

struct rspamd_fuzzy_node {
	int32_t                         value;
	int32_t                         flag;
	uint64_t                        time;
	fuzzy_hash_t                    h;
};


#ifndef HAVE_SA_SIGINFO
static void
sig_handler (int signo)
#else
static void
sig_handler (int signo, siginfo_t *info, void *unused)
#endif
{
	switch (signo) {
	case SIGINT:
		/* Ignore SIGINT as we should got SIGTERM after it anyway */
		return;
	case SIGTERM:
#ifdef WITH_PROFILER
		exit (0);
#else
		_exit (1);
#endif
		break;
	}
}

static gint
compare_nodes (gconstpointer a, gconstpointer b, gpointer unused)
{
	const struct rspamd_fuzzy_node *n1 = a, *n2 = b;

	return n1->value - n2->value;
}

static void
sync_cache (struct rspamd_worker *wrk)
{
	int                             fd, i;
	char                           *filename, *exp_str, header[4];
	GList                          *cur, *tmp;
	struct rspamd_fuzzy_node       *node;
	uint64_t                        expire, now;
#ifdef WITH_JUDY
	PPvoid_t                        pvalue;
	char                            indexbuf[1024], tmpindex[1024];
#endif

	/* Check for modifications */
	if (mods < MOD_LIMIT) {
		return;
	}

	msg_info ("syncing fuzzy hash storage");
	filename = g_hash_table_lookup (wrk->cf->params, "hashfile");
	if (filename == NULL) {
		return;
	}
	exp_str = g_hash_table_lookup (wrk->cf->params, "expire");
	if (exp_str != NULL) {
		expire = parse_seconds (exp_str) / 1000;
	}
	else {
		expire = DEFAULT_EXPIRE;
	}
	
	if ((fd = open (filename, O_WRONLY | O_TRUNC | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)) == -1) {
		msg_err ("cannot create hash file %s: %s", filename, strerror (errno));
		return;
	}

	(void)lock_file (fd, FALSE);

	now = (uint64_t) time (NULL);
	
	/* Fill header */
	memcpy (header, FUZZY_FILE_MAGIC, 3);
	header[3] = (char)CURRENT_FUZZY_VERSION;
	if (write (fd, header, sizeof (header)) == -1) {
		msg_err ("cannot write file %s while writing header: %s", filename, strerror (errno));
		goto end;
	}

#ifdef WITH_JUDY
	if (use_judy) {
		indexbuf[0] = '\0';
		pvalue = JudySLFirst (jtree, indexbuf, PJE0);
		while (pvalue) {
			node = *((struct rspamd_fuzzy_node **)pvalue);
			if (now - node->time > expire) {
				/* Remove expired item */
				g_strlcpy (tmpindex, indexbuf, sizeof (tmpindex));
				pvalue = JudySLNext (jtree, tmpindex, PJE0);
				JudySLDel (&jtree, indexbuf, PJE0);
				g_strlcpy (indexbuf, tmpindex, sizeof (indexbuf));
				bloom_del (bf, node->h.hash_pipe);
				server_stat->fuzzy_hashes_expired ++;
				server_stat->fuzzy_hashes --;
				g_free (node);
				continue;
			}
			if (write (fd, node, sizeof (struct rspamd_fuzzy_node)) == -1) {
				msg_err ("cannot write file %s: %s", filename, strerror (errno));
				goto end;
			}
			pvalue = JudySLNext (jtree, indexbuf, PJE0);
		}
	}
	else {
#endif
	cur = frequent->head;
	while (cur) {
		node = cur->data;
		if (write (fd, node, sizeof (struct rspamd_fuzzy_node)) == -1) {
			msg_err ("cannot write file %s: %s", filename, strerror (errno));
		}
		cur = g_list_next (cur);
	}
	for (i = 0; i < BUCKETS; i++) {
		cur = hashes[i]->head;
		while (cur) {
			node = cur->data;
			if (now - node->time > expire) {
				/* Remove expired item */
				tmp = cur;
				cur = g_list_next (cur);
				g_queue_delete_link (hashes[i], tmp);
				bloom_del (bf, node->h.hash_pipe);
				server_stat->fuzzy_hashes_expired ++;
				server_stat->fuzzy_hashes --;
				g_free (node);
				continue;
			}
			if (write (fd, node, sizeof (struct rspamd_fuzzy_node)) == -1) {
				msg_err ("cannot write file %s: %s", filename, strerror (errno));
				goto end;
			}
			cur = g_list_next (cur);
		}
	}
#ifdef WITH_JUDY
	}
#endif

end:
	(void)unlock_file (fd, FALSE);
	close (fd);
}

static void
sigterm_handler (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	static struct timeval           tv = {
		.tv_sec = 0,
		.tv_usec = 0
	};

	mods = MOD_LIMIT + 1;
	sync_cache (worker);
	close (worker->cf->listen_sock);
	(void)event_loopexit (&tv);
}

/*
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr_handler (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;

	tv.tv_sec = SOFT_SHUTDOWN_TIME;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	close (worker->cf->listen_sock);
	do_reopen_log = 1;
	msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
	event_loopexit (&tv);
	return;
}

static                          gboolean
read_hashes_file (struct rspamd_worker *wrk)
{
	int                             r, fd, i, version = 0;
	struct stat                     st;
	char                           *filename, header[4];
	struct rspamd_fuzzy_node       *node;
	struct {
		int32_t                         value;
		uint64_t                        time;
		fuzzy_hash_t                    h;
	}								legacy_node;
#ifdef WITH_JUDY
	PPvoid_t                         pvalue;

	if (use_judy) {
		jtree = NULL;
	}
	else {
#endif
	for (i = 0; i < BUCKETS; i++) {
		hashes[i] = g_queue_new ();
	}
	frequent = g_queue_new ();
#ifdef WITH_JUDY
	}
#endif

	filename = g_hash_table_lookup (wrk->cf->params, "hashfile");
	if (filename == NULL) {
		return FALSE;
	}

	if ((fd = open (filename, O_RDONLY)) == -1) {
		msg_err ("cannot open hash file %s: %s", filename, strerror (errno));
		return FALSE;
	}

	(void)lock_file (fd, FALSE);

	fstat (fd, &st);

	/* First of all try to read magic and version number */
	if ((r = read (fd, header, sizeof (header))) == sizeof (header)) {
		if (memcmp (header, FUZZY_FILE_MAGIC, sizeof (header) - 1) == 0) {
			/* We have version in last byte of header */
			version = (int)header[3];
			if (version > CURRENT_FUZZY_VERSION) {
				msg_err ("unsupported version of fuzzy hash file: %d", version);
				return FALSE;
			}
			msg_info ("reading fuzzy hashes storage file of version %d of size %d", version, (int)(st.st_size - sizeof (header)) / sizeof (struct rspamd_fuzzy_node));
		}
		else {
			/* Old version */
			version = 0;
			msg_info ("got old version of fuzzy hashes storage, it would be converted to new version %d automatically", CURRENT_FUZZY_VERSION);
			/* Rewind file */
			(void)lseek (fd, 0, SEEK_SET);
		}
	}

	for (;;) {
		node = g_malloc (sizeof (struct rspamd_fuzzy_node));
		if (version == 0) {
			r = read (fd, &legacy_node, sizeof (legacy_node));
			if (r != sizeof (legacy_node)) {
				break;
			}
			node->value = legacy_node.value;
			node->time = legacy_node.time;
			memcpy (&node->h, &legacy_node.h, sizeof (fuzzy_hash_t));
			node->flag = 0;
		}
		else {
			r = read (fd, node, sizeof (struct rspamd_fuzzy_node));
			if (r != sizeof (struct rspamd_fuzzy_node)) {
				break;
			}
		}
#ifdef WITH_JUDY
		if (use_judy) {
			pvalue = JudySLIns (&jtree, node->h.hash_pipe, PJE0);
			*pvalue = node;
		}
		else {
#endif
		if (node->value > frequent_score) {
			g_queue_push_head (frequent, node);
		}
		else {
			g_queue_push_head (hashes[node->h.block_size % BUCKETS], node);
		}
#ifdef WITH_JUDY
		}
#endif
		bloom_add (bf, node->h.hash_pipe);
		server_stat->fuzzy_hashes ++;
	}

#ifdef WITH_JUDY
	if (!use_judy) {
#endif
	/* Sort everything */
	g_queue_sort (frequent, compare_nodes, NULL);
	for (i = 0; i < BUCKETS; i ++) {
		g_queue_sort (hashes[i], compare_nodes, NULL);
	}
#ifdef WITH_JUDY
	}
#endif

	(void)unlock_file (fd, FALSE);
	close (fd);

	if (r > 0) {
		msg_warn ("ignore garbadge at the end of file, length of garbadge: %d", r);
	}
	else if (r == -1) {
		msg_err ("cannot open read file %s: %s", filename, strerror (errno));
		return FALSE;
	}

	return TRUE;
}

static inline struct rspamd_fuzzy_node *
check_hash_node (GQueue *hash, fuzzy_hash_t *s, int update_value)
{
	GList                          *cur;
	struct rspamd_fuzzy_node       *h;
	int                             prob = 0;
#ifdef WITH_JUDY
	PPvoid_t                         pvalue;

	if (use_judy) {
		pvalue = JudySLGet (jtree, s->hash_pipe, PJE0);
		if (pvalue != NULL) {
			h = *((struct rspamd_fuzzy_node **)pvalue);
			/* Also check block size */
			if (h->h.block_size== s->block_size) {
				msg_info ("fuzzy hash was found in judy tree");
				if (update_value) {
					h->value += update_value;
				}
				return h;
			}
		}
	}
	else {
#endif
	cur = frequent->head;
	while (cur) {
		h = cur->data;
		if ((prob = fuzzy_compare_hashes (&h->h, s)) > LEV_LIMIT) {
			msg_info ("fuzzy hash was found, probability %d%%", prob);
			if (update_value) {
				msg_info ("new hash weight: %d", h->value);
				h->value += update_value;
			}
			return h;
		}
		cur = g_list_next (cur);
	}

	cur = hash->head;
	while (cur) {
		h = cur->data;
		if ((prob = fuzzy_compare_hashes (&h->h, s)) > LEV_LIMIT) {
			msg_info ("fuzzy hash was found, probability %d%%", prob);
			if (update_value) {
				h->value += update_value;
				msg_info ("new hash weight: %d", h->value);
			}
			if (h->value > frequent_score) {
				g_queue_unlink (hash, cur);
				g_queue_push_head_link (frequent, cur);
				msg_info ("moved hash to frequent list");
			}
			return h;
		}
		cur = g_list_next (cur);
	}
#ifdef WITH_JUDY
	}
#endif

	return NULL;
}

static                          int
process_check_command (struct fuzzy_cmd *cmd, int *flag)
{
	fuzzy_hash_t                    s;
	struct rspamd_fuzzy_node       *h;

	if (!bloom_check (bf, cmd->hash)) {
		return 0;
	}

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;

	h = check_hash_node (hashes[cmd->blocksize % BUCKETS], &s, 0);

	if (h == NULL) {
		return 0;
	}
	else {
		*flag = h->flag;
		return h->value;
	}
}

static                          gboolean
update_hash (struct fuzzy_cmd *cmd)
{
	fuzzy_hash_t                    s;

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;

	return check_hash_node (hashes[cmd->blocksize % BUCKETS], &s, cmd->value) != NULL;
}

static                          gboolean
process_write_command (struct fuzzy_cmd *cmd)
{
	struct rspamd_fuzzy_node       *h;
#ifdef WITH_JUDY
	PPvoid_t                         pvalue;
#endif

	if (bloom_check (bf, cmd->hash)) {
		if (update_hash (cmd)) {
			return TRUE;
		}
	}

	h = g_malloc (sizeof (struct rspamd_fuzzy_node));
	memcpy (&h->h.hash_pipe, &cmd->hash, sizeof (cmd->hash));
	h->h.block_size = cmd->blocksize;
	h->time = (uint64_t) time (NULL);
	h->value = cmd->value;
	h->flag = cmd->flag;
#ifdef WITH_JUDY
	if (use_judy) {
		pvalue = JudySLIns (&jtree, h->h.hash_pipe, PJE0);
		*pvalue = h;
	}
	else {
#endif

	g_queue_push_head (hashes[cmd->blocksize % BUCKETS], h);
#ifdef WITH_JUDY
	}
#endif
	bloom_add (bf, cmd->hash);
	mods++;
	server_stat->fuzzy_hashes ++;
	msg_info ("fuzzy hash was successfully added");

	return TRUE;
}

static gboolean
delete_hash (GQueue *hash, fuzzy_hash_t *s)
{
	GList                          *cur, *tmp;
	struct rspamd_fuzzy_node       *h;
	gboolean                        res = FALSE;
#ifdef WITH_JUDY
	PPvoid_t                         pvalue;

	if (use_judy) {
		pvalue = JudySLGet (jtree, s->hash_pipe, PJE0);
		if (pvalue) {
			res = JudySLDel (&jtree, s->hash_pipe, PJE0);
			g_free (*pvalue);
		}
	}
	else {
#endif
	cur = hash->head;

	/* XXX: too slow way */
	while (cur) {
		h = cur->data;
		if (fuzzy_compare_hashes (&h->h, s) > LEV_LIMIT) {
			g_free (h);
			tmp = cur;
			cur = g_list_next (cur);
			g_queue_delete_link (hash, tmp);
			bloom_del (bf, s->hash_pipe);
			msg_info ("fuzzy hash was successfully deleted");
			server_stat->fuzzy_hashes --;
			mods++;
			res = TRUE;
			continue;
		}
		cur = g_list_next (cur);
	}
#ifdef WITH_JUDY
	}
#endif

	return res;

}

static                          gboolean
process_delete_command (struct fuzzy_cmd *cmd)
{
	fuzzy_hash_t                    s;
	gboolean                        res = FALSE;

	if (!bloom_check (bf, cmd->hash)) {
		return FALSE;
	}

	memcpy (s.hash_pipe, cmd->hash, sizeof (s.hash_pipe));
	s.block_size = cmd->blocksize;
#ifdef WITH_JUDY
	if (use_judy) {
		return delete_hash (NULL, &s);
	}
	else {
#endif
	res = delete_hash (frequent, &s);
	if (!res) {
		res = delete_hash (hashes[cmd->blocksize % BUCKETS], &s);
	}
	else {
		(void)delete_hash (hashes[cmd->blocksize % BUCKETS], &s);
	}
#ifdef WITH_JUDY
	}
#endif

	return res;
}

#define CMD_PROCESS(x)																			\
do {																							\
if (process_##x##_command (&session->cmd)) {													\
	if (sendto (session->fd, "OK" CRLF, sizeof ("OK" CRLF) - 1, 0, (struct sockaddr *)&session->sa, session->salen) == -1) {							\
		msg_err ("error while writing reply: %s", strerror (errno));		\
	}																							\
}																								\
else {																							\
	if (sendto (session->fd, "ERR" CRLF, sizeof ("ERR" CRLF) - 1, 0, (struct sockaddr *)&session->sa, session->salen) == -1) {						\
		msg_err ("error while writing reply: %s", strerror (errno));		\
	}																							\
}																								\
} while(0)

static void
process_fuzzy_command (struct fuzzy_session *session)
{
	int r, flag = 0;
	char buf[64];

	switch (session->cmd.cmd) {
	case FUZZY_CHECK:
		if ((r = process_check_command (&session->cmd, &flag))) {
			r = snprintf (buf, sizeof (buf), "OK %d %d" CRLF, r, flag);
			if (sendto (session->fd, buf, r, 0, (struct sockaddr *)&session->sa, session->salen) == -1) {
				msg_err ("error while writing reply: %s", strerror (errno));
			}
		}
		else {
			if (sendto (session->fd, "ERR" CRLF, sizeof ("ERR" CRLF) - 1, 0, (struct sockaddr *)&session->sa, session->salen) == -1) {
				msg_err ("error while writing reply: %s", strerror (errno));
			}
		}
		break;
	case FUZZY_WRITE:
		CMD_PROCESS (write);
		break;
	case FUZZY_DEL:
		CMD_PROCESS (delete);
		break;
	default:
		if (sendto (session->fd, "ERR" CRLF, sizeof ("ERR" CRLF) - 1, 0, (struct sockaddr *)&session->sa, session->salen) == -1) {
			msg_err ("error while writing reply: %s", strerror (errno));
		}
		break;
	}
}

#undef CMD_PROCESS


/*
 * Accept new connection and construct task
 */
static void
accept_fuzzy_socket (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	struct fuzzy_session            session;
	ssize_t                         r;
	struct {
		u_char                      cmd;
		uint32_t                    blocksize;
		int32_t                     value;
		u_char                      hash[FUZZY_HASHLEN];
	}								legacy_cmd;


	session.worker = worker;
	session.fd = fd;
	session.pos = (u_char *) & session.cmd;
	session.salen = sizeof (session.sa);

	/* Got some data */
	if (what == EV_READ) {
		if ((r = recvfrom (fd, session.pos, sizeof (struct fuzzy_cmd), MSG_WAITALL, (struct sockaddr *)&session.sa, &session.salen)) == -1) {
			msg_err ("got error while reading from socket: %d, %s", errno, strerror (errno));
			return;
		}
		else if (r == sizeof (struct fuzzy_cmd)) {
			/* Assume that the whole command was read */
			process_fuzzy_command (&session);
		}
		else if (r == sizeof (legacy_cmd)) {
			/* Process requests from old rspamd */
			memcpy (&legacy_cmd, session.pos, sizeof (legacy_cmd));
			session.cmd.cmd = legacy_cmd.cmd;
			session.cmd.blocksize = legacy_cmd.blocksize;
			session.cmd.value = legacy_cmd.value;
			session.cmd.flag = 0;
			memcpy (session.cmd.hash, legacy_cmd.hash, sizeof (legacy_cmd.hash));
			process_fuzzy_command (&session);
		}
		else {
			msg_err ("got incomplete data while reading from socket: %d, %s", errno, strerror (errno));
			return;
		}
	}
}

static void
sync_callback (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Timer event */
	evtimer_set (&tev, sync_callback, worker);
	/* Plan event with jitter */
	tmv.tv_sec = SYNC_TIMEOUT + SYNC_TIMEOUT * g_random_double ();
	tmv.tv_usec = 0;
	evtimer_add (&tev, &tmv);

	sync_cache (worker);
}

/*
 * Start worker process
 */
void
start_fuzzy_storage (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	struct event                    sev;
	int                             retries = 0;
	char                           *value;

	worker->srv->pid = getpid ();
	worker->srv->type = TYPE_FUZZY;

	event_init ();

	server_stat = worker->srv->stat;

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *)worker);
	signal_add (&worker->sig_ev, NULL);
	signal_set (&sev, SIGTERM, sigterm_handler, (void *)worker);
	signal_add (&sev, NULL);
	/* Get params */
	if ((value = g_hash_table_lookup (worker->cf->params, "frequent_score")) != NULL) {
		frequent_score = strtol (value, NULL, 10);
	}
	if ((value = g_hash_table_lookup (worker->cf->params, "use_judy")) != NULL) {
#ifdef WITH_JUDY
		use_judy = TRUE;
#else
		msg_err ("cannot use judy storage as judy support is not compiled in");
#endif
	}

	/* Init bloom filter */
	bf = bloom_create (20000000L, DEFAULT_BLOOM_HASHES);
	/* Try to read hashes from file */
	if (!read_hashes_file (worker)) {
		msg_err ("cannot read hashes file, it can be created after save procedure");
	}
	/* Timer event */
	evtimer_set (&tev, sync_callback, worker);
	/* Plan event with jitter */
	tmv.tv_sec = SYNC_TIMEOUT + SYNC_TIMEOUT * g_random_double ();
	tmv.tv_usec = 0;
	evtimer_add (&tev, &tmv);

	/* Accept event */
	while ((worker->cf->listen_sock = make_udp_socket (&worker->cf->bind_addr, worker->cf->bind_port, TRUE, TRUE)) == -1) {
		sleep (1);
		if (++retries > MAX_RETRIES) {
			msg_err ("cannot bind to socket, exiting");
			exit (0);
		}
	}
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_fuzzy_socket, (void *)worker);
	event_add (&worker->bind_ev, NULL);

	gperf_profiler_init (worker->srv->cfg, "fuzzy");


	event_loop (0);
	exit (EXIT_SUCCESS);
}
