/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "rdns.h"
#include "dns_private.h"
#include "ottery.h"
#include "util.h"
#include "packet.h"
#include "parse.h"
#include "logger.h"
#include "compression.h"

static int
rdns_send_request (struct rdns_request *req, int fd, bool new_req)
{
	int r;
	struct rdns_server *serv = req->io->srv;
	struct rdns_resolver *resolver = req->resolver;
	struct rdns_request *tmp;
	struct dns_header *header;
	const int max_id_cycles = 32;

	/* Find ID collision */
	if (new_req) {
		r = 0;
		HASH_FIND_INT (req->io->requests, &req->id, tmp);
		while (tmp != NULL) {
			/* Check for unique id */
			header = (struct dns_header *)req->packet;
			header->qid = rdns_permutor_generate_id ();
			req->id = header->qid;
			if (++r > max_id_cycles) {
				return -1;
			}
			HASH_FIND_INT (req->io->requests, &req->id, tmp);
		}
	}

	if (resolver->curve_plugin == NULL) {
		r = send (fd, req->packet, req->pos, 0);
	}
	else {
		r = resolver->curve_plugin->cb.curve_plugin.send_cb (req,
				resolver->curve_plugin->data);
	}
	if (r == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			if (new_req) {
				/* Write when socket is ready */
				HASH_ADD_INT (req->io->requests, id, req);
				req->async_event = resolver->async->add_write (resolver->async->data,
					fd, req);
			}
			/*
			 * If request is already processed then the calling function
			 * should take care about events processing
			 */
			return 0;
		} 
		else {
			rdns_debug ("send failed: %s for server %s", strerror (errno), serv->name);
			return -1;
		}
	}
	
	if (new_req) {
		/* Add request to hash table */
		HASH_ADD_INT (req->io->requests, id, req);
		/* Fill timeout */
		req->async_event = resolver->async->add_timer (resolver->async->data,
				req->timeout, req);
		req->state = RDNS_REQUEST_SENT;
	}

	return 1;
}


static struct rdns_reply *
rdns_make_reply (struct rdns_request *req, enum dns_rcode rcode)
{
	struct rdns_reply *rep;

	rep = malloc (sizeof (struct rdns_reply));
	if (rep != NULL) {
		rep->request = req;
		rep->resolver = req->resolver;
		rep->entries = NULL;
		rep->code = rcode;
		req->reply = rep;
	}

	return rep;
}

static struct rdns_request *
rdns_find_dns_request (uint8_t *in, struct rdns_io_channel *ioc)
{
	struct dns_header *header = (struct dns_header *)in;
	struct rdns_request *req;
	int id;
	struct rdns_resolver *resolver = ioc->resolver;
	
	id = header->qid;
	HASH_FIND_INT (ioc->requests, &id, req);
	if (req == NULL) {
		/* No such requests found */
		rdns_debug ("DNS request with id %d has not been found for IO channel", (int)id);
	}

	return req;
}

static bool
rdns_parse_reply (uint8_t *in, int r, struct rdns_request *req,
		struct rdns_reply **_rep)
{
	struct dns_header *header = (struct dns_header *)in;
	struct rdns_reply *rep;
	struct rdns_reply_entry *elt;
	uint8_t *pos, *npos;
	struct rdns_resolver *resolver = req->resolver;
	uint16_t qdcount;
	int type;
	bool found = false;

	int i, t;

	/* First check header fields */
	if (header->qr == 0) {
		rdns_info ("got request while waiting for reply");
		return false;
	}

	qdcount = ntohs (header->qdcount);

	if (qdcount != req->qcount) {
		rdns_info ("request has %d queries, reply has %d queries", (int)req->qcount, (int)header->qdcount);
		return false;
	}

	/* 
	 * Now we have request and query data is now at the end of header, so compare
	 * request QR section and reply QR section
	 */
	req->pos = sizeof (struct dns_header);
	pos = in + sizeof (struct dns_header);
	t = r - sizeof (struct dns_header);
	for (i = 0; i < (int)qdcount; i ++) {
		if ((npos = rdns_request_reply_cmp (req, pos,t)) == NULL) {
			rdns_info ("DNS request with id %d is for different query, ignoring", (int)req->id);
			return false;
		}
		t -= npos - pos;
		pos = npos;
	}
	/*
	 * Now pos is in answer section, so we should extract data and form reply
	 */
	rep = rdns_make_reply (req, header->rcode);

	if (rep == NULL) {
		rdns_warn ("Cannot allocate memory for reply");
		return false;
	}

	type = req->requested_names[0].type;

	if (rep->code == RDNS_RC_NOERROR) {
		r -= pos - in;
		/* Extract RR records */
		for (i = 0; i < ntohs (header->ancount); i ++) {
			elt = malloc (sizeof (struct rdns_reply_entry));
			t = rdns_parse_rr (resolver, in, elt, &pos, rep, &r);
			if (t == -1) {
				free (elt);
				rdns_debug ("incomplete reply");
				break;
			}
			else if (t == 1) {
				DL_APPEND (rep->entries, elt);
				if (elt->type == type) {
					found = true;
				}
			}
			else {
				rdns_debug ("no matching reply for %s",
						req->requested_names[0].name);
				free (elt);
			}
		}
	}
	
	if (!found && type != RDNS_REQUEST_ANY) {
		/* We have not found the requested RR type */
		rep->code = RDNS_RC_NOREC;
	}

	*_rep = rep;
	return true;
}

static void
rdns_request_unschedule (struct rdns_request *req)
{
	req->async->del_timer (req->async->data,
			req->async_event);
	/* Remove from id hashes */
	HASH_DEL (req->io->requests, req);
}

void
rdns_process_read (int fd, void *arg)
{
	struct rdns_io_channel *ioc = arg;
	struct rdns_resolver *resolver;
	struct rdns_request *req = NULL;
	ssize_t r;
	struct rdns_reply *rep;
	uint8_t in[UDP_PACKET_SIZE];

	resolver = ioc->resolver;
	
	/* First read packet from socket */
	if (resolver->curve_plugin == NULL) {
		r = read (fd, in, sizeof (in));
		if (r > (int)(sizeof (struct dns_header) + sizeof (struct dns_query))) {
			req = rdns_find_dns_request (in, ioc);
		}
	}
	else {
		r = resolver->curve_plugin->cb.curve_plugin.recv_cb (ioc, in,
				sizeof (in), resolver->curve_plugin->data, &req);
		if (req == NULL &&
				r > (int)(sizeof (struct dns_header) + sizeof (struct dns_query))) {
			req = rdns_find_dns_request (in, ioc);
		}
	}

	if (req != NULL) {
		if (rdns_parse_reply (in, r, req, &rep)) {
			UPSTREAM_OK (req->io->srv);
			req->state = RDNS_REQUEST_REPLIED;
			rdns_request_unschedule (req);
			req->func (rep, req->arg);
			REF_RELEASE (req);
		}
	}
	else {
		/* Still want to increase uses */
		ioc->uses ++;
	}
}

void
rdns_process_timer (void *arg)
{
	struct rdns_request *req = (struct rdns_request *)arg;
	struct rdns_reply *rep;
	int r;
	bool renew = false;
	struct rdns_resolver *resolver;
	struct rdns_server *serv = NULL;

	req->retransmits --;
	resolver = req->resolver;

	if (req->retransmits == 0) {
		UPSTREAM_FAIL (req->io->srv, time (NULL));
		rep = rdns_make_reply (req, RDNS_RC_TIMEOUT);
		req->state = RDNS_REQUEST_REPLIED;
		rdns_request_unschedule (req);
		req->func (rep, req->arg);
		REF_RELEASE (req);

		return;
	}

	if (!req->io->active) {
		/* Do not reschedule IO requests on inactive sockets */
		rdns_debug ("reschedule request with id: %d", (int)req->id);
		rdns_request_unschedule (req);
		REF_RELEASE (req->io);

		UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);

		if (serv == NULL) {
			rdns_warn ("cannot find suitable server for request");
			rep = rdns_make_reply (req, RDNS_RC_SERVFAIL);
			req->state = RDNS_REQUEST_REPLIED;
			req->func (rep, req->arg);
			REF_RELEASE (req);
		}

		/* Select random IO channel */
		req->io = serv->io_channels[ottery_rand_uint32 () % serv->io_cnt];
		req->io->uses ++;
		REF_RETAIN (req->io);
		renew = true;
	}

	r = rdns_send_request (req, req->io->sock, renew);
	if (r == 0) {
		/* Retransmit one more time */
		req->async->del_timer (req->async->data,
					req->async_event);
		req->async_event = req->async->add_write (req->async->data,
				req->io->sock, req);
		req->state = RDNS_REQUEST_REGISTERED;
	}
	else if (r == -1) {
		UPSTREAM_FAIL (req->io->srv, time (NULL));
		rep = rdns_make_reply (req, RDNS_RC_NETERR);
		req->state = RDNS_REQUEST_REPLIED;
		rdns_request_unschedule (req);
		req->func (rep, req->arg);
		REF_RELEASE (req);
	}
	else {
		req->async->repeat_timer (req->async->data, req->async_event);
	}
}

static void
rdns_process_periodic (void *arg)
{
	struct rdns_resolver *resolver = (struct rdns_resolver*)arg;

	UPSTREAM_RESCAN (resolver->servers, time (NULL));
}

static void
rdns_process_ioc_refresh (void *arg)
{
	struct rdns_resolver *resolver = (struct rdns_resolver*)arg;
	struct rdns_server *serv;
	struct rdns_io_channel *ioc, *nioc;
	unsigned int i;

	if (resolver->max_ioc_uses > 0) {
		UPSTREAM_FOREACH (resolver->servers, serv) {
			for (i = 0; i < serv->io_cnt; i ++) {
				ioc = serv->io_channels[i];
				if (ioc->uses > resolver->max_ioc_uses) {
					/* Schedule IOC removing */
					nioc = calloc (1, sizeof (struct rdns_io_channel));
					if (nioc == NULL) {
						rdns_err ("calloc fails to allocate rdns_io_channel");
						continue;
					}
					nioc->sock = rdns_make_client_socket (serv->name, serv->port,
							SOCK_DGRAM);
					if (nioc->sock == -1) {
						rdns_err ("cannot open socket to %s: %s", serv->name,
								strerror (errno));
						free (nioc);
						continue;
					}
					nioc->srv = serv;
					nioc->active = true;
					nioc->resolver = resolver;
					nioc->async_io = resolver->async->add_read (resolver->async->data,
							nioc->sock, nioc);
					REF_INIT_RETAIN (nioc, rdns_ioc_free);
					serv->io_channels[i] = nioc;
					rdns_debug ("scheduled io channel for server %s to be refreshed after "
							"%lu usages", serv->name, (unsigned long)ioc->uses);
					ioc->active = false;
					REF_RELEASE (ioc);
				}
			}
		}
	}
}

void
rdns_process_retransmit (int fd, void *arg)
{
	struct rdns_request *req = (struct rdns_request *)arg;
	struct rdns_resolver *resolver;
	struct rdns_reply *rep;
	int r;

	resolver = req->resolver;

	resolver->async->del_write (resolver->async->data,
			req->async_event);

	r = rdns_send_request (req, fd, false);

	if (r == 0) {
		/* Retransmit one more time */
		req->async_event = req->async->add_write (req->async->data,
						fd, req);
		req->state = RDNS_REQUEST_REGISTERED;
	}
	else if (r == -1) {
		UPSTREAM_FAIL (req->io->srv, time (NULL));
		rep = rdns_make_reply (req, RDNS_RC_NETERR);
		req->state = RDNS_REQUEST_REPLIED;
		req->func (rep, req->arg);
		REF_RELEASE (req);
	}
	else {
		req->async_event = req->async->add_timer (req->async->data,
			req->timeout, req);
		req->state = RDNS_REQUEST_SENT;
	}
}

struct rdns_request*
rdns_make_request_full (
		struct rdns_resolver *resolver,
		dns_callback_type cb,
		void *cbdata,
		double timeout,
		unsigned int repeats,
		unsigned int queries,
		...
		)
{
	va_list args;
	struct rdns_request *req;
	struct rdns_server *serv;
	int r, type;
	unsigned int i, tlen = 0, clen = 0, cur;
	size_t olen;
	const char *cur_name, *last_name = NULL;
	struct rdns_compression_entry *comp = NULL;

	if (!resolver->initialized) {
		return NULL;
	}

	req = malloc (sizeof (struct rdns_request));
	if (req == NULL) {
		return NULL;
	}

	req->resolver = resolver;
	req->func = cb;
	req->arg = cbdata;
	req->reply = NULL;
	req->qcount = queries;
	req->io = NULL;
	req->state = RDNS_REQUEST_NEW;
	req->packet = NULL;
	req->requested_names = calloc (queries, sizeof (struct rdns_request_name));
	if (req->requested_names == NULL) {
		free (req);
		return NULL;
	}

	req->type = 0;
#ifdef TWEETNACL
	req->curve_plugin_data = NULL;
#endif
	REF_INIT_RETAIN (req, rdns_request_free);
	
	/* Calculate packet's total length based on records count */
	va_start (args, queries);
	for (i = 0; i < queries * 2; i += 2) {
		cur = i / 2;
		cur_name = va_arg (args, const char *);
		if (cur_name != NULL) {
			last_name = cur_name;
			clen = strlen (cur_name);
			if (clen == 0) {
				rdns_info ("got empty name to resolve");
				rdns_request_free (req);
				return NULL;
			}
			tlen += clen;
		}
		else if (last_name == NULL) {
			rdns_info ("got NULL as the first name to resolve");
			rdns_request_free (req);
			return NULL;
		}

		if (!rdns_format_dns_name (resolver, last_name, clen,
				&req->requested_names[cur].name, &olen)) {
			rdns_request_free (req);
			return NULL;
		}

		type = va_arg (args, int);
		req->requested_names[cur].type = type;
		req->requested_names[cur].len = olen;
	}
	va_end (args);

	rdns_allocate_packet (req, tlen);
	rdns_make_dns_header (req, queries);

	for (i = 0; i < queries; i ++) {
		cur_name = req->requested_names[i].name;
		clen = req->requested_names[i].len;
		type = req->requested_names[i].type;
		if (queries > 1) {
			if (!rdns_add_rr (req, cur_name, clen, type, &comp)) {
				REF_RELEASE (req);
				rnds_compression_free (comp);
				return NULL;
			}
		}
		else {
			if (!rdns_add_rr (req, cur_name, clen, type, NULL)) {
				REF_RELEASE (req);
				rnds_compression_free (comp);
				return NULL;
			}
		}
	}

	rnds_compression_free (comp);

	/* Add EDNS RR */
	rdns_add_edns0 (req);

	req->retransmits = repeats;
	req->timeout = timeout;
	req->state = RDNS_REQUEST_NEW;
	req->async = resolver->async;

	UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);

	if (serv == NULL) {
		rdns_warn ("cannot find suitable server for request");
		REF_RELEASE (req);
		return NULL;
	}
	
	/* Select random IO channel */
	req->io = serv->io_channels[ottery_rand_uint32 () % serv->io_cnt];
	req->io->uses ++;
	
	/* Now send request to server */
	r = rdns_send_request (req, req->io->sock, true);

	if (r == -1) {
		REF_RELEASE (req);
		return NULL;
	}

	REF_RETAIN (req->io);
	REF_RETAIN (req->resolver);

	return req;
}

bool
rdns_resolver_init (struct rdns_resolver *resolver)
{
	unsigned int i;
	struct rdns_server *serv;
	struct rdns_io_channel *ioc;

	if (!resolver->async_binded) {
		return false;
	}
	
	if (resolver->servers == NULL) {
		return false;
	}

	/* Now init io channels to all servers */
	UPSTREAM_FOREACH (resolver->servers, serv) {
		serv->io_channels = calloc (serv->io_cnt, sizeof (struct rdns_io_channel *));
		for (i = 0; i < serv->io_cnt; i ++) {
			ioc = calloc (1, sizeof (struct rdns_io_channel));
			if (ioc == NULL) {
				rdns_err ("cannot allocate memory for the resolver");
				return false;
			}
			ioc->sock = rdns_make_client_socket (serv->name, serv->port, SOCK_DGRAM);
			ioc->active = true;
			if (ioc->sock == -1) {
				rdns_err ("cannot open socket to %s:%d %s", serv->name, serv->port, strerror (errno));
				free (ioc);
				return false;
			}
			else {
				ioc->srv = serv;
				ioc->resolver = resolver;
				ioc->async_io = resolver->async->add_read (resolver->async->data,
						ioc->sock, ioc);
				REF_INIT_RETAIN (ioc, rdns_ioc_free);
				serv->io_channels[i] = ioc;
			}
		}
	}

	if (resolver->async->add_periodic) {
		resolver->periodic = resolver->async->add_periodic (resolver->async->data,
				UPSTREAM_REVIVE_TIME, rdns_process_periodic, resolver);
	}

	resolver->initialized = true;

	return true;
}

void
rdns_resolver_register_plugin (struct rdns_resolver *resolver,
		struct rdns_plugin *plugin)
{
	if (resolver != NULL && plugin != NULL) {
		/* XXX: support only network plugin now, and only a single one */
		if (plugin->type == RDNS_PLUGIN_CURVE) {
			resolver->curve_plugin = plugin;
		}
	}
}

bool
rdns_resolver_add_server (struct rdns_resolver *resolver,
		const char *name, unsigned int port,
		int priority, unsigned int io_cnt)
{
	struct rdns_server *serv;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;

	if (inet_pton (AF_INET, name, &addr) == 0 &&
		inet_pton (AF_INET6, name, &addr) == 0) {
		/* Invalid IP */
		return false;
	}

	if (io_cnt == 0) {
		return false;
	}
	if (port == 0 || port > UINT16_MAX) {
		return false;
	}

	serv = calloc (1, sizeof (struct rdns_server));
	if (serv == NULL) {
		return false;
	}
	serv->name = strdup (name);
	if (serv->name == NULL) {
		free (serv);
		return false;
	}

	serv->io_cnt = io_cnt;
	serv->port = port;

	UPSTREAM_ADD (resolver->servers, serv, priority);

	return true;
}

void
rdns_resolver_set_logger (struct rdns_resolver *resolver,
		rdns_log_function logger, void *log_data)
{
	resolver->logger = logger;
	resolver->log_data = log_data;
}

void
rdns_resolver_set_log_level (struct rdns_resolver *resolver,
		enum rdns_log_level level)
{
	resolver->log_level = level;
}


void
rdns_resolver_set_max_io_uses (struct rdns_resolver *resolver,
		uint64_t max_ioc_uses, double check_time)
{
	if (resolver->refresh_ioc_periodic != NULL) {
		resolver->async->del_periodic (resolver->async->data,
				resolver->refresh_ioc_periodic);
		resolver->refresh_ioc_periodic = NULL;
	}

	resolver->max_ioc_uses = max_ioc_uses;
	if (check_time > 0.0 && resolver->async->add_periodic) {
		resolver->refresh_ioc_periodic =
				resolver->async->add_periodic (resolver->async->data,
				check_time, rdns_process_ioc_refresh, resolver);
	}
}

static void
rdns_resolver_free (struct rdns_resolver *resolver)
{
	struct rdns_server *serv, *stmp;
	struct rdns_io_channel *ioc;
	unsigned int i;

	if (resolver->initialized) {
		if (resolver->periodic != NULL) {
			resolver->async->del_periodic (resolver->async->data, resolver->periodic);
		}
		if (resolver->refresh_ioc_periodic != NULL) {
			resolver->async->del_periodic (resolver->async->data,
					resolver->refresh_ioc_periodic);
		}
		if (resolver->curve_plugin != NULL && resolver->curve_plugin->dtor != NULL) {
			resolver->curve_plugin->dtor (resolver, resolver->curve_plugin->data);
		}
		/* Stop IO watch on all IO channels */
		UPSTREAM_FOREACH_SAFE (resolver->servers, serv, stmp) {
			for (i = 0; i < serv->io_cnt; i ++) {
				ioc = serv->io_channels[i];
				REF_RELEASE (ioc);
			}
			serv->io_cnt = 0;
			UPSTREAM_DEL (resolver->servers, serv);
			free (serv->io_channels);
			free (serv->name);
			free (serv);
		}
	}
	free (resolver->async);
	free (resolver);
}


struct rdns_resolver *
rdns_resolver_new (void)
{
	struct rdns_resolver     *new;

	new = calloc (1, sizeof (struct rdns_resolver));

	REF_INIT_RETAIN (new, rdns_resolver_free);

	new->logger = rdns_logger_internal;
	new->log_data = new;

	return new;
}

void
rdns_resolver_async_bind (struct rdns_resolver *resolver,
		struct rdns_async_context *ctx)
{
	if (resolver != NULL && ctx != NULL) {
		resolver->async = ctx;
		resolver->async_binded = true;
	}
}
