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
		if (!req->io->connected) {
			r = sendto (fd, req->packet, req->pos, 0,
					req->io->saddr,
					req->io->slen);
		}
		else {
			r = send (fd, req->packet, req->pos, 0);
		}
	}
	else {
		if (!req->io->connected) {
			r = resolver->curve_plugin->cb.curve_plugin.send_cb (req,
					resolver->curve_plugin->data,
					req->io->saddr,
					req->io->slen);
		}
		else {
			r = resolver->curve_plugin->cb.curve_plugin.send_cb (req,
					resolver->curve_plugin->data,
					NULL,
					0);
		}
	}
	if (r == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			if (new_req) {
				/* Write when socket is ready */
				HASH_ADD_INT (req->io->requests, id, req);
				req->async_event = resolver->async->add_write (resolver->async->data,
					fd, req);
				req->state = RDNS_REQUEST_WAIT_SEND;
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
	else if (!req->io->connected) {
		/* Connect socket */
		r = connect (fd, req->io->saddr, req->io->slen);

		if (r == -1) {
			rdns_err ("cannot connect after sending request: %s for server %s",
					strerror (errno), serv->name);
		}
		else {
			req->io->connected = true;
		}
	}

	if (new_req) {
		/* Add request to hash table */
		HASH_ADD_INT (req->io->requests, id, req);
		/* Fill timeout */
		req->async_event = resolver->async->add_timer (resolver->async->data,
				req->timeout, req);
		req->state = RDNS_REQUEST_WAIT_REPLY;
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
		rep->authenticated = false;
		rep->requested_name = req->requested_names[0].name;
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

	if (header->ad) {
		rep->authenticated = true;
	}

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
		if (rep->code == RDNS_RC_NOERROR) {
			rep->code = RDNS_RC_NOREC;
		}
	}

	*_rep = rep;
	return true;
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
		r = recv (fd, in, sizeof (in), 0);
		if (r > (int)(sizeof (struct dns_header) + sizeof (struct dns_query))) {
			req = rdns_find_dns_request (in, ioc);
		}
	}
	else {
		r = resolver->curve_plugin->cb.curve_plugin.recv_cb (ioc, in,
				sizeof (in), resolver->curve_plugin->data, &req,
				ioc->saddr, ioc->slen);
		if (req == NULL &&
				r > (int)(sizeof (struct dns_header) + sizeof (struct dns_query))) {
			req = rdns_find_dns_request (in, ioc);
		}
	}

	if (req != NULL) {
		if (rdns_parse_reply (in, r, req, &rep)) {
			UPSTREAM_OK (req->io->srv);

			if (req->resolver->ups && req->io->srv->ups_elt) {
				req->resolver->ups->ok (req->io->srv->ups_elt,
						req->resolver->ups->data);
			}

			rdns_request_unschedule (req);
			req->state = RDNS_REQUEST_REPLIED;
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
	unsigned cnt;

	req->retransmits --;
	resolver = req->resolver;

	if (req->resolver->ups && req->io->srv->ups_elt) {
		req->resolver->ups->fail (req->io->srv->ups_elt,
				req->resolver->ups->data, "timeout waiting reply");
	}
	else {
		UPSTREAM_FAIL (req->io->srv, time (NULL));
	}

	if (req->retransmits == 0) {

		rep = rdns_make_reply (req, RDNS_RC_TIMEOUT);
		rdns_request_unschedule (req);
		req->state = RDNS_REQUEST_REPLIED;
		req->func (rep, req->arg);
		REF_RELEASE (req);

		return;
	}

	if (!req->io->active || req->retransmits == 1) {

		if (resolver->ups) {
			cnt = resolver->ups->count (resolver->ups->data);
		}
		else {
			cnt = 0;
			UPSTREAM_FOREACH (resolver->servers, serv) {
				cnt ++;
			}
		}

		if (!req->io->active || cnt > 1) {
			/* Do not reschedule IO requests on inactive sockets */
			rdns_debug ("reschedule request with id: %d", (int)req->id);
			rdns_request_unschedule (req);
			REF_RELEASE (req->io);

			if (resolver->ups) {
				struct rdns_upstream_elt *elt;

				elt = resolver->ups->select_retransmit (
						req->requested_names[0].name,
						req->requested_names[0].len,
						req->io->srv->ups_elt,
						resolver->ups->data);

				if (elt) {
					serv = elt->server;
					serv->ups_elt = elt;
				}
				else {
					UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);
				}
			}
			else {
				UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);
			}

			if (serv == NULL) {
				rdns_warn ("cannot find suitable server for request");
				rep = rdns_make_reply (req, RDNS_RC_SERVFAIL);
				req->state = RDNS_REQUEST_REPLIED;
				req->func (rep, req->arg);
				REF_RELEASE (req);

				return;
			}

			/* Select random IO channel */
			req->io = serv->io_channels[ottery_rand_uint32 () % serv->io_cnt];
			req->io->uses ++;
			REF_RETAIN (req->io);
			renew = true;
		}
	}

	/*
	 * Note: when `renew` is true, then send_request deals with the
	 * timers and events itself
	 */
	r = rdns_send_request (req, req->io->sock, renew);
	if (r == 0) {
		/* Retransmit one more time */
		if (!renew) {
			req->async->del_timer (req->async->data,
					req->async_event);
			req->async_event = req->async->add_write (req->async->data,
					req->io->sock, req);
		}

		req->state = RDNS_REQUEST_WAIT_SEND;
	}
	else if (r == -1) {
		if (req->resolver->ups && req->io->srv->ups_elt) {
			req->resolver->ups->fail (req->io->srv->ups_elt,
					req->resolver->ups->data, "cannot send retransmit after timeout");
		}
		else {
			UPSTREAM_FAIL (req->io->srv, time (NULL));
		}

		if (!renew) {
			req->async->del_timer (req->async->data,
					req->async_event);
			req->async_event = NULL;
			HASH_DEL (req->io->requests, req);
		}

		/* We have not scheduled timeout actually due to send error */
		rep = rdns_make_reply (req, RDNS_RC_NETERR);
		req->state = RDNS_REQUEST_REPLIED;
		req->func (rep, req->arg);
		REF_RELEASE (req);
	}
	else {
		req->async->repeat_timer (req->async->data, req->async_event);
		req->state = RDNS_REQUEST_WAIT_REPLY;
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
							SOCK_DGRAM, &nioc->saddr, &nioc->slen);
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
	req->async_event = NULL;

	if (req->state == RDNS_REQUEST_FAKE) {
		/* Reply is ready */
		req->func (req->reply, req->arg);
		REF_RELEASE (req);

		return;
	}

	r = rdns_send_request (req, fd, false);

	if (r == 0) {
		/* Retransmit one more time */
		req->async_event = req->async->add_write (req->async->data,
						fd, req);
		req->state = RDNS_REQUEST_WAIT_SEND;
	}
	else if (r == -1) {
		if (req->resolver->ups && req->io->srv->ups_elt) {
			req->resolver->ups->fail (req->io->srv->ups_elt,
					req->resolver->ups->data, "retransmit send failed");
		}
		else {
			UPSTREAM_FAIL (req->io->srv, time (NULL));
		}

		rep = rdns_make_reply (req, RDNS_RC_NETERR);
		req->state = RDNS_REQUEST_REPLIED;
		req->func (rep, req->arg);
		REF_RELEASE (req);
	}
	else {
		req->async_event = req->async->add_timer (req->async->data,
			req->timeout, req);
		req->state = RDNS_REQUEST_WAIT_REPLY;
	}
}

struct rdns_server *
rdns_select_request_upstream (struct rdns_resolver *resolver,
							  struct rdns_request *req,
							  bool is_retransmit,
							  struct rdns_server *prev_serv)
{
	struct rdns_server *serv = NULL;

	if (resolver->ups) {
		struct rdns_upstream_elt *elt;

		if (is_retransmit && prev_serv) {
			elt = resolver->ups->select_retransmit (req->requested_names[0].name,
					req->requested_names[0].len,
					prev_serv->ups_elt,
					resolver->ups->data);
		}
		else {
			elt = resolver->ups->select (req->requested_names[0].name,
					req->requested_names[0].len, resolver->ups->data);
		}

		if (elt) {
			serv = elt->server;
			serv->ups_elt = elt;
		}
		else {
			UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);
		}
	}
	else {
		UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);
	}

	return serv;
}

#define align_ptr(p, a)                                                   \
    (guint8 *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

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
	struct rdns_fake_reply *fake_rep = NULL;
	char fake_buf[MAX_FAKE_NAME + sizeof (struct rdns_fake_reply_idx) + 16];
	struct rdns_fake_reply_idx *idx;

	if (resolver == NULL || !resolver->initialized) {
		if (resolver == NULL) {
			return NULL;
		}

		rdns_err ("resolver is uninitialized");

		return NULL;
	}

	req = malloc (sizeof (struct rdns_request));
	if (req == NULL) {
		rdns_err ("failed to allocate memory for request: %s",
				strerror (errno));
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
	req->async_event = NULL;

	if (req->requested_names == NULL) {
		free (req);
		rdns_err ("failed to allocate memory for request data: %s",
				strerror (errno));

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
		type = va_arg (args, int);

		if (cur_name != NULL) {
			clen = strlen (cur_name);

			if (clen == 0) {
				rdns_warn ("got empty name to resolve");
				rdns_request_free (req);
				return NULL;
			}

			if (cur_name[0] == '.') {
				/* Skip dots at the begin */
				unsigned int ndots = strspn (cur_name, ".");

				cur_name += ndots;
				clen -= ndots;

				if (clen == 0) {
					rdns_warn ("got empty name to resolve");
					rdns_request_free (req);
					return NULL;
				}
			}

			if (cur_name[clen - 1] == '.') {
				/* Skip trailing dots */
				while (clen >= 1 && cur_name[clen - 1] == '.') {
					clen --;
				}

				if (clen == 0) {
					rdns_warn ("got empty name to resolve");
					rdns_request_free (req);
					return NULL;
				}
			}

			if (last_name == NULL && queries == 1 && clen < MAX_FAKE_NAME) {
				/* We allocate structure in the static space */
				idx = (struct rdns_fake_reply_idx *)align_ptr (fake_buf, 16);
				idx->type = type;
				idx->len = clen;
				memcpy (idx->request, cur_name, clen);
				HASH_FIND (hh, resolver->fake_elts, idx, sizeof (*idx) + clen,
						fake_rep);

				if (fake_rep) {
					/* We actually treat it as a short-circuit */
					req->reply = rdns_make_reply (req, fake_rep->rcode);
					req->reply->entries = fake_rep->result;
					req->state = RDNS_REQUEST_FAKE;
				}
			}

			last_name = cur_name;
			tlen += clen;
		}
		else if (last_name == NULL) {
			rdns_err ("got NULL as the first name to resolve");
			rdns_request_free (req);
			return NULL;
		}

		if (req->state != RDNS_REQUEST_FAKE) {
			if (!rdns_format_dns_name (resolver, last_name, clen,
					&req->requested_names[cur].name, &olen)) {
				rdns_err ("cannot format %s", last_name);
				rdns_request_free (req);
				return NULL;
			}

			req->requested_names[cur].len = olen;
		}
		else {
			req->requested_names[cur].len = clen;
		}

		req->requested_names[cur].type = type;
	}

	va_end (args);

	if (req->state != RDNS_REQUEST_FAKE) {
		rdns_allocate_packet (req, tlen);
		rdns_make_dns_header (req, queries);

		for (i = 0; i < queries; i++) {
			cur_name = req->requested_names[i].name;
			clen = req->requested_names[i].len;
			type = req->requested_names[i].type;
			if (queries > 1) {
				if (!rdns_add_rr (req, cur_name, clen, type, &comp)) {
					rdns_err ("cannot add rr");
					REF_RELEASE (req);
					rnds_compression_free (comp);
					return NULL;
				}
			} else {
				if (!rdns_add_rr (req, cur_name, clen, type, NULL)) {
					rdns_err ("cannot add rr");
					REF_RELEASE (req);
					rnds_compression_free (comp);
					return NULL;
				}
			}
		}

		rnds_compression_free (comp);

		/* Add EDNS RR */
		rdns_add_edns0 (req);

		req->retransmits = repeats ? repeats : 1;
		req->timeout = timeout;
		req->state = RDNS_REQUEST_NEW;
	}

	req->async = resolver->async;

	serv = rdns_select_request_upstream (resolver, req, false, NULL);

	if (serv == NULL) {
		rdns_warn ("cannot find suitable server for request");
		REF_RELEASE (req);
		return NULL;
	}

	/* Select random IO channel */
	req->io = serv->io_channels[ottery_rand_uint32 () % serv->io_cnt];

	if (req->state == RDNS_REQUEST_FAKE) {
		req->async_event = resolver->async->add_write (resolver->async->data,
				req->io->sock, req);
	}
	else {
		/* Now send request to server */
		do {
			r = rdns_send_request (req, req->io->sock, true);

			if (r == -1) {
				req->retransmits --; /* It must be > 0 */

				if (req->retransmits > 0) {
					if (resolver->ups && serv->ups_elt) {
						resolver->ups->fail (serv->ups_elt, resolver->ups->data,
								"send IO error");
					}
					else {
						UPSTREAM_FAIL (serv, time (NULL));
					}

					serv = rdns_select_request_upstream (resolver, req,
							true, serv);

					if (serv == NULL) {
						rdns_warn ("cannot find suitable server for request");
						REF_RELEASE (req);
						return NULL;
					}

					req->io = serv->io_channels[ottery_rand_uint32 () % serv->io_cnt];
				}
				else {
					rdns_info ("cannot send DNS request: %s", strerror (errno));
					REF_RELEASE (req);

					if (resolver->ups && serv->ups_elt) {
						resolver->ups->fail (serv->ups_elt, resolver->ups->data,
								"send IO error");
					}
					else {
						UPSTREAM_FAIL (serv, time (NULL));
					}

					return NULL;
				}
			}
			else {
				/* All good */
				req->io->uses++;
				break;
			}
		} while (req->retransmits > 0);
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
		rdns_err ("no async backend specified");
		return false;
	}

	if (resolver->servers == NULL) {
		rdns_err ("no DNS servers defined");
		return false;
	}

	/* Now init io channels to all servers */
	UPSTREAM_FOREACH (resolver->servers, serv) {
		serv->io_channels = calloc (serv->io_cnt, sizeof (struct rdns_io_channel *));
		for (i = 0; i < serv->io_cnt; i ++) {
			ioc = calloc (1, sizeof (struct rdns_io_channel));
			if (ioc == NULL) {
				rdns_err ("cannot allocate memory for the resolver IO channels");
				return false;
			}

			ioc->sock = rdns_make_client_socket (serv->name, serv->port, SOCK_DGRAM,
					&ioc->saddr, &ioc->slen);

			if (ioc->sock == -1) {
				ioc->active = false;
				rdns_err ("cannot open socket to %s:%d %s",
						serv->name, serv->port, strerror (errno));
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

void *
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
		return NULL;
	}

	if (io_cnt == 0) {
		return NULL;
	}
	if (port == 0 || port > UINT16_MAX) {
		return NULL;
	}

	serv = calloc (1, sizeof (struct rdns_server));
	if (serv == NULL) {
		return NULL;
	}
	serv->name = strdup (name);
	if (serv->name == NULL) {
		free (serv);
		return NULL;
	}

	serv->io_cnt = io_cnt;
	serv->port = port;

	UPSTREAM_ADD (resolver->servers, serv, priority);

	return serv;
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
rdns_resolver_set_upstream_lib (struct rdns_resolver *resolver,
		struct rdns_upstream_context *ups_ctx,
		void *ups_data)
{
	resolver->ups = ups_ctx;
	resolver->ups->data = ups_data;
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
rdns_resolver_new (int flags)
{
	struct rdns_resolver     *new_resolver;

	new_resolver = calloc (1, sizeof (struct rdns_resolver));

	REF_INIT_RETAIN (new_resolver, rdns_resolver_free);

	new_resolver->logger = rdns_logger_internal;
	new_resolver->log_data = new_resolver;
	new_resolver->flags = flags;

	return new_resolver;
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

void
rdns_resolver_set_dnssec (struct rdns_resolver *resolver, bool enabled)
{
	if (resolver) {
		resolver->enable_dnssec = enabled;
	}
}


void rdns_resolver_set_fake_reply (struct rdns_resolver *resolver,
								   const char *name,
								   enum rdns_request_type type,
								   enum dns_rcode rcode,
								   struct rdns_reply_entry *reply)
{
	struct rdns_fake_reply *fake_rep;
	struct rdns_fake_reply_idx *srch;
	unsigned len = strlen (name);

	assert (len < MAX_FAKE_NAME);
	srch = malloc (sizeof (*srch) + len);
	srch->len = len;
	srch->type = type;
	memcpy (srch->request, name, len);

	HASH_FIND (hh, resolver->fake_elts, srch, len + sizeof (*srch), fake_rep);

	if (fake_rep) {
		/* Append reply to the existing list */
		fake_rep->rcode = rcode;

		if (reply) {
			DL_CONCAT (fake_rep->result, reply);
		}
	}
	else {
		fake_rep = calloc (1, sizeof (*fake_rep) + len);

		if (fake_rep == NULL) {
			abort ();
		}

		fake_rep->rcode = rcode;

		memcpy (&fake_rep->key, srch, sizeof (*srch) + len);

		if (reply) {
			DL_CONCAT (fake_rep->result, reply);
		}

		HASH_ADD (hh, resolver->fake_elts, key, sizeof (*srch) + len, fake_rep);
	}

	free (srch);
}
