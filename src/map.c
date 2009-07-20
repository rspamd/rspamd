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
 * Implementation of map files handling
 */
#include "config.h"
#include "map.h"
#include "main.h"
#include "util.h"
#include "mem_pool.h"

static memory_pool_t *map_pool = NULL;

static GList *maps = NULL;
static char *hash_fill = "1";

/* Value in seconds after whitch we would try to do stat on list file */
#define MON_TIMEOUT 10

static void
read_map_file (struct rspamd_map *map, struct file_map_data *data)
{
	struct map_cb_data cbdata;
	char buf[BUFSIZ];
	ssize_t r;
	int fd;
	
	if (map->read_callback == NULL || map->fin_callback == NULL) {
		msg_err ("read_map_file: bad callback for reading map file");
		return;
	}

	if ((fd = open (data->filename, O_RDONLY)) == -1) {
		msg_warn ("read_map_file: cannot open file '%s': %s", data->filename, strerror (errno));
		return;
	}

	cbdata.state = 0;
	cbdata.prev_data = *map->user_data;
	cbdata.cur_data = NULL;

	while ((r = read (fd, buf, sizeof (buf) - 1)) > 0) {
		buf[r ++] = '\0';
		map->read_callback (map->pool, buf, r, &cbdata);
	}
		
	close (fd);

	map->fin_callback (map->pool, &cbdata);
	*map->user_data = cbdata.cur_data;
}

gboolean 
add_map (const char *map_line, map_cb_t read_callback, map_fin_cb_t fin_callback, void **user_data)
{
	struct rspamd_map *new_map;
	enum fetch_proto proto;
	const char *def, *p;
	struct file_map_data *fdata;
	struct http_map_data *hdata;
	char portbuf[6];
	int i, s, fd;
	struct hostent *hent;

	/* First of all detect protocol line */
	if (strncmp (map_line, "http://", sizeof ("http://") - 1) == 0) {
		proto = PROTO_HTTP;
		def = map_line + sizeof ("http://") - 1;
	}
	else if (strncmp (map_line, "file://", sizeof ("file://") - 1) == 0) {
		proto = PROTO_FILE;
		def = map_line + sizeof ("file://") - 1;
	}
	else {
		msg_err ("add_map: invalid map fetching protocol: %s", map_line);
		return FALSE;
	}
	/* Constant pool */
	if (map_pool == NULL) {
		map_pool = memory_pool_new (memory_pool_get_size ());
	}
	new_map = memory_pool_alloc (map_pool, sizeof (struct rspamd_map));
	new_map->read_callback = read_callback;
	new_map->fin_callback = fin_callback;
	new_map->user_data = user_data;
	new_map->protocol = proto;
	
	/* Now check for each proto separately */
	if (proto == PROTO_FILE) {
		if ((fd = open (def, O_RDONLY)) == -1) {
			msg_warn ("add_map: cannot open file '%s': %s", def, strerror (errno));
			return FALSE;
		}
		fdata = memory_pool_alloc (map_pool, sizeof (struct file_map_data));
		fdata->filename = memory_pool_strdup (map_pool, def);
		fstat (fd, &fdata->st);
		new_map->map_data = fdata;
	}
	else if (proto == PROTO_HTTP) {
		hdata = memory_pool_alloc (map_pool, sizeof (struct http_map_data));
		/* Try to search port */
		if ((p = strchr (def, ':')) != NULL) {
			i = 0;
			while (g_ascii_isdigit (*p) && i < sizeof (portbuf) - 1) {
				portbuf[i ++] = *p ++;
			}
			if (*p != '/') {
				msg_info ("add_map: bad http map definition: %s", def);
				return FALSE;
			}
			portbuf[i] = '\0';
			hdata->port = atoi (portbuf);
		}
		else {
			/* Default http port */
			hdata->port = 80;
			/* Now separate host from path */
			if ((p = strchr (def, '/')) == NULL) {
				msg_info ("add_map: bad http map definition: %s", def);
				return FALSE;
			}
		}
		hdata->host = memory_pool_alloc (map_pool, p - def + 1);
		g_strlcpy (hdata->host, def, p - def + 1);
		hdata->path = memory_pool_strdup (map_pool, p);
		/* Now try to resolve */
		if (!inet_aton (hdata->host, &hdata->addr)) {
			/* Resolve using dns */
			hent = gethostbyname (hdata->host);
			if (hent == NULL) {
				msg_info ("add_map: cannot resolve: %s", hdata->host);
				return FALSE;
			}
			else {
				memcpy (&hdata->addr, hent->h_addr, sizeof(struct in_addr));
			}
		}
		/* Now try to connect */
		if ((s = make_tcp_socket (&hdata->addr, hdata->port, FALSE)) == -1) {
			msg_info ("add_map: cannot connect to http server %s: %d, %s", hdata->host, errno, strerror (errno));
			return FALSE;
		}
		close (s);
		new_map->map_data = hdata;
	}
	/* Temp pool */
	new_map->pool = memory_pool_new (memory_pool_get_size ());

	maps = g_list_prepend (maps, new_map);

	return TRUE;
}

typedef void (*insert_func)(gpointer st, gconstpointer key, gpointer value);

static gboolean
abstract_parse_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data, insert_func func)
{
	u_char *s, *p, *str;

	p = chunk;

	str = g_malloc (len + 1);
	s = str;

	while (*p) {
		switch (data->state) {
			/* READ_SYMBOL */
			case 0:
				if (*p == '#') {
					if (s != str) {
						*s = '\0';
						s = memory_pool_strdup (pool, str);
						func (data->cur_data, s, hash_fill);
						s = str;
					}
					data->state = 1;
				}
				else if (*p == '\r' || *p == '\n') {
					if (s != str) {
						*s = '\0';
						s = memory_pool_strdup (pool, str);
						func (data->cur_data, s, hash_fill);
						s = str;
					}
					while (*p == '\r' || *p == '\n') {
						p ++;
					}
				}
				else if (g_ascii_isspace (*p)) {
					p ++;
				}
				else {
					*s = *p;
					s ++;
					p ++;
				}
				break;
			/* SKIP_COMMENT */
			case 1:
				if (*p == '\r' || *p == '\n') {
					while (*p == '\r' || *p == '\n') {
						p ++;
					}
					s = str;
					data->state = 0;
				}
				else {
					p ++;
				}
				break;
		}
	}

	g_free (str);

	return TRUE;
}

static void
radix_tree_insert_helper (gpointer st, gconstpointer key, gpointer value)
{
	radix_tree_t *tree = st;

	uint32_t mask = 0xFFFFFFFF;
	uint32_t ip;
	char *token, *ipnet;
	struct in_addr ina;
	int k;
	
	k = strlen ((char *)key) + 1;
	ipnet = alloca (k);
	g_strlcpy (ipnet, key, k);
	token = strsep (&ipnet, "/");

	if (ipnet != NULL) {
		k = atoi (ipnet);
		if (k > 32 || k < 0) {
			msg_warn ("radix_tree_insert_helper: invalid netmask value: %d", k);
			k = 32;
		}
		k = 32 - k;
		mask = mask << k;
	}

	if (inet_aton (token, &ina) == 0) {
		msg_err ("radix_tree_insert_helper: invalid ip address: %s", token);
		return;
	}

	ip = ntohl ((uint32_t)ina.s_addr);
	k = radix32tree_insert (tree, ip, mask, 1);
	if (k == -1) {
		msg_warn ("radix_tree_insert_helper: cannot insert ip to tree: %s, mask %X", inet_ntoa (ina), mask);
	}
	else if (k == 1) {
		msg_warn ("add_ip_radix: ip %s, mask %X, value already exists", inet_ntoa (ina), mask);
	}
}

void
read_host_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data)
{	
	if (data->cur_data == NULL) {
		data->cur_data = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	}
	(void)abstract_parse_list (pool, chunk, len, data, (insert_func)g_hash_table_insert);
}

void 
fin_host_list (memory_pool_t *pool, struct map_cb_data *data)
{
	if (data->prev_data) {
		g_hash_table_destroy (data->prev_data);
	}
}

void
read_radix_list (memory_pool_t *pool, u_char *chunk, size_t len, struct map_cb_data *data)
{
	if (data->cur_data == NULL) {
		data->cur_data = radix_tree_create ();
	}
	(void)abstract_parse_list (pool, chunk, len, data, (insert_func)radix_tree_insert_helper);
}

void 
fin_radix_list (memory_pool_t *pool, struct map_cb_data *data)
{
	if (data->prev_data) {
		radix_tree_free (data->prev_data);
	}
}

static void
file_callback (int fd, short what, void *ud)
{
	struct rspamd_map *map = ud;
	struct file_map_data *data = map->map_data;
	struct stat st;

	/* Plan event again with jitter */
	evtimer_del (&map->ev);
	map->tv.tv_sec = MON_TIMEOUT + MON_TIMEOUT * g_random_double ();
	map->tv.tv_usec = 0;
	evtimer_add (&map->ev, &map->tv);

	if (stat (data->filename, &st) != -1 && st.st_mtime > data->st.st_mtime) {
		memcpy (&data->st, &st, sizeof (struct stat));
	}
	else {
		return;
	}
	
	msg_info ("rereading map file %s", data->filename);
	read_map_file (map, data);
}

/* Start watching event for all maps */
void 
start_map_watch (void)
{
	GList *cur = maps;
	struct rspamd_map *map;
	
	/* First of all do synced read of data */
	while (cur) {
		map = cur->data;
		if (map->protocol == PROTO_FILE) {
			evtimer_set (&map->ev, file_callback, map);
			/* Read initial data */
			read_map_file (map, map->map_data);
			/* Plan event with jitter */
			map->tv.tv_sec = MON_TIMEOUT + MON_TIMEOUT * g_random_double ();
			map->tv.tv_usec = 0;
			evtimer_add (&map->ev, &map->tv);
		}
		else {
			/* XXX */
		}
		cur = g_list_next (cur);
	}
}
