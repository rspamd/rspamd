/*-
 * Copyright 2018 Vsevolod Stakhov
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

#ifndef RSPAMD_MAP_HELPERS_H
#define RSPAMD_MAP_HELPERS_H

#include "config.h"
#include "map.h"

/**
 * @file map_helpers.h
 *
 * Defines helper structures to deal with different map types
 */

/**
 * Common structures, abstract for simplicity
 */
struct rspamd_radix_map_helper;
struct rspamd_hash_map_helper;
struct rspamd_regexp_map_helper;

typedef void (*insert_func) (gpointer st, gconstpointer key,
		gconstpointer value);

/**
 * Radix list is a list like ip/mask
 */
gchar * rspamd_radix_read (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
void rspamd_radix_fin (struct map_cb_data *data);

/**
 * Host list is an ordinal list of hosts or domains
 */
gchar * rspamd_hosts_read (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
void rspamd_hosts_fin (struct map_cb_data *data);

/**
 * Kv list is an ordinal list of keys and values separated by whitespace
 */
gchar * rspamd_kv_list_read (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
void rspamd_kv_list_fin (struct map_cb_data *data);

/**
 * Regexp list is a list of regular expressions
 */

gchar * rspamd_regexp_list_read_single (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
gchar * rspamd_regexp_list_read_multiple (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
gchar * rspamd_glob_list_read_single (
		gchar *chunk,
		gint len,
		struct map_cb_data *data,
		gboolean final);
void rspamd_regexp_list_fin (struct map_cb_data *data);

/**
 * FSM for lists parsing (support comments, blank lines and partial replies)
 */
gchar *
rspamd_parse_kv_list (
		gchar * chunk,
		gint len,
		struct map_cb_data *data,
		insert_func func,
		const gchar *default_value,
		gboolean final);

/**
 * Find a single (any) matching regexp for the specified text or NULL if
 * no matches found
 * @param map
 * @param in
 * @param len
 * @return
 */
gpointer rspamd_match_regexp_map_single (struct rspamd_regexp_map *map,
		const gchar *in, gsize len);

/**
 * Find a multiple (all) matching regexp for the specified text or NULL if
 * no matches found. Returns GPtrArray that *must* be freed by a caller if not NULL
 * @param map
 * @param in
 * @param len
 * @return
 */
gpointer rspamd_match_regexp_map_all (struct rspamd_regexp_map *map,
		const gchar *in, gsize len);

#endif
