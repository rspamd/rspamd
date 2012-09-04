/*
 * Copyright (c) 2012, Vsevolod Stakhov
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

/*
 * Ipmark is custom plugin for marking ip with some weight, it understand several commands:
 * - add <ip[/mask]> value
 * - delete <ip[/mask]>
 * - check <ip>
 * 
 * This plugin is a sample of custom filters system in rspamd
 */

#include "config.h"
#include "cfg_file.h"
#include "radix.h"

#define ADD_COMMAND "add"
#define DELETE_COMMAND "delete"
#define CHECK_COMMAND "check"


enum ipmark_command {
	COMMAND_ADD,
	COMMAND_DELETE,
	COMMAND_CHECK
};

/* Exported functions */
void module_init (struct config_file *cfg);
void* before_connect (void);
gboolean parse_line (const char *line, size_t len, char **output, void *user_data);
void after_connect (char **output, char **log_line, void *user_data);
void module_fin (void);	

/* Internal variables */
static char *filename = NULL;
static radix_tree_t *radix = NULL;

/* Implementation */

char                           *
get_module_opt (struct config_file *cfg, char *module_name, char *opt_name)
{
	GList                          *cur_opt;
	struct module_opt              *cur;

	cur_opt = g_hash_table_lookup (cfg->modules_opts, module_name);
	if (cur_opt == NULL) {
		return NULL;
	}

	while (cur_opt) {
		cur = cur_opt->data;
		if (strcmp (cur->param, opt_name) == 0) {
			return cur->value;
		}
		cur_opt = g_list_next (cur_opt);
	}

	return NULL;
}

static gboolean
parse_ipmask (const char *begin, struct in_addr *ina, int *mask, int *value)
{
	const char *pos;
	char ip_buf[sizeof ("255.255.255.255")], mask_buf[3] = { '\0', '\0', '\0' }, *p;
	int state = 1, dots = 0;
	
	bzero (ip_buf, sizeof (ip_buf));
	bzero (mask_buf, sizeof (mask_buf));
	pos = begin;

	while (*pos && state < 5) {
		switch (state) {
			case 1:
				/* Begin parse ip */
				if (g_ascii_isspace (*p)) {
					state = 3;
				}
				else if (p - ip_buf >= sizeof (ip_buf) || dots > 3) {
					return FALSE;
				}
				if (g_ascii_isdigit (*pos)) {
					*p ++ = *pos ++;
				}
				else if (*pos == '.') {
					*p ++ = *pos ++;
					dots ++;
				}
				else if (*pos == '/') {
					pos ++;
					p = mask_buf;
					state = 2;
				}
				else {
					/* Invalid character */
					return FALSE;
				}
				break;
			case 2:
				/* Parse mask */
				if (g_ascii_isspace (*p)) {
					state = 3;
				}
				else if (p - mask_buf > 2) {
					return FALSE;
				}
				if (g_ascii_isdigit (*pos)) {
					*p ++ = *pos ++;
				}
				else {
					return FALSE;
				}
				break;
			case 3:
				if (!g_ascii_isspace (*p)) {
					state = 4;
				}
				else {
					p ++;
				}
				break;
			case 4:
				*value = strtol (p, NULL, 10);
				state = 99;
				break;
		}
	}

	if (!inet_aton (ip_buf, ina)) {
		return FALSE;
	}

	if (mask_buf[0] != '\0') {
		/* Also parse mask */
		*mask = (mask_buf[0] - '0') * 10 + mask_buf[1] - '0';
		if (*mask > 32) {
			return FALSE;
		}
	}
	else {
		*mask = 32;
	}

	*mask = 0xFFFFFFFF << (32 - *mask); 
	
	return TRUE;
}

static void
read_radix_file (void)
{
	FILE *f;
	char buf[BUFSIZ];
	struct in_addr ina;
	int mask = 0, value = 0;

	f = fopen (filename, "r");
	if (f != NULL) {
		while (fgets (buf, sizeof (buf), f)) {
			if (parse_ipmask (buf, &ina, &mask, &value)) {
				(void)radix32tree_add (radix, ntohl (ina.s_addr), mask, (uintptr_t)value);
			}
		}

		fclose (f);
	}
}

static gboolean
write_cb_func (uint32_t key, uint32_t level, uintptr_t value, void *user_data)
{
	FILE *f = user_data;
	struct in_addr ina;

	ina.s_addr = htonl (value);

	fprintf (f, "%s/%d %d\n", inet_ntoa (ina), level, (int)value);

	return FALSE;
}

static void
write_radix_file (void)
{
	FILE *f;

	/* Traverse throught radix tree */
	f = fopen (filename, "w");
	if (f != NULL) {
		radix32tree_traverse (radix, write_cb_func, f);
		fclose (f);
	}
}

void 
module_init (struct config_file *cfg)
{
	char *value;

	if (cfg && (value = get_module_opt (cfg, "ipmark", "file")) != NULL) {
		filename = g_strdup (value);
	}
	
	radix = radix_tree_create ();
	if (filename) {
		read_radix_file ();
	}
}

void *
before_connect (void)
{
	/* In fact we do not need any session data, so just return NULL */
	return NULL;
}

void
module_fin (void)
{
	if (filename) {
		write_radix_file ();
		g_free (filename);
		filename = NULL;
	}
	if (radix) {
		radix_tree_free (radix);
		radix = NULL;
	}
	
}

gboolean 
parse_line (const char *line, size_t len, char **output, void *user_data)
{
	char ip_buf[sizeof ("255.255.255.255")], mask_buf[3] = {'\0', '\0', '\0'};
	const char *p;
	char *c = ip_buf, *err_str;
	struct in_addr ina;
	int state = 0, next_state = 0, dots = 0;
	int16_t value = 0;
	uint32_t mask;
	enum ipmark_command cmd = COMMAND_ADD;

	/* Parse input line */
	p = line;
	while (p - line < len && state < 100) {
		switch (state) {
			case 0:
				/* Expect command */
				if (g_ascii_strncasecmp (line, ADD_COMMAND, sizeof (ADD_COMMAND) - 1) == 0) {
					state = 99;
					next_state = 1;
					cmd = COMMAND_ADD;
					p += sizeof (ADD_COMMAND);
				}
				else if (g_ascii_strncasecmp (line, DELETE_COMMAND, sizeof (DELETE_COMMAND) - 1) == 0) {
					state = 99;
					next_state = 1;
					cmd = COMMAND_DELETE;
					p += sizeof (DELETE_COMMAND);
				}
				else if (g_ascii_strncasecmp (line, CHECK_COMMAND, sizeof (CHECK_COMMAND) - 1) == 0) {
					state = 99;
					next_state = 1;
					cmd = COMMAND_CHECK;
					p += sizeof (CHECK_COMMAND);
				}
				else {
					state = 100;
				}
				break;
			case 1:
				/* Expect ip or ipmask */
				if (c - ip_buf >= sizeof (ip_buf) || dots > 3) {
					state = 100;
				}
				if (g_ascii_isdigit (*p)) {
					*c ++ = *p ++;
				}
				else if (*p == '.') {
					*c ++ = *p ++;
					dots ++;
				}
				else if (*p == '/') {
					p ++;
					c = mask_buf;
					state = 2;
				}
				else if (g_ascii_isspace (*p)) {
					if (cmd == COMMAND_ADD) {
						next_state = 3;
					}
					else {
						next_state = 100;
					}
					state = 99;
				}
				else {
					/* Invalid character */
					state = 100;
				}
				break;
			case 2:
				/* Parse mask */
				if (c - mask_buf > 2) {
					state = 100;
				}
				if (g_ascii_isdigit (*p)) {
					*c ++ = *p ++;
				}
				else if (g_ascii_isspace (*p)) {
					if (cmd == COMMAND_ADD) {
						next_state = 3;
					}
					else {
						next_state = 100;
					}
					state = 99;
				}
				else {
					state = 100;
				}
				break;
			case 3:
				errno = 0;
				value = strtol (p, &err_str, 10);
				if (errno != 0) {
					state = 100;
				}
				else {
					state = 101;
				}
				break;
			case 99:
				/* Skip spaces */
				if (g_ascii_isspace (*p)) {
					p ++;
				}
				else {
					state = next_state;
				}
				break;
		}
	}

	if (state == 100 || !inet_aton (ip_buf, &ina)) {
		/* Error occured */
		*output = g_strdup ("ERR: invalid command");
		return FALSE;
	}
	
	/* Process mask */
	if (mask_buf[0] == '\0') {
		/* Assume /32 mask */
		mask = 0xFFFFFFFF;
	}
	else {
		mask = (mask_buf[0] - '0') * 10 + mask_buf[1] - '0';
		if (mask > 32) {
			mask = 32;
		}

		mask = 0xFFFFFFFF << (32 - mask);  
	}

	/* Process command */
	switch (cmd) {
		case COMMAND_ADD:
			state = radix32tree_add (radix, ntohl (ina.s_addr), mask, (uintptr_t)value);
			if (state == 0) {
				*output = g_strdup_printf ("OK: new value %d", (int)value);
			}
			else if (state == -1) {
				*output = g_strdup ("ERR: cannot insert value");
			}
			else {
				*output = g_strdup_printf ("OK: new value %d", state);
			}
			break;
		case COMMAND_DELETE:
			if (radix32tree_delete (radix, ntohl (ina.s_addr), mask) == 0) {
				*output = g_strdup ("OK: address deleted");
			}
			else {
				*output = g_strdup ("ERR: address not found");
			}
			break;
		case COMMAND_CHECK:
			if ((value = radix32tree_find (radix, ntohl (ina.s_addr))) != RADIX_NO_VALUE) {
				*output = g_strdup_printf ("OK: %d", (int)value);
			}
			else {
				*output = g_strdup ("ERR: address not found");
			}
			break;
	}

	return TRUE;
}

void after_connect (char **output, char **log_line, void *user_data)
{
	/* Placeholder */
	return;
}

