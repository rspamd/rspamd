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
#include "rspamadm.h"
#include "libutil/util.h"

extern struct rspamadm_command pw_command;
extern struct rspamadm_command keypair_command;
extern struct rspamadm_command configtest_command;
extern struct rspamadm_command fuzzy_merge_command;
extern struct rspamadm_command configdump_command;
extern struct rspamadm_command control_command;
extern struct rspamadm_command confighelp_command;
extern struct rspamadm_command statconvert_command;
extern struct rspamadm_command fuzzyconvert_command;
extern struct rspamadm_command grep_command;
extern struct rspamadm_command signtool_command;
extern struct rspamadm_command lua_command;
extern struct rspamadm_command dkim_keygen_command;
extern struct rspamadm_command configwizard_command;
extern struct rspamadm_command corpus_test_command;
extern struct rspamadm_command rescore_command;

const struct rspamadm_command *commands[] = {
	&help_command,
	&pw_command,
	&keypair_command,
	&configtest_command,
	&fuzzy_merge_command,
	&configdump_command,
	&control_command,
	&confighelp_command,
	&statconvert_command,
	&fuzzyconvert_command,
	&grep_command,
	&signtool_command,
	&lua_command,
	&dkim_keygen_command,
	&configwizard_command,
	&corpus_test_command,
	&rescore_command,
	NULL
};


const struct rspamadm_command *
rspamadm_search_command (const gchar *name, GPtrArray *all_commands)
{
	const struct rspamadm_command *ret = NULL, *cmd;
	guint i;

	if (name == NULL) {
		name = "help";
	}

	PTR_ARRAY_FOREACH (all_commands, i, cmd) {
			if (strcmp (name, cmd->name) == 0) {
				ret = cmd;
				break;
			}
	}

	return ret;
}

void
rspamadm_fill_internal_commands (GPtrArray *dest)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (commands); i ++) {
		if (commands[i]) {
			g_ptr_array_add (dest, (gpointer)commands[i]);
		}
	}
}
