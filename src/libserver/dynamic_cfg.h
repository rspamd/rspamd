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
#ifndef DYNAMIC_CFG_H_
#define DYNAMIC_CFG_H_

#include "config.h"
#include "cfg_file.h"


#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Init dynamic configuration using map logic and specific configuration
 * @param cfg config file
 */
void init_dynamic_config (struct rspamd_config *cfg);

/**
 * Dump dynamic configuration to the disk
 * @param cfg
 * @return
 */
gboolean dump_dynamic_config (struct rspamd_config *cfg);

/**
 * Add symbol for specified metric
 * @param cfg config file object
 * @param metric metric's name
 * @param symbol symbol's name
 * @param value value of symbol
 * @return
 */
gboolean add_dynamic_symbol (struct rspamd_config *cfg,
							 const gchar *metric,
							 const gchar *symbol,
							 gdouble value);

gboolean remove_dynamic_symbol (struct rspamd_config *cfg,
								const gchar *metric,
								const gchar *symbol);

/**
 * Add action for specified metric
 * @param cfg config file object
 * @param metric metric's name
 * @param action action's name
 * @param value value of symbol
 * @return
 */
gboolean add_dynamic_action (struct rspamd_config *cfg,
							 const gchar *metric,
							 guint action,
							 gdouble value);

/**
 * Removes dynamic action
 */
gboolean remove_dynamic_action (struct rspamd_config *cfg,
								const gchar *metric,
								guint action);

#ifdef  __cplusplus
}
#endif

#endif /* DYNAMIC_CFG_H_ */
