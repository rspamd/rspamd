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
#ifndef SRC_LIBMIME_SMTP_PARSERS_H_
#define SRC_LIBMIME_SMTP_PARSERS_H_

#include "config.h"
#include "email_addr.h"
#include "content_type.h"
#include "task.h"
#include "message.h"


#ifdef  __cplusplus
extern "C" {
#endif

int rspamd_smtp_addr_parse (const char *data, size_t len,
							struct rspamd_email_address *addr);

gboolean rspamd_content_disposition_parser (const char *data, size_t len,
											struct rspamd_content_disposition *cd,
											rspamd_mempool_t *pool);

gboolean
rspamd_rfc2047_parser (const gchar *in, gsize len, gint *pencoding,
					   const gchar **charset, gsize *charset_len,
					   const gchar **encoded, gsize *encoded_len);

rspamd_inet_addr_t *rspamd_parse_smtp_ip (const char *data, size_t len,
										  rspamd_mempool_t *pool);

guint64 rspamd_parse_smtp_date (const unsigned char *data, size_t len, GError **err);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBMIME_SMTP_PARSERS_H_ */
