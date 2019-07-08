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
#ifndef PRINTF_H_
#define PRINTF_H_

#include "config.h"
#include "fstring.h"

#ifdef  __cplusplus
extern "C" {
#endif
/*
 * supported formats:
 *	%[0][width][x][X]O		    off_t
 *	%[0][width]T			    time_t
 *	%[0][width][u][x|X|h|H]z	    ssize_t/size_t
 *	%[0][width][u][x|X|h|H]d	    gint/guint
 *	%[0][width][u][x|X|h|H]l	    long
 *	%[0][width][u][x|X|h|H]D	    gint32/guint32
 *	%[0][width][u][x|X|h|H]L	    gint64/guint64
 *	%[0][width][.width]f	    double
 *	%[0][width][.width]F	    long double
 *	%[0][width][.width]g	    double
 *	%[0][width][.width]G	    long double
 *	%P						    pid_t
 *	%r				            rlim_t
 *	%p						    void *
 *	%V						    rspamd_fstring_t *
 *	%T						    rspamd_ftok_t
 *	%v                          GString *
 *	%s						    null-terminated string
 *	%xs                         hex encoded string
 *	%bs                         base32 encoded string
 *	%Bs							base64 encoded string
 *	%*s					        length and string
 *	%Z						    '\0'
 *	%N						    '\n'
 *	%c						    gchar
 *	%t						    time_t
 *	%e                          GError *
 *	%%						    %
 *
 */

/**
 * Callback used for common printf operations
 * @param buf buffer to append
 * @param buflen length of the buffer
 * @param ud opaque pointer
 * @return number of characters written
 */
typedef glong (*rspamd_printf_append_func) (const gchar *buf, glong buflen,
											gpointer ud);

glong rspamd_fprintf (FILE *f, const gchar *fmt, ...);

glong rspamd_printf (const gchar *fmt, ...);

glong rspamd_log_fprintf (FILE *f, const gchar *fmt, ...);

glong rspamd_snprintf (gchar *buf, glong max, const gchar *fmt, ...);

gchar *rspamd_vsnprintf (gchar *buf, glong max, const gchar *fmt,
						 va_list args);

glong rspamd_printf_gstring (GString *s, const gchar *fmt, ...);

glong rspamd_vprintf_gstring (GString *s, const gchar *fmt, va_list args);

glong rspamd_printf_fstring (rspamd_fstring_t **s, const gchar *fmt, ...);

glong rspamd_vprintf_fstring (rspamd_fstring_t **s, const gchar *fmt, va_list args);

glong rspamd_vprintf_common (rspamd_printf_append_func func,
							 gpointer apd,
							 const gchar *fmt,
							 va_list args);

#ifdef  __cplusplus
}
#endif

#endif /* PRINTF_H_ */
