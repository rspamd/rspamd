/* Copyright (c) 2010, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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


#ifndef PRINTF_H_
#define PRINTF_H_

#include "config.h"

/*
 * supported formats:
 *	%[0][width][x][X]O		    off_t
 *	%[0][width]T			    time_t
 *	%[0][width][u][x|X]z	    ssize_t/size_t
 *	%[0][width][u][x|X]d	    gint/guint
 *	%[0][width][u][x|X]l	    long
 *	%[0][width][u][x|X]D	    gint32/guint32
 *	%[0][width][u][x|X]L	    gint64/guint64
 *	%[0][width][.width]f	    double
 *	%[0][width][.width]F	    long double
 *	%[0][width][.width]g	    double
 *	%[0][width][.width]G	    long double
 *	%P						    pid_t
 *	%r				            rlim_t
 *	%p						    void *
 *	%V						    f_str_t *
 *	%s						    null-terminated string
 *	%S						    ascii null-terminated string
 *	%*s					        length and string
 *	%Z						    '\0'
 *	%N						    '\n'
 *	%c						    gchar
 *	%%						    %
 *
 */
gint rspamd_sprintf (gchar *buf, const gchar *fmt, ...);
gint rspamd_fprintf (FILE *f, const gchar *fmt, ...);
gint rspamd_snprintf (gchar *buf, size_t max, const gchar *fmt, ...);
gchar *rspamd_vsnprintf (gchar *buf, size_t max, const gchar *fmt, va_list args);

#endif /* PRINTF_H_ */
