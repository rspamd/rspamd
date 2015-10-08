/*
 * Copyright (c) 2015, Vsevolod Stakhov
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
#ifndef RSPAMD_UNIX_STD_H_H
#define RSPAMD_UNIX_STD_H_H

#include "config.h"

/*
 * Default unix system includes
 */

/* sys/file.h */
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

/* sys/uio.h */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

/* sys/mman */
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif


/* timedb */
#ifdef HAVE_SYS_TIMEB_H
#include <sys/timeb.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* sysexits */
#ifdef HAVE_SYSEXITS_H
#include <sysexits.h>
#endif

/* strings */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

/* fcntl */
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif


#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <signal.h>

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#endif
