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

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#endif
