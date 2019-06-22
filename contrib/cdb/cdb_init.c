/* $Id: cdb_init.c,v 1.12 2008-11-06 18:07:04 mjt Exp $
 * cdb_init, cdb_free and cdb_read routines
 *
 * This file is a part of tinycdb package by Michael Tokarev, mjt@corpit.ru.
 * Public domain.
 */

#include "cdb.h"

unsigned
cdb_hash(const void *buf, unsigned len)
{
	register const unsigned char *p = (const unsigned char *) buf;
	register const unsigned char *end = p + len;
	register unsigned hash = 5381; /* start value */
	while (p < end)
		hash = (hash + (hash << 5)) ^ *p++;
	return hash;
}

int
cdb_init(struct cdb *cdbp, int fd)
{
	struct stat st;
	unsigned char *mem;
	unsigned fsize, dend;
#ifdef _WIN32
	HANDLE hFile, hMapping;
#endif

	/* get file size */
	if (fstat (fd, &st) < 0)
		return -1;
	/* trivial sanity check: at least toc should be here */
	if (st.st_size < 2048)
		return errno = EPROTO, -1;
	fsize = (unsigned) (st.st_size & 0xffffffffu);
	/* memory-map file */
#ifdef _WIN32
	hFile = (HANDLE) _get_osfhandle(fd);
	if (hFile == (HANDLE) -1)
	return -1;
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!hMapping)
	return -1;
	mem = (unsigned char *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hMapping);
	if (!mem)
	return -1;
#else
	mem = (unsigned char*) mmap (NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		return -1;
#endif /* _WIN32 */

	cdbp->cdb_fd = fd;
	cdbp->cdb_fsize = fsize;
	cdbp->cdb_mem = mem;
	cdbp->mtime = st.st_mtime;

	cdbp->cdb_vpos = cdbp->cdb_vlen = 0;
	cdbp->cdb_kpos = cdbp->cdb_klen = 0;
	dend = cdb_unpack (mem);
	if (dend < 2048)
		dend = 2048;
	else if (dend >= fsize)
		dend = fsize;
	cdbp->cdb_dend = dend;

	return 0;
}

void
cdb_free(struct cdb *cdbp)
{
	if (cdbp->cdb_mem) {
#ifdef _WIN32
		UnmapViewOfFile((void*) cdbp->cdb_mem);
#else
		munmap ((void*) cdbp->cdb_mem, cdbp->cdb_fsize);
#endif /* _WIN32 */
		cdbp->cdb_mem = NULL;
	}
	cdbp->cdb_fsize = 0;

	if (cdbp->loop) {
		ev_stat_stop (cdbp->loop, &cdbp->stat_ev);
	}
}

const void *
cdb_get(const struct cdb *cdbp, unsigned len, unsigned pos)
{
	if (pos > cdbp->cdb_fsize || cdbp->cdb_fsize - pos < len) {
		errno = EPROTO;
		return NULL;
	}
	return cdbp->cdb_mem + pos;
}

int
cdb_read(const struct cdb *cdbp, void *buf, unsigned len, unsigned pos)
{
	const void *data = cdb_get (cdbp, len, pos);
	if (!data)
		return -1;
	memcpy (buf, data, len);
	return 0;
}

static void
cdb_timer_callback (EV_P_ ev_stat *w, int revents)
{
	struct cdb *cdbp = w->data;
	gint nfd;

	/* Check cdb file for modifications */
	if ((nfd = open (cdbp->filename, O_RDONLY)) != -1) {
		if (cdbp->cdb_mem) {
#ifdef _WIN32
			UnmapViewOfFile((void*) cdbp->cdb_mem);
#else
			munmap ((void*) cdbp->cdb_mem, cdbp->cdb_fsize);
#endif /* _WIN32 */
			cdbp->cdb_mem = NULL;
		}
		(void)close (cdbp->cdb_fd);
		cdbp->cdb_fsize = 0;
		(void)cdb_init (cdbp, nfd);
	}
}

void
cdb_add_timer (struct cdb *cdbp, EV_P_ ev_tstamp seconds)
{
	cdbp->loop = loop;
	ev_stat_init (&cdbp->stat_ev, cdb_timer_callback, cdbp->filename, seconds);
	cdbp->stat_ev.data = cdbp;
	ev_stat_start (EV_A_ &cdbp->stat_ev);
}
