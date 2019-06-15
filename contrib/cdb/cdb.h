/* $Id: cdb.h,v 1.10 2009-01-31 17:12:22 mjt Exp $
 * public cdb include file
 *
 * This file is a part of tinycdb package by Michael Tokarev, mjt@corpit.ru.
 * Public domain.
 */

#ifndef TINYCDB_VERSION
#define TINYCDB_VERSION 0.77

#include "config.h"
#include "unix-std.h"
#include "contrib/libev/ev.h"

/*
 * OpenBSD fix
 */
#ifndef EPROTO
#define EPROTO EPROTONOSUPPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int cdbi_t; /* compatibility */

/* common routines */
unsigned cdb_hash(const void *buf, unsigned len);
unsigned cdb_unpack(const unsigned char buf[4]);
void cdb_pack(unsigned num, unsigned char buf[4]);

struct cdb
{
	int cdb_fd; /* file descriptor */
	char *filename; /* file name */
	time_t mtime; /* mtime of cdb file */
	struct ev_loop *loop;
	ev_stat stat_ev; /* event structure for checking cdb for modifications */
	ev_tstamp check_ts;
	/* private members */
	unsigned cdb_fsize; /* datafile size */
	unsigned cdb_dend; /* end of data ptr */
	const unsigned char *cdb_mem; /* mmap'ed file memory */
	unsigned cdb_vpos, cdb_vlen; /* found data */
	unsigned cdb_kpos, cdb_klen; /* found key */
};

#define CDB_STATIC_INIT {0,0,0,0,0,0,0,0}

#define cdb_datapos(c) ((c)->cdb_vpos)
#define cdb_datalen(c) ((c)->cdb_vlen)
#define cdb_keypos(c) ((c)->cdb_kpos)
#define cdb_keylen(c) ((c)->cdb_klen)
#define cdb_fileno(c) ((c)->cdb_fd)

int cdb_init(struct cdb *cdbp, int fd);
void cdb_add_timer(struct cdb *cdbp, EV_P_ ev_tstamp seconds);
void cdb_free(struct cdb *cdbp);

int cdb_read(const struct cdb *cdbp, void *buf, unsigned len, unsigned pos);
#define cdb_readdata(cdbp, buf) \
        cdb_read((cdbp), (buf), cdb_datalen(cdbp), cdb_datapos(cdbp))
#define cdb_readkey(cdbp, buf) \
        cdb_read((cdbp), (buf), cdb_keylen(cdbp), cdb_keypos(cdbp))

const void *cdb_get(const struct cdb *cdbp, unsigned len, unsigned pos);
#define cdb_getdata(cdbp) \
        cdb_get((cdbp), cdb_datalen(cdbp), cdb_datapos(cdbp))
#define cdb_getkey(cdbp) \
        cdb_get((cdbp), cdb_keylen(cdbp), cdb_keypos(cdbp))

int cdb_find(struct cdb *cdbp, const void *key, unsigned klen);

struct cdb_find
{
	struct cdb *cdb_cdbp;
	unsigned cdb_hval;
	const unsigned char *cdb_htp, *cdb_htab, *cdb_htend;
	unsigned cdb_httodo;
	const void *cdb_key;
	unsigned cdb_klen;
};

int cdb_findinit(struct cdb_find *cdbfp, struct cdb *cdbp, const void *key,
		unsigned klen);
int cdb_findnext(struct cdb_find *cdbfp);

#define cdb_seqinit(cptr, cdbp) ((*(cptr))=2048)
int cdb_seqnext(unsigned *cptr, struct cdb *cdbp);

/* old simple interface */
/* open file using standard routine, then: */
int cdb_seek(int fd, const void *key, unsigned klen, unsigned *dlenp);
int cdb_bread(int fd, void *buf, int len);

/* cdb_make */

struct cdb_make
{
	int cdb_fd; /* file descriptor */

	/* private */
	unsigned cdb_dpos; /* data position so far */
	unsigned cdb_rcnt; /* record count so far */
	unsigned char cdb_buf[4096]; /* write buffer */
	unsigned char *cdb_bpos; /* current buf position */
	struct cdb_rl *cdb_rec[256]; /* list of arrays of record infos */
};

enum cdb_put_mode
{
	CDB_PUT_ADD = 0, /* add unconditionnaly, like cdb_make_add() */
#define CDB_PUT_ADD	CDB_PUT_ADD
	CDB_FIND = CDB_PUT_ADD, CDB_PUT_REPLACE, /* replace: do not place to index OLD record */
#define CDB_PUT_REPLACE	CDB_PUT_REPLACE
	CDB_FIND_REMOVE = CDB_PUT_REPLACE, CDB_PUT_INSERT, /* add only if not already exists */
#define CDB_PUT_INSERT	CDB_PUT_INSERT
	CDB_PUT_WARN, /* add unconditionally but ret. 1 if exists */
#define CDB_PUT_WARN	CDB_PUT_WARN
	CDB_PUT_REPLACE0, /* if a record exists, fill old one with zeros */
#define CDB_PUT_REPLACE0 CDB_PUT_REPLACE0
	CDB_FIND_FILL0 = CDB_PUT_REPLACE0
};

int cdb_make_start(struct cdb_make *cdbmp, int fd);
int cdb_make_add(struct cdb_make *cdbmp, const void *key, unsigned klen,
		const void *val, unsigned vlen);
int cdb_make_exists(struct cdb_make *cdbmp, const void *key, unsigned klen);
int cdb_make_find(struct cdb_make *cdbmp, const void *key, unsigned klen,
		enum cdb_put_mode mode);
int cdb_make_put(struct cdb_make *cdbmp, const void *key, unsigned klen,
		const void *val, unsigned vlen, enum cdb_put_mode mode);
int cdb_make_finish(struct cdb_make *cdbmp);

/** Private API **/
struct cdb_rec
{
	unsigned hval;
	unsigned rpos;
};

struct cdb_rl
{
	struct cdb_rl *next;
	unsigned cnt;
	struct cdb_rec rec[254];
};

int _cdb_make_write(struct cdb_make *cdbmp, const unsigned char *ptr,
		unsigned len);
int _cdb_make_fullwrite(int fd, const unsigned char *buf, unsigned len);
int _cdb_make_flush(struct cdb_make *cdbmp);
int _cdb_make_add(struct cdb_make *cdbmp, unsigned hval, const void *key,
		unsigned klen, const void *val, unsigned vlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* include guard */
