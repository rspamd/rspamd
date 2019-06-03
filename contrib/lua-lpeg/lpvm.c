/*
** $Id: lpvm.c,v 1.6 2015/09/28 17:01:25 roberto Exp $
** Copyright 2007, Lua.org & PUC-Rio  (see 'lpeg.html' for license)
*/

#include "config.h"

#include <limits.h>
#include <string.h>


#include "lua.h"
#include "lauxlib.h"

#include "lpcap.h"
#include "lptypes.h"
#include "lpvm.h"
#include "lpprint.h"

#include <sys/mman.h>

#define MAX_PIECES (1u << 2u)

/* 64 bytes, 1 cache line */
struct poor_slab {
	struct slab_piece {
		unsigned char *ptr;
		uint32_t sz;
		uint32_t occupied;
	} pieces[MAX_PIECES];
};

/* Used to optimize pages allocation */
struct poor_slab slabs;

static uint64_t xorshifto_seed[2] = {0xdeadbabe, 0xdeadbeef};

static inline uint64_t
xoroshiro_rotl (const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

void *
lpeg_allocate_mem_low (size_t sz)
{
	unsigned char *cp;
	unsigned flags = MAP_PRIVATE | MAP_ANON;
	void *base_addr = NULL;

	/* Check slabs */
	for (unsigned i = 0; i < MAX_PIECES; i ++) {
		if (!slabs.pieces[i].occupied && slabs.pieces[i].sz == sz) {
			/* Reuse, short path */
			slabs.pieces[i].occupied = 1;
			return slabs.pieces[i].ptr + sizeof (size_t);
		}
	}

#ifdef MAP_32BIT
	flags |= MAP_32BIT;
#else
	const uint64_t s0 = xorshifto_seed[0];
	uint64_t s1 = xorshifto_seed[1];

	s1 ^= s0;
	xorshifto_seed[0] = xoroshiro_rotl(s0, 55) ^ s1 ^ (s1 << 14);
	xorshifto_seed[1] = xoroshiro_rotl (s1, 36);
	flags |= MAP_FIXED;
	/* Get 46 bits */
	base_addr = (void *)((xorshifto_seed[0] + xorshifto_seed[1]) & 0x7FFFFFFFF000ULL);
#endif

	cp = mmap (base_addr, sz + sizeof (sz), PROT_WRITE | PROT_READ,
			flags, -1, 0);
	assert (cp != NULL);
	memcpy (cp, &sz, sizeof (sz));

	for (unsigned i = 0; i < MAX_PIECES; i ++) {
		if (slabs.pieces[i].sz == 0) {
			/* Store piece */
			slabs.pieces[i].sz = sz;
			slabs.pieces[i].ptr = cp;
			slabs.pieces[i].occupied = 1;

			return cp + sizeof (sz);
		}
	}

	/* Not enough free pieces, pop some */
	unsigned sel = ((uintptr_t)cp) & ((MAX_PIECES * 2) - 1);
	/* Here we free memory in fact */
	munmap (slabs.pieces[sel].ptr, slabs.pieces[sel].sz);
	slabs.pieces[sel].sz = sz;
	slabs.pieces[sel].ptr = cp;
	slabs.pieces[sel].occupied = 1;

	return cp + sizeof (sz);
}

void
lpeg_free_mem_low(void *p)
{
	unsigned char *cp = (unsigned char *)p;
	size_t sz;

	/* Base address */
	cp -= sizeof (sz);
	memcpy (&sz, cp, sizeof (sz));

	for (unsigned i = 0; i < MAX_PIECES; i ++) {
		if (slabs.pieces[i].occupied && slabs.pieces[i].ptr == cp) {
			/* Return back */
			slabs.pieces[i].occupied = 0;

			return;
		}
	}

	/* No match, unmapped by allocation */
}

/* initial size for call/backtrack stack */
#if !defined(INITBACK)
#define INITBACK	MAXBACK
#endif


#define getoffset(p)	(((p) + 1)->offset)

static const Instruction giveup = {{IGiveup, 0, 0}};


/*
** {======================================================
** Virtual Machine
** =======================================================
*/


typedef struct Stack {
  const char *s;  /* saved position (or NULL for calls) */
  const Instruction *p;  /* next instruction */
  int caplevel;
} Stack;


#define getstackbase(L, ptop)	((Stack *)lua_touserdata(L, stackidx(ptop)))


/*
** Double the size of the array of captures
*/
static Capture *doublecap (lua_State *L, Capture *cap, int captop, int ptop) {
  Capture *newc;
  if (captop >= INT_MAX/((int)sizeof(Capture) * 2))
    luaL_error(L, "too many captures");
  newc = (Capture *)lua_newuserdata(L, captop * 2 * sizeof(Capture));
  memcpy(newc, cap, captop * sizeof(Capture));
  lua_replace(L, caplistidx(ptop));
  return newc;
}


/*
** Double the size of the stack
*/
static Stack *doublestack (lua_State *L, Stack **stacklimit, int ptop) {
  Stack *stack = getstackbase(L, ptop);
  Stack *newstack;
  int n = *stacklimit - stack;  /* current stack size */
  int max, newn;
  lua_getfield(L, LUA_REGISTRYINDEX, MAXSTACKIDX);
  max = lua_tointeger(L, -1);  /* maximum allowed size */
  lua_pop(L, 1);
  if (n >= max)  /* already at maximum size? */
    luaL_error(L, "backtrack stack overflow (current limit is %d)", max);
  newn = 2 * n;  /* new size */
  if (newn > max) newn = max;
  newstack = (Stack *)lua_newuserdata(L, newn * sizeof(Stack));
  memcpy(newstack, stack, n * sizeof(Stack));
  lua_replace(L, stackidx(ptop));
  *stacklimit = newstack + newn;
  return newstack + n;  /* return next position */
}


/*
** Interpret the result of a dynamic capture: false -> fail;
** true -> keep current position; number -> next position.
** Return new subject position. 'fr' is stack index where
** is the result; 'curr' is current subject position; 'limit'
** is subject's size.
*/
static int resdyncaptures (lua_State *L, int fr, int curr, int limit) {
  lua_Integer res;
  if (!lua_toboolean(L, fr)) {  /* false value? */
    lua_settop(L, fr - 1);  /* remove results */
    return -1;  /* and fail */
  }
  else if (lua_isboolean(L, fr))  /* true? */
    res = curr;  /* keep current position */
  else {
    res = lua_tointeger(L, fr) - 1;  /* new position */
    if (res < curr || res > limit)
      luaL_error(L, "invalid position returned by match-time capture");
  }
  lua_remove(L, fr);  /* remove first result (offset) */
  return res;
}


/*
** Add capture values returned by a dynamic capture to the capture list
** 'base', nested inside a group capture. 'fd' indexes the first capture
** value, 'n' is the number of values (at least 1).
*/
static void adddyncaptures (const char *s, Capture *base, int n, int fd) {
  int i;
  /* Cgroup capture is already there */
  assert(base[0].kind == Cgroup && base[0].siz == 0);
  base[0].idx = 0;  /* make it an anonymous group */
  for (i = 1; i <= n; i++) {  /* add runtime captures */
    base[i].kind = Cruntime;
    base[i].siz = 1;  /* mark it as closed */
    base[i].idx = fd + i - 1;  /* stack index of capture value */
    base[i].s = s;
  }
  base[i].kind = Cclose;  /* close group */
  base[i].siz = 1;
  base[i].s = s;
}


/*
** Remove dynamic captures from the Lua stack (called in case of failure)
*/
static int removedyncap (lua_State *L, Capture *capture,
                         int level, int last) {
  int id = finddyncap(capture + level, capture + last);  /* index of 1st cap. */
  int top = lua_gettop(L);
  if (id == 0) return 0;  /* no dynamic captures? */
  lua_settop(L, id - 1);  /* remove captures */
  return top - id + 1;  /* number of values removed */
}


/*
** Opcode interpreter
*/
const char *match (lua_State *L, const char *o, const char *s, const char *e,
                   Instruction *op, Capture *capture, int ptop) {
#ifdef LPEG_LUD_WORKAROUND
  Stack *stackbase = lpeg_allocate_mem_low(sizeof (Stack) * INITBACK);
#else
  Stack stackbase[INITBACK];
#endif
  Stack *stacklimit = stackbase + INITBACK;
  Stack *stack = stackbase;  /* point to first empty slot in stack */
  int capsize = INITCAPSIZE;
  int captop = 0;  /* point to first empty slot in captures */
  int ndyncap = 0;  /* number of dynamic captures (in Lua stack) */
  const Instruction *p = op;  /* current instruction */
  stack->p = &giveup; stack->s = s; stack->caplevel = 0; stack++;
  lua_pushlightuserdata(L, stackbase);
  for (;;) {
#if defined(DEBUG)
      printf("s: |%s| stck:%d, dyncaps:%d, caps:%d  ",
             s, stack - getstackbase(L, ptop), ndyncap, captop);
      printinst(op, p);
      printcaplist(capture, capture + captop);
#endif
    assert(stackidx(ptop) + ndyncap == lua_gettop(L) && ndyncap <= captop);
    switch ((Opcode)p->i.code) {
      case IEnd: {
        assert(stack == getstackbase(L, ptop) + 1);
        capture[captop].kind = Cclose;
        capture[captop].s = NULL;
#ifdef LPEG_LUD_WORKAROUND
        lpeg_free_mem_low(stackbase);
#endif
        return s;
      }
      case IGiveup: {
        assert(stack == getstackbase(L, ptop));
#ifdef LPEG_LUD_WORKAROUND
        lpeg_free_mem_low(stackbase);
#endif
        return NULL;
      }
      case IRet: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s == NULL);
        p = (--stack)->p;
        continue;
      }
      case IAny: {
        if (s < e) { p++; s++; }
        else goto fail;
        continue;
      }
      case ITestAny: {
        if (s < e) p += 2;
        else p += getoffset(p);
        continue;
      }
      case IChar: {
        if ((byte)*s == p->i.aux && s < e) { p++; s++; }
        else goto fail;
        continue;
      }
      case ITestChar: {
        if ((byte)*s == p->i.aux && s < e) p += 2;
        else p += getoffset(p);
        continue;
      }
      case ISet: {
        int c = (byte)*s;
        if (testchar((p+1)->buff, c) && s < e)
          { p += CHARSETINSTSIZE; s++; }
        else goto fail;
        continue;
      }
      case ITestSet: {
        int c = (byte)*s;
        if (testchar((p + 2)->buff, c) && s < e)
          p += 1 + CHARSETINSTSIZE;
        else p += getoffset(p);
        continue;
      }
      case IBehind: {
        int n = p->i.aux;
        if (n > s - o) goto fail;
        s -= n; p++;
        continue;
      }
      case ISpan: {
        for (; s < e; s++) {
          int c = (byte)*s;
          if (!testchar((p+1)->buff, c)) break;
        }
        p += CHARSETINSTSIZE;
        continue;
      }
      case IJmp: {
        p += getoffset(p);
        continue;
      }
      case IChoice: {
        if (stack == stacklimit)
          stack = doublestack(L, &stacklimit, ptop);
        stack->p = p + getoffset(p);
        stack->s = s;
        stack->caplevel = captop;
        stack++;
        p += 2;
        continue;
      }
      case ICall: {
        if (stack == stacklimit)
          stack = doublestack(L, &stacklimit, ptop);
        stack->s = NULL;
        stack->p = p + 2;  /* save return address */
        stack++;
        p += getoffset(p);
        continue;
      }
      case ICommit: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s != NULL);
        stack--;
        p += getoffset(p);
        continue;
      }
      case IPartialCommit: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s != NULL);
        (stack - 1)->s = s;
        (stack - 1)->caplevel = captop;
        p += getoffset(p);
        continue;
      }
      case IBackCommit: {
        assert(stack > getstackbase(L, ptop) && (stack - 1)->s != NULL);
        s = (--stack)->s;
        captop = stack->caplevel;
        p += getoffset(p);
        continue;
      }
      case IFailTwice:
        assert(stack > getstackbase(L, ptop));
        stack--;
        /* go through */
      case IFail:
      fail: { /* pattern failed: try to backtrack */
        do {  /* remove pending calls */
          assert(stack > getstackbase(L, ptop));
          s = (--stack)->s;
        } while (s == NULL);
        if (ndyncap > 0)  /* is there matchtime captures? */
          ndyncap -= removedyncap(L, capture, stack->caplevel, captop);
        captop = stack->caplevel;
        p = stack->p;
        continue;
      }
      case ICloseRunTime: {
        CapState cs;
        int rem, res, n;
        int fr = lua_gettop(L) + 1;  /* stack index of first result */
        cs.s = o; cs.L = L; cs.ocap = capture; cs.ptop = ptop;
        n = runtimecap(&cs, capture + captop, s, &rem);  /* call function */
        captop -= n;  /* remove nested captures */
        fr -= rem;  /* 'rem' items were popped from Lua stack */
        res = resdyncaptures(L, fr, s - o, e - o);  /* get result */
        if (res == -1)  /* fail? */
          goto fail;
        s = o + res;  /* else update current position */
        n = lua_gettop(L) - fr + 1;  /* number of new captures */
        ndyncap += n - rem;  /* update number of dynamic captures */
        if (n > 0) {  /* any new capture? */
          if ((captop += n + 2) >= capsize) {
            capture = doublecap(L, capture, captop, ptop);
            capsize = 2 * captop;
          }
          /* add new captures to 'capture' list */
          adddyncaptures(s, capture + captop - n - 2, n, fr);
        }
        p++;
        continue;
      }
      case ICloseCapture: {
        const char *s1 = s;
        assert(captop > 0);
        /* if possible, turn capture into a full capture */
        if (capture[captop - 1].siz == 0 &&
            s1 - capture[captop - 1].s < UCHAR_MAX) {
          capture[captop - 1].siz = s1 - capture[captop - 1].s + 1;
          p++;
          continue;
        }
        else {
          capture[captop].siz = 1;  /* mark entry as closed */
          capture[captop].s = s;
          goto pushcapture;
        }
      }
      case IOpenCapture:
        capture[captop].siz = 0;  /* mark entry as open */
        capture[captop].s = s;
        goto pushcapture;
      case IFullCapture:
        capture[captop].siz = getoff(p) + 1;  /* save capture size */
        capture[captop].s = s - getoff(p);
        /* goto pushcapture; */
      pushcapture: {
        capture[captop].idx = p->i.key;
        capture[captop].kind = getkind(p);
        if (++captop >= capsize) {
          capture = doublecap(L, capture, captop, ptop);
          capsize = 2 * captop;
        }
        p++;
        continue;
      }
      default: assert(0); return NULL;
    }
  }

}

/* }====================================================== */


