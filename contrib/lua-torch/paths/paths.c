/* -*- C -*- */


#include "paths.h"


/* ------------------------------------------------------ */
/* Utils to manipulate strings */


#define SBINCREMENT 256

typedef struct {
  char *buffer;
  int maxlen;
  int len;
} SB;

static void
sbinit(SB *sb)
{
  sb->buffer = (char*)malloc(SBINCREMENT);
  sb->maxlen = SBINCREMENT;
  sb->len = 0;
}

static char *
sbfree(SB *sb)
{
  if (sb->buffer)
    free(sb->buffer);
  sb->buffer = 0;
  return 0;
}

static void
sbgrow(SB *sb, int n)
{
  if (sb->buffer && sb->len + n > sb->maxlen)
    {
      int nlen = sb->maxlen;
      while (sb->len + n > nlen)
        nlen += SBINCREMENT;
      sb->buffer = (char*)realloc(sb->buffer, nlen);
      sb->maxlen = nlen;
    }
}

static void
sbadd1(SB *sb, char c)
{
  sbgrow(sb, 1);
  if (sb->buffer)
    sb->buffer[sb->len++] = c;
}

static void
sbaddn(SB *sb, const char *s, int n)
{
  sbgrow(sb, n);
  if (sb->buffer && s && n)
    memcpy(sb->buffer + sb->len, s, n);
  else if (sb->buffer && n)
    sbfree(sb);
  sb->len += n;
}

static void
sbaddsf(SB *sb, char *s)
{
  if (s)
    sbaddn(sb, s, strlen(s));
  else
    sbfree(sb);
  if (s)
    free((void*)s);
}

static void
sbslash(SB *sb)
{
  int i;
  if (sb->buffer && sb->len)
    for(i=0; i<sb->len; i++)
      if (sb->buffer[i]=='\\')
        sb->buffer[i]='/';
}

static int
sbpush(lua_State *L, SB *sb)
{
  sbslash(sb);
  lua_pushlstring(L, sb->buffer, sb->len);
  sbfree(sb);
  return 1;
}

static int
sbsetpush(lua_State *L,  SB *sb, const char *s)
{
  sbfree(sb);
  lua_pushstring(L, s);
  return 1;
}


/* ------------------------------------------------------ */
/* filep, dirp, basename, dirname */


static int
filep(lua_State *L, int i)
{
  const char *s = luaL_checkstring(L, i);
#ifdef _WIN32
  struct _stat buf;
  if (_stat(s,&buf) < 0)
    return 0;
  if (buf.st_mode & S_IFDIR)
    return 0;
#else
  struct stat buf;
  if (stat(s,&buf) < 0)
    return 0;
  if (buf.st_mode & S_IFDIR)
    return 0;
#endif
  return 1;
}


static int
dirp(lua_State *L, int i)
{
  const char *s = luaL_checkstring(L, i);
#ifdef _WIN32
  char buffer[8];
  struct _stat buf;
  const char *last;
  if ((s[0]=='/' || s[0]=='\\') &&
      (s[1]=='/' || s[1]=='\\') && !s[2])
    return 1;
  if (s[0] && isalpha((unsigned char)(s[0])) && s[1] == ':' && s[2] == 0)
    { buffer[0]=s[0]; buffer[1]=':'; buffer[2]='.'; buffer[3]=0; s = buffer; }
  if (_stat(s, &buf) >= 0)
    if (buf.st_mode & S_IFDIR)
      return 1;
#else
  struct stat buf;
  if (stat(s,&buf)==0)
    if (buf.st_mode & S_IFDIR)
      return 1;
#endif
  return 0;
}


static int
lua_filep(lua_State *L)
{
  lua_pushboolean(L, filep(L, 1));
  return 1;
}


static int
lua_dirp(lua_State *L)
{
  lua_pushboolean(L, dirp(L, 1));
  return 1;
}


static int
lua_basename(lua_State *L)
{
  const char *fname = luaL_checkstring(L, 1);
  const char *suffix = luaL_optstring(L, 2, 0);

#ifdef _WIN32

  int sl;
  const char *p, *s;
  SB sb;
  sbinit(&sb);
  /* Special cases */
  if (fname[0] && fname[1]==':') {
    sbaddn(&sb, fname, 2);
    fname += 2;
    if (fname[0]=='/' || fname[0]=='\\')
      sbadd1(&sb, '/');
    while (fname[0]=='/' || fname[0]=='\\')
      fname += 1;
    if (fname[0]==0)
      return sbpush(L, &sb);
    sb.len = 0;
  }
  /* Position p after last nontrivial slash */
  s = p = fname;
  while (*s) {
    if ((s[0]=='\\' || s[0]=='/') &&
        (s[1] && s[1]!='/' && s[1]!='\\' ) )
      p = s + 1;
    s++;
  }
  /* Copy into buffer */
  while (*p && *p!='/' && *p!='\\')
    sbadd1(&sb, *p++);
  /* Process suffix */
  if (suffix==0 || suffix[0]==0)
    return sbpush(L, &sb);
  if (suffix[0]=='.')
    suffix += 1;
  if (suffix[0]==0)
    return sbpush(L, &sb);
  sl = strlen(suffix);
  if (sb.len > sl) {
    s =  sb.buffer + sb.len - (sl + 1);
    if (s[0]=='.' && _strnicmp(s+1,suffix, sl)==0)
      sb.len = s - sb.buffer;
  }
  return sbpush(L, &sb);

#else

  int sl;
  const char *s, *p;
  SB sb;
  sbinit(&sb);
  /* Position p after last nontrivial slash */
  s = p = fname;
  while (*s) {
    if (s[0]=='/' && s[1] && s[1]!='/')
      p = s + 1;
    s++;
  }
  /* Copy into buffer */
  while (*p && *p!='/')
    sbadd1(&sb, *p++);
  /* Process suffix */
  if (suffix==0 || suffix[0]==0)
    return sbpush(L, &sb);
  if (suffix[0]=='.')
    suffix += 1;
  if (suffix[0]==0)
    return sbpush(L, &sb);
  sl = strlen(suffix);
  if (sb.len > sl) {
    s =  sb.buffer + sb.len - (sl + 1);
    if (s[0]=='.' && strncmp(s+1,suffix, sl)==0)
      sb.len = s - sb.buffer;
  }
  return sbpush(L, &sb);

#endif
}


static int
lua_dirname(lua_State *L)
{
  const char *fname = luaL_checkstring(L, 1);

#ifdef _WIN32

  const char *s;
  const char *p;
  SB sb;
  sbinit(&sb);
  /* Handle leading drive specifier */
  if (isalpha((unsigned char)fname[0]) && fname[1]==':') {
    sbadd1(&sb, *fname++);
    sbadd1(&sb, *fname++);
  }
  /* Search last non terminal / or \ */
  p = 0;
  s = fname;
  while (*s) {
    if ((s[0]=='\\' || s[0]=='/') &&
        (s[1] && s[1]!='/' && s[1]!='\\') )
      p = s;
    s++;
  }
  /* Cannot find non terminal / or \ */
  if (p == 0) {
    if (sb.len > 0) {
      if (fname[0]==0 || fname[0]=='/' || fname[0]=='\\')
	sbadd1(&sb, '/');
      return sbpush(L, &sb);
    } else {
      if (fname[0]=='/' || fname[0]=='\\')
	return sbsetpush(L, &sb, "//");
      else
	return sbsetpush(L, &sb, ".");
    }
  }
  /* Single leading slash */
  if (p == fname) {
    sbadd1(&sb, '/');
    return sbpush(L, &sb);
  }
  /* Backtrack all slashes */
  while (p>fname && (p[-1]=='/' || p[-1]=='\\'))
    p--;
  /* Multiple leading slashes */
  if (p == fname)
    return sbsetpush(L, &sb, "//");
  /* Regular case */
  s = fname;
  do {
    sbadd1(&sb, *s++);
  } while (s<p);
  return sbpush(L, &sb);

#else

  const char *s = fname;
  const char *p = 0;
  SB sb;
  sbinit(&sb);
  while (*s) {
    if (s[0]=='/' && s[1] && s[1]!='/')
      p = s;
    s++;
  }
  if (!p) {
    if (fname[0]=='/')
      return sbsetpush(L, &sb, fname);
    else
      return sbsetpush(L, &sb, ".");
  }
  s = fname;
  do {
    sbadd1(&sb, *s++);
  } while (s<p);
  return sbpush(L, &sb);

#endif
}


static int
lua_extname(lua_State *L)
{
  const char *fname = luaL_checkstring(L, 1);
  const char *p;

  p = fname + strlen(fname) - 1;
  while (p >= fname) {
    if (*p == '.') {
      lua_pushstring(L, p + 1);
      return 1;
    }
    p--;
  }
  return 0;
}


/* ------------------------------------------------------ */
/* cwd and concat */


static int
lua_cwd(lua_State *L)
{
#ifdef _WIN32

  char drv[2];
  int l;
  SB sb;
  sbinit(&sb);
  drv[0] = '.'; drv[1] = 0;
  l = GetFullPathNameA(drv, sb.maxlen, sb.buffer, 0);
  if (l > sb.maxlen) {
    sbgrow(&sb, l+1);
    l = GetFullPathNameA(drv, sb.maxlen, sb.buffer, 0);
  }
  if (l <= 0)
    return sbsetpush(L, &sb, ".");
  sb.len += l;
  return sbpush(L, &sb);

#elif HAVE_GETCWD

  const char *s;
  SB sb;
  sbinit(&sb);
  s = getcwd(sb.buffer, sb.maxlen);
  while (!s && errno==ERANGE)
    {
      sbgrow(&sb, sb.maxlen + SBINCREMENT);
      s = getcwd(sb.buffer, sb.maxlen);
    }
  if (! s)
    return sbsetpush(L, &sb, ".");
  sb.len += strlen(s);
  return sbpush(L, &sb);

#else

  const char *s;
  SB sb;
  sbinit(&sb);
  sbgrow(&sb, PATH_MAX);
  s = getwd(sb.buffer);
  if (! s)
    return sbsetpush(L, &sb, ".");
  sb.len += strlen(s);
  return sbpush(L, &sb);

#endif
}



static int
concat_fname(lua_State *L, const char *fname)
{
  const char *from = lua_tostring(L, -1);

#ifdef _WIN32

  const char *s;
  SB sb;
  sbinit(&sb);
  sbaddn(&sb, from, strlen(from));
  if (fname==0)
    return sbpush(L, &sb);
  /* Handle absolute part of fname */
  if (fname[0]=='/' || fname[0]=='\\') {
    if (fname[1]=='/' || fname[1]=='\\') {
      sb.len = 0;                            /* Case //abcd */
      sbaddn(&sb, "//", 2);
    } else {
      char drive;
      if (sb.len >= 2 && sb.buffer[1]==':'   /* Case "/abcd" */
          && isalpha((unsigned char)(sb.buffer[0])) )
        drive = sb.buffer[0];
      else
        drive = _getdrive() + 'A' - 1;
      sb.len = 0;
      sbadd1(&sb, drive);
      sbaddn(&sb, ":/", 2);
    }
  } else if (fname[0] && 	              /* Case "x:abcd"   */
             isalpha((unsigned char)(fname[0])) && fname[1]==':') {
    if (fname[2]!='/' && fname[2]!='\\') {
      if (sb.len < 2 || sb.buffer[1]!=':'
          || !isalpha((unsigned char)(sb.buffer[0]))
          || (toupper((unsigned char)sb.buffer[0]) !=
              toupper((unsigned char)fname[0]) ) )
        {
          int l;
          char drv[4];
          sb.len = 0;
          drv[0]=fname[0]; drv[1]=':'; drv[2]='.'; drv[3]=0;
          l = GetFullPathNameA(drv, sb.maxlen, sb.buffer, 0);
          if (l > sb.maxlen) {
            sbgrow(&sb, l+1);
            l = GetFullPathNameA(drv, sb.maxlen, sb.buffer, 0);
          }
          if (l <= 0)
            sbaddn(&sb, drv, 3);
          else
            sb.len += l;
        }
      fname += 2;
    } else {
      sb.len = 0;                              /* Case "x:/abcd"  */
      sbadd1(&sb, toupper((unsigned char)fname[0]));
      sbaddn(&sb, ":/", 2);
      fname += 2;
      while (*fname == '/' || *fname == '\\')
        fname += 1;
    }
  }
  /* Process path components */
  for (;;)
  {
    while (*fname=='/' || *fname=='\\')
      fname ++;
    if (*fname == 0)
      return sbpush(L, &sb);
    if (fname[0]=='.') {
      if (fname[1]=='/' || fname[1]=='\\' || fname[1]==0) {
	fname += 1;
	continue;
      }
      if (fname[1]=='.')
        if (fname[2]=='/' || fname[2]=='\\' || fname[2]==0) {
          size_t l;
	  fname += 2;
          lua_pushcfunction(L, lua_dirname);
          sbpush(L, &sb);
          lua_call(L, 1, 1);
          s = lua_tolstring(L, -1, &l);
          sbinit(&sb);
          sbaddn(&sb, s, l);
          lua_pop(L, 1);
	  continue;
      }
    }
    if (sb.len==0 ||
        (sb.buffer[sb.len-1]!='/' && sb.buffer[sb.len-1]!='\\') )
      sbadd1(&sb, '/');
    while (*fname && *fname!='/' && *fname!='\\')
      sbadd1(&sb, *fname++);
  }

#else
  SB sb;
  sbinit(&sb);

  if (fname && fname[0]=='/')
    sbadd1(&sb, '/');
  else
    sbaddn(&sb, from, strlen(from));
  for (;;) {
    while (fname && fname[0]=='/')
      fname++;
    if (!fname || !fname[0]) {
      sbadd1(&sb, '/');
      while (sb.len > 1 && sb.buffer[sb.len-1]=='/')
        sb.len --;
      return sbpush(L, &sb);
    }
    if (fname[0]=='.') {
      if (fname[1]=='/' || fname[1]==0) {
	fname +=1;
	continue;
      }
      if (fname[1]=='.')
	if (fname[2]=='/' || fname[2]==0) {
	  fname +=2;
          while (sb.len > 0 && sb.buffer[sb.len-1]=='/')
            sb.len --;
          while (sb.len > 0 && sb.buffer[sb.len-1]!='/')
            sb.len --;
	  continue;
	}
    }
    if (sb.len == 0 || sb.buffer[sb.len-1] != '/')
      sbadd1(&sb, '/');
    while (*fname!=0 && *fname!='/')
      sbadd1(&sb, *fname++);
  }


#endif

}


static int
lua_concatfname(lua_State *L)
{
  int i;
  int narg = lua_gettop(L);
  lua_cwd(L);
  for (i=1; i<=narg; i++)
    {
      concat_fname(L, luaL_checkstring(L, i));
      lua_remove(L, -2);
    }
  return 1;
}



/* ------------------------------------------------------ */
/* execdir */


static int
lua_execdir(lua_State *L)
{
  const char *s = 0;
#if HAVE_LUA_EXECUTABLE_DIR
  s =  lua_executable_dir(0);
#endif
  if (s && s[0])
    lua_pushstring(L, s);
  else
    lua_pushnil(L);
  return 1;
}



/* ------------------------------------------------------ */
/* file lists */


static int
lua_dir(lua_State *L)
{
  int k = 0;
  const char *s = luaL_checkstring(L, 1);

#ifdef _WIN32

  SB sb;
  struct _finddata_t info;
  intptr_t hfind;
  /* special cases */
  lua_createtable(L, 0, 0);
  if ((s[0]=='/' || s[0]=='\\') &&
      (s[1]=='/' || s[1]=='\\') && !s[2])
    {
      int drive;
      hfind = GetLogicalDrives();
      for (drive='A'; drive<='Z'; drive++)
        if (hfind & ((intptr_t)1<<(drive-'A'))) {
          lua_pushfstring(L, "%c:/", drive);
          lua_rawseti(L, -2, ++k);
        }
    }
  else if (dirp(L, 1)) {
    lua_pushliteral(L, "..");
    lua_rawseti(L, -2, ++k);
  } else {
    lua_pushnil(L);
    return 1;
  }
  /* files */
  sbinit(&sb);
  sbaddn(&sb, s, strlen(s));
  if (sb.len>0 && sb.buffer[sb.len-1]!='/' && sb.buffer[sb.len-1]!='\\')
    sbadd1(&sb, '/');
  sbaddn(&sb, "*.*", 3);
  sbadd1(&sb, 0);
  hfind = _findfirst(sb.buffer, &info);
  if (hfind != -1) {
    do {
      if (strcmp(".",info.name) && strcmp("..",info.name)) {
        lua_pushstring(L, info.name);
        lua_rawseti(L, -2, ++k);
      }
    } while ( _findnext(hfind, &info) != -1 );
    _findclose(hfind);
  }
  sbfree(&sb);

#else

  DIR *dirp;
  struct dirent *d;
  dirp = opendir(s);
  if (dirp) {
    lua_createtable(L, 0, 0);
    while ((d = readdir(dirp))) {
      int n = NAMLEN(d);
      lua_pushlstring(L, d->d_name, n);
      lua_rawseti(L, -2, ++k);
    }
    closedir(dirp);
  } else
    lua_pushnil(L);

#endif

  return 1;
}


/* ------------------------------------------------------ */
/* tmpname */


static const char *tmpnames_key = "tmpname_sentinel";

struct tmpname_s {
    struct tmpname_s *next;
    char tmp[4];
};

static int
gc_tmpname(lua_State *L)
{
  if (lua_isuserdata(L, -1))
  {
    struct tmpname_s **pp = (struct tmpname_s **)lua_touserdata(L, -1);
    while (pp && *pp)
    {
      struct tmpname_s *p = *pp;
      *pp = p->next;
      remove(p->tmp);
      free(p);
    }
  }
  return 0;

}

static void
add_tmpname(lua_State *L, const char *tmp)
{
  struct tmpname_s **pp = 0;
  lua_pushlightuserdata(L, (void*)tmpnames_key);
  lua_rawget(L, LUA_REGISTRYINDEX);
  if (lua_isuserdata(L, -1))
  {
    pp = (struct tmpname_s **)lua_touserdata(L, -1);
    lua_pop(L, 1);
  }
  else
  {
    lua_pop(L, 1);
    /* create sentinel */
    lua_pushlightuserdata(L, (void*)tmpnames_key);
    pp = (struct tmpname_s **)lua_newuserdata(L, sizeof(void*));
    pp[0] = 0;
    lua_createtable(L, 0, 1);
    lua_pushcfunction(L, gc_tmpname);
    lua_setfield(L,-2,"__gc");
    lua_setmetatable(L, -2);
    lua_rawset(L, LUA_REGISTRYINDEX);
  }
  while (pp && *pp)
  {
      struct tmpname_s *p = *pp;
      if (!strcmp(p->tmp, tmp)) {
        return;
      }
      pp = &(p->next);
  }
  if (pp)
  {
        int len = strlen(tmp);
        struct tmpname_s *t = (struct tmpname_s*)malloc(len + sizeof(struct tmpname_s));
        if (t)
        {
            t->next = 0;
            memcpy(t->tmp, tmp, len);
            t->tmp[len] = 0;
            *pp = t;
        }
    }
}


static int
lua_tmpname(lua_State *L)
{
  char *tmp;
  int fd = -1;
#ifdef _WIN32
  tmp = _tempnam("c:/temp", "luatmp");
#else
  char *tempdir = getenv("TMPDIR");
  if (tempdir == NULL) {
    tempdir = "/tmp";
  }
  tmp = calloc(1, PATH_MAX);
  snprintf(tmp, PATH_MAX, "%s/%sXXXXXXXX", tempdir, "luatmp");
  fd = mkstemp(tmp);

  if (fd == -1) {
    free(tmp);
    tmp = NULL;
  }
  else {
    /* Stupid and unsafe thing but that's how this library wants to do it */
    close(fd);
  }
#endif
  if (tmp)
  {
    lua_pushstring(L, tmp);
    add_tmpname(L, tmp);
    free(tmp);
    return 1;
  }
  else
  {
    lua_pushnil(L);
    return 1;
  }
}



/* ------------------------------------------------------ */
/* mkdir, rmdir */

static int
pushresult (lua_State *L, int i, const char *filename) {
  int en = errno;
  if (i) {
    lua_pushboolean(L, 1);
    return 1;
  }
  else {
    lua_pushnil(L);
    lua_pushfstring(L, "%s: %s", filename, strerror(en));
    lua_pushinteger(L, en);
    return 3;
  }
}

static int
lua_mkdir(lua_State *L)
{
   int status = 0;
   const char *s = luaL_checkstring(L, 1);
   lua_pushcfunction(L, lua_mkdir);
   lua_pushcfunction(L, lua_dirname);
   lua_pushvalue(L, 1);
   lua_call(L, 1, 1);
   if (! dirp(L, -1))
      lua_call(L, 1, 3);
#ifdef _WIN32
   status = _mkdir(s);
#else
   status = mkdir(s, 0777);
#endif
   return pushresult(L, status == 0, s);
}

static int
lua_rmdir(lua_State *L)
{
  const char *s = luaL_checkstring(L, 1);
#ifdef _WIN32
  int status = _rmdir(s);
#else
  int status = rmdir(s);
#endif
  return pushresult(L, status == 0, s);
}


/* ------------------------------------------------------ */
/* uname */


static int
lua_uname(lua_State *L)
{
#if defined(_WIN32)
  const char *name;
  SYSTEM_INFO info;
  lua_pushliteral(L, "Windows");
  name = getenv("COMPUTERNAME");
  lua_pushstring(L, name ? name : "");
  memset(&info, 0, sizeof(info));
  GetSystemInfo(&info);
  if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
    lua_pushliteral(L, "AMD64");
  else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
    lua_pushliteral(L, "X86");
  else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM)
    lua_pushliteral(L, "ARM");
  else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
    lua_pushliteral(L, "IA64");
  else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
    lua_pushstring(L, "");
  return 3;
#else
# if defined(HAVE_SYS_UTSNAME_H)
  struct utsname info;
  if (uname(&info) >= 0)
    {
      lua_pushstring(L, info.sysname);
      lua_pushstring(L, info.nodename);
      lua_pushstring(L, info.machine);
      return 3;
    }
# endif
  lua_pushstring(L, "Unknown");
  return 1;
#endif
}

static int
lua_getregistryvalue(lua_State *L)
{
#ifdef _WIN32
    static char *keynames[] = {
        "HKEY_CLASSES_ROOT",
        "HKEY_CURRENT_CONFIG",
        "HKEY_CURRENT_USER",
        "HKEY_LOCAL_MACHINE",
        "HKEY_USERS",
        NULL };
    static HKEY keys[] = {
        HKEY_CLASSES_ROOT,
        HKEY_CURRENT_CONFIG,
        HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE,
        HKEY_USERS
    };

    HKEY rkey = keys[ luaL_checkoption(L, 1, NULL, keynames) ];
    const char *subkey = luaL_checkstring(L, 2);
    const char *value = luaL_checkstring(L, 3);
    HKEY skey;
    DWORD type;
    DWORD len = 0;
    char *data = NULL;
    LONG res;
    res = RegOpenKeyExA(rkey, subkey, 0, KEY_READ, &skey);
    if (res != ERROR_SUCCESS)
    {
        lua_pushnil(L);
        lua_pushinteger(L, res);
        if (res == ERROR_FILE_NOT_FOUND)
            lua_pushstring(L, "subkey not found");
        if (res == ERROR_ACCESS_DENIED)
            lua_pushstring(L, "subkey access denied");
        else
            return 2;
        return 3;
    }
    res = RegQueryValueExA(skey, value, NULL, &type, (LPBYTE)data, &len);
    if (len > 0)
    {
        len += 8;
        data = (char*)malloc(len);
        if (! data)
            luaL_error(L, "out of memory");
        res = RegQueryValueExA(skey, value, NULL, &type, (LPBYTE)data, &len);
    }
    RegCloseKey(skey);
    if (res != ERROR_SUCCESS)
    {
        if (data)
            free(data);
        lua_pushnil(L);
        lua_pushinteger(L, res);
        if (res == ERROR_FILE_NOT_FOUND)
            lua_pushstring(L, "value not found");
        if (res == ERROR_ACCESS_DENIED)
            lua_pushstring(L, "value access denied");
        else
            return 2;
        return 3;
    }
    switch(type)
    {
    case REG_DWORD:
      lua_pushinteger(L, (lua_Integer)*(const DWORD*)data);
      if (data)
          free(data);
      return 1;
    case REG_EXPAND_SZ:
      if (data && len > 0)
      {
          if ((len = ExpandEnvironmentStrings(data, NULL, 0)) > 0)
          {
            char *buf = (char*)malloc(len + 8);
            if (!buf)
                luaL_error(L, "out of memory");
            len = ExpandEnvironmentStrings(data, buf, len+8);
            free(data);
            data = buf;
          }
      }
      /* fall thru */
    case REG_SZ:
      if (data && len > 0)
        if (((const char*)data)[len-1] == 0)
          len -= 1;
      /* fall thru */
    case REG_BINARY:
      if (data && len > 0)
        lua_pushlstring(L, (const char*)data, (int)len);
      else
        lua_pushliteral(L, "");
      if (data)
          free(data);
      return 1;
      /* unimplemented */
    case REG_QWORD:
    case REG_MULTI_SZ:
    default:
      lua_pushnil(L);
      lua_pushinteger(L, res);
      lua_pushfstring(L, "getting registry type %d not implemented", type);
      return 3;
    }
#else
    luaL_error(L, "This function exists only on windows");
    return 0;
#endif
}

/* ------------------------------------------------------ */
/* require (with global flag) */

#ifdef HAVE_DLOPEN
# define NEED_PATH_REQUIRE 1
# include <dlfcn.h>
# ifndef RTLD_LAZY
#  define RTLD_LAZY 1
# endif
# ifndef RTLD_GLOBAL
#  define RTLD_GLOBAL 0
# endif
# define LL_LOAD(h,fname) h=dlopen(fname,RTLD_LAZY|RTLD_GLOBAL)
# define LL_SYM(h,sym) dlsym(h, sym)
#endif

#ifdef _WIN32
# define NEED_PATH_REQUIRE 1
# include <windows.h>
# define LL_LOAD(h,fname) h=(void*)LoadLibraryA(fname)
# define LL_SYM(h,sym) GetProcAddress((HINSTANCE)h,sym)
#endif

#if NEED_PATH_REQUIRE

/* {{{ functions copied or derived from loadlib.c */

static int readable (const char *filename)
{
  FILE *f = fopen(filename, "r");  /* try to open file */
  if (f == NULL) return 0;  /* open failed */
  fclose(f);
  return 1;
}

#if LUA_VERSION_NUM >= 502 /* LUA52 compatibility defs */
#define LUA_PATHSEP ";"
#define PATHS_LUA_CLEANUP_DEFS 1
#endif
static const char *pushnexttemplate (lua_State *L, const char *path)
{
  const char *l;
  while (*path == *LUA_PATHSEP) path++;  /* skip separators */
  if (*path == '\0') return NULL;  /* no more templates */
  l = strchr(path, *LUA_PATHSEP);  /* find next separator */
  if (l == NULL) l = path + strlen(path);
  lua_pushlstring(L, path, l - path);  /* template */
  return l;
}
#ifdef PATHS_LUA_CLEANUP_DEFS /* cleanup after yourself */
#undef LUA_PATHSEP
#endif

static const char *pushfilename (lua_State *L, const char *name)
{
  const char *path;
  const char *filename;
  lua_getglobal(L, "package");
  lua_getfield(L, -1, "cpath");
  lua_remove(L, -2);
  if (! (path = lua_tostring(L, -1)))
    luaL_error(L, LUA_QL("package.cpath") " must be a string");
  lua_pushliteral(L, "");
  while ((path = pushnexttemplate(L, path))) {
    filename = luaL_gsub(L, lua_tostring(L, -1), "?", name);
    lua_remove(L, -2);
    if (readable(filename))
    { /* stack:  cpath errmsg filename */
        lua_remove(L, -3);
        lua_remove(L, -2);
        return lua_tostring(L, -1);
      }
    lua_pushfstring(L, "\n\tno file " LUA_QS, filename);
    lua_remove(L, -2); /* remove file name */
    lua_concat(L, 2);  /* add entry to possible error message */
  }
  lua_pushfstring(L, "module " LUA_QS " not found", name);
  lua_replace(L, -3);
  lua_concat(L, 2);
  lua_error(L);
  return 0;
}

/* functions copied or derived from loadlib.c }}} */

static int
path_require(lua_State *L)
{
  const char *filename;
  lua_CFunction func;
  void *handle;
  const char *name = luaL_checkstring(L, 1);
  lua_settop(L, 1);
  lua_getfield(L, LUA_REGISTRYINDEX, "_LOADED");  /* index 2 */
  lua_getfield(L, 2, name);
  if (lua_toboolean(L, -1))
    return 1;
  filename = pushfilename(L, name);  /* index 3 */
  LL_LOAD(handle, filename);
  if (! handle)
    luaL_error(L, "cannot load " LUA_QS, filename);
  lua_pushfstring(L, "luaopen_%s", name);  /* index 4 */
  func = (lua_CFunction)LL_SYM(handle, lua_tostring(L, -1));
  if (! func)
    luaL_error(L, "no symbol " LUA_QS " in module " LUA_QS,
               lua_tostring(L, -1), filename);
  lua_pushboolean(L, 1);
  lua_setfield(L, 2, name);
  lua_pushcfunction(L, func);
  lua_pushstring(L, name);
  lua_call(L, 1, 1);
  if (! lua_isnil(L, -1))
    lua_setfield(L, 2, name);
  lua_getfield(L, 2, name);
  return 1;
}

#else

/* fallback to calling require */

static int
path_require(lua_State *L)
{
  int narg = lua_gettop(L);
  lua_getglobal(L, "require");
  lua_insert(L, 1);
  lua_call(L, narg, 1);
  return 1;
}

#endif




/* ------------------------------------------------------ */
/* register */


static const struct luaL_Reg paths__ [] = {
  {"filep", lua_filep},
  {"dirp", lua_dirp},
  {"basename", lua_basename},
  {"dirname", lua_dirname},
  {"extname", lua_extname},
  {"cwd", lua_cwd},
  {"concat", lua_concatfname},
  {"execdir", lua_execdir},
  {"dir", lua_dir},
  {"tmpname", lua_tmpname},
  {"mkdir", lua_mkdir},
  {"rmdir", lua_rmdir},
  {"uname", lua_uname},
  {"getregistryvalue", lua_getregistryvalue},
  {"require", path_require},
  {NULL, NULL}
};


PATHS_API int
luaopen_libpaths(lua_State *L)
{
  lua_newtable(L);
  lua_pushvalue(L, -1);
  lua_setglobal(L, "paths");
#if LUA_VERSION_NUM >= 502
  luaL_setfuncs(L, paths__, 0);
#else
  luaL_register(L, NULL, paths__);
#endif
  return 1;
}
