#include "khash.h"
#include <pthread.h>

KHASH_MAP_INIT_INT64(long, long)
typedef khash_t(long)* internal_hash_map_t;

typedef struct {
   hash_map_t h;
   int refcount;
   pthread_mutex_t mutex;
   int autolock;
   long counter;
} hash_map_lua_t;
