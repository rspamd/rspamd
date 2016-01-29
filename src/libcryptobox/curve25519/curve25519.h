#ifndef CURVE25519_H
#define CURVE25519_H

#include "config.h"

static const guchar curve25519_basepoint[32] = {9};

int curve25519 (guchar *mypublic, const guchar *secret, const guchar *basepoint);
/* Call for optimized implementation of scalarmult if needed */
int curve25519_base (guchar *mypublic, const guchar *secret);
const char* curve25519_load (void);

#endif
