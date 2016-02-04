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
/* Imported from Public Domain djb code */

#ifndef SRC_LIBCRYPTOBOX_CURVE25519_FE_H_
#define SRC_LIBCRYPTOBOX_CURVE25519_FE_H_

typedef int32_t fe[10];

void fe_frombytes(fe,const unsigned char *);
void fe_tobytes(unsigned char *,const fe);

void fe_copy(fe,const fe);
int fe_isnonzero(const fe);
int fe_isnegative(const fe);
void fe_0(fe);
void fe_1(fe);
void fe_cmov(fe,const fe,unsigned int);
void fe_add(fe,const fe,const fe);
void fe_sub(fe,const fe,const fe);
void fe_neg(fe,const fe);
void fe_mul(fe,const fe,const fe);
void fe_sq(fe,const fe);
void fe_sq2(fe,const fe);
void fe_invert(fe,const fe);
void fe_pow22523(fe,const fe);

/*
ge means group element.
Here the group is the set of pairs (x,y) of field elements (see fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2
where d = -121665/121666.
Representations:
  ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
  ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
  ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
  ge_precomp (Duif): (y+x,y-x,2dxy)
*/

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;


void ge_tobytes(unsigned char *,const ge_p2 *);
void ge_p3_tobytes(unsigned char *,const ge_p3 *);
int ge_frombytes_negate_vartime(ge_p3 *,const unsigned char *);

void ge_p2_0(ge_p2 *);
void ge_p3_0(ge_p3 *);
void ge_precomp_0(ge_precomp *);
void ge_p3_to_p2(ge_p2 *,const ge_p3 *);
void ge_p3_to_cached(ge_cached *,const ge_p3 *);
void ge_p1p1_to_p2(ge_p2 *,const ge_p1p1 *);
void ge_p1p1_to_p3(ge_p3 *,const ge_p1p1 *);
void ge_p2_dbl(ge_p1p1 *,const ge_p2 *);
void ge_p3_dbl(ge_p1p1 *,const ge_p3 *);

void ge_madd(ge_p1p1 *,const ge_p3 *,const ge_precomp *);
void ge_msub(ge_p1p1 *,const ge_p3 *,const ge_precomp *);
void ge_add(ge_p1p1 *,const ge_p3 *,const ge_cached *);
void ge_sub(ge_p1p1 *,const ge_p3 *,const ge_cached *);
void ge_scalarmult_base(ge_p3 *,const unsigned char *);
void ge_double_scalarmult_vartime(ge_p2 *,const unsigned char *,const ge_p3 *,const unsigned char *);
void ge_scalarmult_vartime(ge_p3 *,const unsigned char *,const ge_p3 *);
int verify_32(const unsigned char *x, const unsigned char *y);

/*
The set of scalars is \Z/l
where l = 2^252 + 27742317777372353535851937790883648493.
*/

void sc_reduce(unsigned char *);
void sc_muladd(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);

#endif /* SRC_LIBCRYPTOBOX_CURVE25519_FE_H_ */
