-- Actually these regular expressions were obtained from SpamAssassin project, so they are licensed by apache license:
--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to you under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at:
-- 
--     http://www.apache.org/licenses/LICENSE-2.0
-- 
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- Drugs spam (viagra, pills etc)
-- XXX: remove this legacy to statfile


local reconf = config['regexp']

local drugs_diet1 = '/(?:\\b|\\s)[_\\W]{0,3}p[_\\W]{0,3}h[_\\W]{0,3}[e3\\xE8-\\xEB][_\\W]{0,3}n[_\\W]{0,3}t[_\\W]{0,3}[e3\\xE8-\\xEB][_\\W]{0,3}r[_\\W]{0,3}m[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}n[_\\W]{0,3}[e3\\xE8-\\xEB][_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_diet2 = '/(?:\\b|\\s)_{0,3}[i1!|l\\xEC-\\xEF][_\\W]?o[_\\W]?n[_\\W]?[a4\\xE0-\\xE6@][_\\W]?m[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?n_{0,3}\\b/irP'
local drugs_diet3 = '/\\bbontril\\b/irP'
local drugs_diet4 = '/\\bphendimetrazine\\b/irP'
local drugs_diet5 = '/\\bdiethylpropion\\b/irP'
local drugs_diet6 = '/(?:\\b|\\s)[_\\W]{0,3}M[_\\W]{0,3}[e3\\xE8-\\xEB][_\\W]{0,3}r[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}d[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_diet7 = '/\\b_{0,3}t[_\\W]?[e3\\xE8-\\xEB][_\\W]?n[_\\W]?u[_\\W]?a[_\\W]?t[_\\W]?[e3\\xE8-\\xEB]_{0,3}(?:\\b|\\s)/irP'
local drugs_diet8 = '/\\b_{0,3}d[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?d[_\\W]?r[_\\W][e3\\xE8-\\xEB[_\\W]?xx?_{0,3}\\b/irP'
local drugs_diet9 = '/\\b_{0,3}a[_\\W]?d[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?p[_\\W]?[e3\\xE8-\\xEB][_\\W]?x_{0,3}\\b/irP'
local drugs_diet10 = '/\\b_{0,3}x?x[_\\W]?[e3\\xE8-\\xEB][_\\W]?n[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?c[_\\W]?[a4\\xE0-\\xE6@][_\\W]?l_{0,3}\\b/irP'
reconf['DRUGS_DIET'] = string.format('((%s) | (%s) | (%s)) & ((%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], drugs_diet1, drugs_diet2, drugs_diet3, drugs_diet4, drugs_diet5, drugs_diet6, drugs_diet7, drugs_diet8, drugs_diet9, drugs_diet10)
local drugs_erectile1 = '/(?:\\b|\\s)[_\\W]{0,3}(?:\\\\\\/|V)[_\\W]{0,3}[ij1!|l\\xEC\\xED\\xEE\\xEF][_\\W]{0,3}[a40\\xE0-\\xE6@][_\\W]{0,3}[xyz]?[gj][_\\W]{0,3}r[_\\W]{0,3}[a40\\xE0-\\xE6@][_\\W]{0,3}x?[_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_erectile2 = '/\\bV(?:agira|igara|iaggra|iaegra)\\b/irP'
local drugs_erectile3 = '/(?:\\A|[\\s\\x00-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\x7f])[_\\W]{0,3}C[_\\W]{0,3}[ij1!|l\\xEC\\xED\\xEE\\xEF][_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}l?[l!|1][_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}s[_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_erectile4 = '/\\bC(?:alis|ilias|ilais)\\b/irP'
local drugs_erectile5 = '/\\b_{0,3}s[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?l[_\\W]?d[_\\W]?[e3\\xE8-\\xEB][_\\W]?n[_\\W]?[a4\\xE0-\\xE6@][_\\W]?f[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?l c[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?t[_\\W]?r[_\\W]?[a4\\xE0-\\xE6@][_\\W]?t[_\\W]?[e3\\xE8-\\xEB]_{0,3}(?:\\b|\\s)/irP'
local drugs_erectile6 = '/\\b_{0,3}L[_\\W]?[e3\\xE8-\\xEB][_\\W]?(?:\\\\\\/|V)[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?t[_\\W]?r[_\\W]?[a4\\xE0-\\xE6@][_\\W]?(?:\\b|\\s)/irP'
local drugs_erectile8 = '/\\b_{0,3}T[_\\W]?[a4\\xE0-\\xE6@][_\\W]?d[_\\W]?[a4\\xE0-\\xE6@][_\\W]?l[_\\W]?[a4\\xE0-\\xE6@][_\\W]?f[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?l_{0,3}\\b/irP'
local drugs_erectile10 = '/\\b_{0,3}V[_\\W]?(?:i|\\&iuml\\;)[_\\W]?(?:a|\\&agrave|\\&aring)\\;?[_\\W]?g[_\\W]?r[_\\W]?(?:a|\\&agrave|\\&aring)\\b/irP'
local drugs_erectile11 = '/(?:\\b|\\s)_{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}p[_\\W]{0,3}c[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}[l!|1][_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}s_{0,3}\\b/irP'
reconf['DRUGS_ERECTILE'] = string.format('((%s) | (%s) | (%s)) & ((%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], drugs_erectile1, drugs_erectile2, drugs_erectile3, drugs_erectile4, drugs_erectile5, drugs_erectile6, drugs_erectile8, drugs_erectile10, drugs_erectile11)
local drugs_anxiety1 = '/(?:\\b|\\s)[_\\W]{0,3}x?x[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}n[_\\W]{0,3}[ea4\\xE1\\xE2\\xE3@][_\\W]{0,3}xx?_{0,3}\\b/irP'
local drugs_anxiety2 = '/\\bAlprazolam\\b/irP'
local drugs_anxiety3 = '/(?:\\b|\\s)[_\\W]{0,3}(?:\\\\\\/|V)[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}[l|][_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}[u\\xB5\\xF9-\\xFC][_\\W]{0,3}m\\b/irP'
local drugs_anxiety4 = '/\\b_{0,3}D[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?[a4\\xE0-\\xE6@][_\\W]?z[_\\W]?[ea3\\xE9\\xEA\\xEB][_\\W]?p[_\\W]?[a4\\xE0-\\xE6@][_\\W]?m_{0,3}\\b/irP'
local drugs_anxiety5 = '/(?:\\b|\\s)[a4\\xE0-\\xE6@][_\\W]?t[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?v[_\\W]?[a4\\xE0-\\xE6@][_\\W]?n_{0,3}\\b/irP'
local drugs_anxiety6 = '/\\b_{0,3}l[_\\W]?[o0\\xF2-\\xF6][_\\W]?r[_\\W]?[a4\\xE0-\\xE6@][_\\W]?z[_\\W]?[e3\\xE8-\\xEB][_\\W]?p[_\\W]?[a4\\xE0-\\xE6@][_\\W]?m_{0,3}\\b/irP'
local drugs_anxiety7 = '/\\b_{0,3}c[_\\W]?l[_\\W]?[o0\\xF2-\\xF6][_\\W]?n[_\\W]?[a4\\xE0-\\xE6@][_\\W]?z[_\\W]?e[_\\W]?p[_\\W]?[a4\\xE0-\\xE6@][_\\W]?m\\b/irP'
local drugs_anxiety8 = '/\\bklonopin\\b/irP'
local drugs_anxiety9 = '/\\brivotril\\b/irP'
reconf['DRUGS_ANXIETY'] = string.format('((%s) | (%s) | (%s)) & ((%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], drugs_anxiety1, drugs_anxiety2, drugs_anxiety3, drugs_anxiety4, drugs_anxiety5, drugs_anxiety6, drugs_anxiety7, drugs_anxiety8, drugs_anxiety9)
reconf['DRUGS_ANXIETY_EREC'] = string.format('(%s) & (%s)', reconf['DRUGS_ERECTILE'], reconf['DRUGS_ANXIETY'])
local drugs_pain1 = '/\\b_{0,3}h[_\\W]?y[_\\W]?d[_\\W]?r[_\\W]?[o0\\xF2-\\xF6][_\\W]?c[_\\W]?[o0\\xF2-\\xF6][_\\W]?d[_\\W]?[o0\\xF2-\\xF6][_\\W]?n[_\\W]?e_{0,3}\\b/irP'
local drugs_pain2 = '/\\b_{0,3}c[o0\\xF2-\\xF6]deine_{0,3}\\b/irP'
local drugs_pain3 = '/(?:\\b|\\s)[_\\W]{0,3}[u\\xB5\\xF9-\\xFC][_\\W]{0,3}l[_\\W]{0,3}t[_\\W]{0,3}r[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}m_{0,3}\\b/irP'
local drugs_pain4 = '/(?:\\b|\\s)[_\\W]{0,3}(?:\\\\\\/|V)[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}c[_\\W]{0,3}[o0\\xF2-\\xF6][_\\W]{0,3}d[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}ns?[_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_pain5 = '/\\b_{0,3}t[_\\W]?r[_\\W]?[a4\\xE0-\\xE6@][_\\W]?m[_\\W]?[a4\\xE0-\\xE6@][_\\W]?d[_\\W]?[o0\\xF2-\\xF6][_\\W]?[l!|1]_{0,3}\\b/irP'
local drugs_pain6 = '/\\b_{0,3}u[_\\W]?l[_\\W]?t[_\\W]?r[_\\W]?a[_\\W]?c[_\\W]?e[_\\W]?t_{0,3}\\b/irP'
local drugs_pain7 = '/\\b_{0,3}f[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?[o0\\xF2-\\xF6][_\\W]?r[_\\W]?[i1!|l\\xEC-\\xEF][_\\W]?c[_\\W]?[e3\\xE8-\\xEB][_\\W]?[t7]_{0,3}\\b/irP'
local drugs_pain8 = '/\\b_{0,3}c[_\\W]?[e3\\xE8-\\xEB][_\\W]?l[_\\W]?[e3\\xE8-\\xEB][_\\W]?b[_\\W]?r[_\\W]?[e3\\xE8-\\xEB][_\\W]?x_{0,3}\\b/irP'
local drugs_pain9 = '/(?:\\b|\\s)_{0,3}[i1!|l\\xEC-\\xEF]m[i1!|l\\xEC-\\xEF]tr[e3\\xE8-\\xEB]x_{0,3}\\b/irP'
local drugs_pain10 = '/(?:\\b|\\s)[_\\W]{0,3}(?:\\\\\\/|V)[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}[o0\\xF2-\\xF6][_\\W]{0,3}x[_\\W]{0,3}xx?_{0,3}\\b/irP'
local drugs_pain11 = '/\\bzebutal\\b/irP'
local drugs_pain12 = '/\\besgic plus\\b/irP'
local drugs_pain13 = '/\\bD[_\\W]?[a4\\xE0-\\xE6@][_\\W]?r[_\\W]?v[_\\W]?[o0\\xF2-\\xF6][_\\W]?n\\b/irP'
local drugs_pain14 = '/N[o0\\xF2-\\xF6]rc[o0\\xF2-\\xF6]/irP'
local drugs_pain = string.format('((%s) | (%s) | (%s)) & ((%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) | (%s) || (%s) | (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], drugs_pain1, drugs_pain2, drugs_pain3, drugs_pain4, drugs_pain5, drugs_pain6, drugs_pain7, drugs_pain8, drugs_pain9, drugs_pain10, drugs_pain11, drugs_pain12, drugs_pain13, drugs_pain14)
local drugs_sleep1 = '/(?:\\b|\\s)[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}m[_\\W]{0,3}b[_\\W]{0,3}[i1!|l\\xEC-\\xEF][_\\W]{0,3}[e3\\xE8-\\xEB][_\\W]{0,3}n[_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_sleep2 = '/(?:\\b|\\s)[_\\W]{0,3}S[_\\W]{0,3}[o0\\xF2-\\xF6][_\\W]{0,3}n[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}t[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_sleep3 = '/\\b_{0,3}R[_\\W]?[e3\\xE8-\\xEB][_\\W]?s[_\\W]?t[_\\W]?[o0\\xF2-\\xF6][_\\W]?r[_\\W]?i[_\\W]?l_{0,3}\\b/irP'
local drugs_sleep4 = '/\\b_{0,3}H[_\\W]?[a4\\xE0-\\xE6@][_\\W]?l[_\\W]?c[_\\W]?i[_\\W]?[o0\\xF2-\\xF6][_\\W]?n_{0,3}\\b/irP'
local drugs_sleep = string.format('(%s) | (%s) | (%s) | (%s)', drugs_sleep1, drugs_sleep2, drugs_sleep3, drugs_sleep4)
local drugs_muscle1 = '/(?:\\b|\\s)[_\\W]{0,3}s[_\\W]{0,3}[o0\\xF2-\\xF6][_\\W]{0,3}m[_\\W]{0,3}[a4\\xE0-\\xE6@][_\\W]{0,3}(?:\\b|\\s)/irP'
local drugs_muscle2 = '/\\b_{0,3}cycl[o0\\xF2-\\xF6]b[e3\\xE8-\\xEB]nz[a4\\xE0-\\xE6@]pr[i1!|l\\xEC-\\xEF]n[e3\\xE8-\\xEB]_{0,3}(?:\\b|\\s)/irP'
local drugs_muscle3 = '/\\b_{0,3}f[_\\W]?l[_\\W]?[e3\\xE8-\\xEB][_\\W]?x[_\\W]?[e3\\xE8-\\xEB][_\\W]?r[_\\W]?[i1!|l\\xEC-\\xEF]_{0,3}[_\\W]?l_{0,3}\\b/irP'
local drugs_muscle4 = '/\\b_{0,3}z[_\\W]?a[_\\W]?n[_\\W]?a[_\\W]?f[_\\W]?l[_\\W]?e[_\\W]?x_{0,3}\\b/irP'
local drugs_muscle5 = '/\\bskelaxin\\b/irP'
reconf['DRUGS_MUSCLE'] = string.format('((%s) | (%s) | (%s)) & ((%s) | (%s) | (%s) | (%s) | (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], drugs_muscle1, drugs_muscle2, drugs_muscle3, drugs_muscle4, drugs_muscle5)
reconf['DRUGS_MANYKINDS'] = string.format('((%s) | (%s) | (%s)) & regexp_match_number(3, (%s), (%s), (%s), (%s), (%s), (%s))', reconf['R_UNDISC_RCPT'], reconf['R_BAD_CTE_7BIT'], reconf['R_NO_SPACE_IN_FROM'], reconf['DRUGS_ERECTILE'], reconf['DRUGS_DIET'], drugs_pain, drugs_sleep, reconf['DRUGS_MUSCLE'], reconf['DRUGS_ANXIETY'])

