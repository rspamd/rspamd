# Rspamd variables for drugs emails

$__DRUGS_DIET1="/(?:\b|\s)[_\W]{0,3}p[_\W]{0,3}h[_\W]{0,3}[e3\xE8-\xEB][_\W]{0,3}n[_\W]{0,3}t[_\W]{0,3}[e3\xE8-\xEB][_\W]{0,3}r[_\W]{0,3}m[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}n[_\W]{0,3}[e3\xE8-\xEB][_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_DIET2="/(?:\b|\s)_{0,3}[i1!|l\xEC-\xEF][_\W]?o[_\W]?n[_\W]?[a4\xE0-\xE6@][_\W]?m[_\W]?[i1!|l\xEC-\xEF][_\W]?n_{0,3}\b/irP";
$__DRUGS_DIET3="/\bbontril\b/irP";
$__DRUGS_DIET4="/\bphendimetrazine\b/irP";
$__DRUGS_DIET5="/\bdiethylpropion\b/irP";
$__DRUGS_DIET6="/(?:\b|\s)[_\W]{0,3}M[_\W]{0,3}[e3\xE8-\xEB][_\W]{0,3}r[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}d[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_DIET7="/\b_{0,3}t[_\W]?[e3\xE8-\xEB][_\W]?n[_\W]?u[_\W]?a[_\W]?t[_\W]?[e3\xE8-\xEB]_{0,3}(?:\b|\s)/irP";
$__DRUGS_DIET8="/\b_{0,3}d[_\W]?[i1!|l\xEC-\xEF][_\W]?d[_\W]?r[_\W][e3\xE8-\xEB[_\W]?xx?_{0,3}\b/irP";
$__DRUGS_DIET9="/\b_{0,3}a[_\W]?d[_\W]?[i1!|l\xEC-\xEF][_\W]?p[_\W]?[e3\xE8-\xEB][_\W]?x_{0,3}\b/irP";
$__DRUGS_DIET10="/\b_{0,3}x?x[_\W]?[e3\xE8-\xEB][_\W]?n[_\W]?[i1!|l\xEC-\xEF][_\W]?c[_\W]?[a4\xE0-\xE6@][_\W]?l_{0,3}\b/irP";
$DRUGS_DIET="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & (${__DRUGS_DIET1} | ${__DRUGS_DIET2} | ${__DRUGS_DIET3} | ${__DRUGS_DIET4} | ${__DRUGS_DIET5} | ${__DRUGS_DIET6} | ${__DRUGS_DIET7} | ${__DRUGS_DIET8} | ${__DRUGS_DIET9} | ${__DRUGS_DIET10})";

$__DRUGS_ERECTILE1="/(?:\b|\s)[_\W]{0,3}(?:\\\/|V)[_\W]{0,3}[ij1!|l\xEC\xED\xEE\xEF][_\W]{0,3}[a40\xE0-\xE6@][_\W]{0,3}[xyz]?[gj][_\W]{0,3}r[_\W]{0,3}[a40\xE0-\xE6@][_\W]{0,3}x?[_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_ERECTILE2="/\bV(?:agira|igara|iaggra|iaegra)\b/irP";
$__DRUGS_ERECTILE3="/(?:\A|[\s\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f])[_\W]{0,3}C[_\W]{0,3}[ij1!|l\xEC\xED\xEE\xEF][_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}l?[l!|1][_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}s[_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_ERECTILE4="/\bC(?:alis|ilias|ilais)\b/irP";
$__DRUGS_ERECTILE5="/\b_{0,3}s[_\W]?[i1!|l\xEC-\xEF][_\W]?l[_\W]?d[_\W]?[e3\xE8-\xEB][_\W]?n[_\W]?[a4\xE0-\xE6@][_\W]?f[_\W]?[i1!|l\xEC-\xEF][_\W]?l c[_\W]?[i1!|l\xEC-\xEF][_\W]?t[_\W]?r[_\W]?[a4\xE0-\xE6@][_\W]?t[_\W]?[e3\xE8-\xEB]_{0,3}(?:\b|\s)/irP";
$__DRUGS_ERECTILE6="/\b_{0,3}L[_\W]?[e3\xE8-\xEB][_\W]?(?:\\\/|V)[_\W]?[i1!|l\xEC-\xEF][_\W]?t[_\W]?r[_\W]?[a4\xE0-\xE6@][_\W]?(?:\b|\s)/irP";
$__DRUGS_ERECTILE8="/\b_{0,3}T[_\W]?[a4\xE0-\xE6@][_\W]?d[_\W]?[a4\xE0-\xE6@][_\W]?l[_\W]?[a4\xE0-\xE6@][_\W]?f[_\W]?[i1!|l\xEC-\xEF][_\W]?l_{0,3}\b/irP";
$__DRUGS_ERECTILE10="/\b_{0,3}V[_\W]?(?:i|\&iuml\;)[_\W]?(?:a|\&agrave|\&aring)\;?[_\W]?g[_\W]?r[_\W]?(?:a|\&agrave|\&aring)\b/irP";
$__DRUGS_ERECTILE11="/(?:\b|\s)_{0,3}[a4\xE0-\xE6@][_\W]{0,3}p[_\W]{0,3}c[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}[l!|1][_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}s_{0,3}\b/irP";
$DRUGS_ERECTILE="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & (${__DRUGS_ERECTILE1} | ${__DRUGS_ERECTILE2} | ${__DRUGS_ERECTILE3} | ${__DRUGS_ERECTILE4} | ${__DRUGS_ERECTILE5} | ${__DRUGS_ERECTILE6} | ${__DRUGS_ERECTILE8} | ${__DRUGS_ERECTILE10} | ${__DRUGS_ERECTILE11})";

$__DRUGS_ANXIETY1="/(?:\b|\s)[_\W]{0,3}x?x[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}n[_\W]{0,3}[ea4\xE1\xE2\xE3@][_\W]{0,3}xx?_{0,3}\b/irP";
$__DRUGS_ANXIETY2="/\bAlprazolam\b/irP";
$__DRUGS_ANXIETY3="/(?:\b|\s)[_\W]{0,3}(?:\\\/|V)[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}[l|][_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}[u\xB5\xF9-\xFC][_\W]{0,3}m\b/irP";
$__DRUGS_ANXIETY4="/\b_{0,3}D[_\W]?[i1!|l\xEC-\xEF][_\W]?[a4\xE0-\xE6@][_\W]?z[_\W]?[ea3\xE9\xEA\xEB][_\W]?p[_\W]?[a4\xE0-\xE6@][_\W]?m_{0,3}\b/irP";
$__DRUGS_ANXIETY5="/(?:\b|\s)[a4\xE0-\xE6@][_\W]?t[_\W]?[i1!|l\xEC-\xEF][_\W]?v[_\W]?[a4\xE0-\xE6@][_\W]?n_{0,3}\b/irP";
$__DRUGS_ANXIETY6="/\b_{0,3}l[_\W]?[o0\xF2-\xF6][_\W]?r[_\W]?[a4\xE0-\xE6@][_\W]?z[_\W]?[e3\xE8-\xEB][_\W]?p[_\W]?[a4\xE0-\xE6@][_\W]?m_{0,3}\b/irP";
$__DRUGS_ANXIETY7="/\b_{0,3}c[_\W]?l[_\W]?[o0\xF2-\xF6][_\W]?n[_\W]?[a4\xE0-\xE6@][_\W]?z[_\W]?e[_\W]?p[_\W]?[a4\xE0-\xE6@][_\W]?m\b/irP";
$__DRUGS_ANXIETY8="/\bklonopin\b/irP";
$__DRUGS_ANXIETY9="/\brivotril\b/irP";
$DRUGS_ANXIETY="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & (${__DRUGS_ANXIETY1} | ${__DRUGS_ANXIETY2} | ${__DRUGS_ANXIETY3} | ${__DRUGS_ANXIETY4} | ${__DRUGS_ANXIETY5} | ${__DRUGS_ANXIETY6} | ${__DRUGS_ANXIETY7} | ${__DRUGS_ANXIETY8} | ${__DRUGS_ANXIETY9})";
$DRUGS_ANXIETY_EREC="${DRUGS_ERECTILE} & ${DRUGS_ANXIETY}";

$__DRUGS_PAIN1="/\b_{0,3}h[_\W]?y[_\W]?d[_\W]?r[_\W]?[o0\xF2-\xF6][_\W]?c[_\W]?[o0\xF2-\xF6][_\W]?d[_\W]?[o0\xF2-\xF6][_\W]?n[_\W]?e_{0,3}\b/irP";
$__DRUGS_PAIN2="/\b_{0,3}c[o0\xF2-\xF6]deine_{0,3}\b/irP";
$__DRUGS_PAIN3="/(?:\b|\s)[_\W]{0,3}[u\xB5\xF9-\xFC][_\W]{0,3}l[_\W]{0,3}t[_\W]{0,3}r[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}m_{0,3}\b/irP";
$__DRUGS_PAIN4="/(?:\b|\s)[_\W]{0,3}(?:\\\/|V)[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}c[_\W]{0,3}[o0\xF2-\xF6][_\W]{0,3}d[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}ns?[_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_PAIN5="/\b_{0,3}t[_\W]?r[_\W]?[a4\xE0-\xE6@][_\W]?m[_\W]?[a4\xE0-\xE6@][_\W]?d[_\W]?[o0\xF2-\xF6][_\W]?[l!|1]_{0,3}\b/irP";
$__DRUGS_PAIN6="/\b_{0,3}u[_\W]?l[_\W]?t[_\W]?r[_\W]?a[_\W]?c[_\W]?e[_\W]?t_{0,3}\b/irP";
$__DRUGS_PAIN7="/\b_{0,3}f[_\W]?[i1!|l\xEC-\xEF][_\W]?[o0\xF2-\xF6][_\W]?r[_\W]?[i1!|l\xEC-\xEF][_\W]?c[_\W]?[e3\xE8-\xEB][_\W]?[t7]_{0,3}\b/irP";
$__DRUGS_PAIN8="/\b_{0,3}c[_\W]?[e3\xE8-\xEB][_\W]?l[_\W]?[e3\xE8-\xEB][_\W]?b[_\W]?r[_\W]?[e3\xE8-\xEB][_\W]?x_{0,3}\b/irP";
$__DRUGS_PAIN9="/(?:\b|\s)_{0,3}[i1!|l\xEC-\xEF]m[i1!|l\xEC-\xEF]tr[e3\xE8-\xEB]x_{0,3}\b/irP";
$__DRUGS_PAIN10="/(?:\b|\s)[_\W]{0,3}(?:\\\/|V)[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}[o0\xF2-\xF6][_\W]{0,3}x[_\W]{0,3}xx?_{0,3}\b/irP";
$__DRUGS_PAIN11="/\bzebutal\b/irP";
$__DRUGS_PAIN12="/\besgic plus\b/irP";
$__DRUGS_PAIN13="/\bD[_\W]?[a4\xE0-\xE6@][_\W]?r[_\W]?v[_\W]?[o0\xF2-\xF6][_\W]?n\b/irP";
$__DRUGS_PAIN14="/N[o0\xF2-\xF6]rc[o0\xF2-\xF6]/irP";
$__DRUGS_PAIN="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & (${__DRUGS_PAIN1} | ${__DRUGS_PAIN2} | ${__DRUGS_PAIN3} | ${__DRUGS_PAIN4} | ${__DRUGS_PAIN5} | ${__DRUGS_PAIN6} | ${__DRUGS_PAIN7} | ${__DRUGS_PAIN8} | ${__DRUGS_PAIN9} | ${__DRUGS_PAIN10} | ${__DRUGS_PAIN11} | ${__DRUGS_PAIN12} || ${__DRUGS_PAIN13} | ${__DRUGS_PAIN14})";

$__DRUGS_SLEEP1="/(?:\b|\s)[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}m[_\W]{0,3}b[_\W]{0,3}[i1!|l\xEC-\xEF][_\W]{0,3}[e3\xE8-\xEB][_\W]{0,3}n[_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_SLEEP2="/(?:\b|\s)[_\W]{0,3}S[_\W]{0,3}[o0\xF2-\xF6][_\W]{0,3}n[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}t[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_SLEEP3="/\b_{0,3}R[_\W]?[e3\xE8-\xEB][_\W]?s[_\W]?t[_\W]?[o0\xF2-\xF6][_\W]?r[_\W]?i[_\W]?l_{0,3}\b/irP";
$__DRUGS_SLEEP4="/\b_{0,3}H[_\W]?[a4\xE0-\xE6@][_\W]?l[_\W]?c[_\W]?i[_\W]?[o0\xF2-\xF6][_\W]?n_{0,3}\b/irP";
$__DRUGS_SLEEP="${__DRUGS_SLEEP1} | ${__DRUGS_SLEEP2} | ${__DRUGS_SLEEP3} | ${__DRUGS_SLEEP4}";

$__DRUGS_MUSCLE1="/(?:\b|\s)[_\W]{0,3}s[_\W]{0,3}[o0\xF2-\xF6][_\W]{0,3}m[_\W]{0,3}[a4\xE0-\xE6@][_\W]{0,3}(?:\b|\s)/irP";
$__DRUGS_MUSCLE2="/\b_{0,3}cycl[o0\xF2-\xF6]b[e3\xE8-\xEB]nz[a4\xE0-\xE6@]pr[i1!|l\xEC-\xEF]n[e3\xE8-\xEB]_{0,3}(?:\b|\s)/irP";
$__DRUGS_MUSCLE3="/\b_{0,3}f[_\W]?l[_\W]?[e3\xE8-\xEB][_\W]?x[_\W]?[e3\xE8-\xEB][_\W]?r[_\W]?[i1!|l\xEC-\xEF]_{0,3}[_\W]?l_{0,3}\b/irP";
$__DRUGS_MUSCLE4="/\b_{0,3}z[_\W]?a[_\W]?n[_\W]?a[_\W]?f[_\W]?l[_\W]?e[_\W]?x_{0,3}\b/irP";
$__DRUGS_MUSCLE5="/\bskelaxin\b/irP";
$DRUGS_MUSCLE="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & (${__DRUGS_MUSCLE1} | ${__DRUGS_MUSCLE2} | ${__DRUGS_MUSCLE3} | ${__DRUGS_MUSCLE4} | ${__DRUGS_MUSCLE5})";

$DRUGS_MANYKINDS="(${R_UNDISC_RCPT} | ${R_BAD_CTE_7BIT} | ${R_NO_SPACE_IN_FROM}) & regexp_match_number(3, ${DRUGS_ERECTILE}, ${DRUGS_DIET}, ${__DRUGS_PAIN}, ${__DRUGS_SLEEP}, ${DRUGS_MUSCLE}, ${DRUGS_ANXIETY})";

