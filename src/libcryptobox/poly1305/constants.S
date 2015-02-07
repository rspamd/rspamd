SECTION_RODATA

.p2align 4
poly1305_constants_x86:
/*   0 */ poly1305_x86_scale: .long 0x0,0x37f40000
/*   8 */ poly1305_x86_two32: .long 0x0,0x41f00000
/*  16 */ poly1305_x86_two64: .long 0x0,0x43f00000
/*  24 */ poly1305_x86_two96: .long 0x0,0x45f00000
/*  32 */ poly1305_x86_alpha32: .long 0x0,0x45e80000
/*  40 */ poly1305_x86_alpha64: .long 0x0,0x47e80000
/*  48 */ poly1305_x86_alpha96: .long 0x0,0x49e80000
/*  56 */ poly1305_x86_alpha130: .long 0x0,0x4c080000
/*  64 */ poly1305_x86_doffset0: .long 0x0,0x43300000
/*  72 */ poly1305_x86_doffset1: .long 0x0,0x45300000
/*  80 */ poly1305_x86_doffset2: .long 0x0,0x47300000
/*  88 */ poly1305_x86_doffset3: .long 0x0,0x49300000
/*  96 */ poly1305_x86_doffset3minustwo128: .long 0x0,0x492ffffe
/* 104 */ poly1305_x86_hoffset0: .long 0xfffffffb,0x43300001
/* 112 */ poly1305_x86_hoffset1: .long 0xfffffffe,0x45300001
/* 120 */ poly1305_x86_hoffset2: .long 0xfffffffe,0x47300001
/* 124 */ poly1305_x86_hoffset3: .long 0xfffffffe,0x49300003
