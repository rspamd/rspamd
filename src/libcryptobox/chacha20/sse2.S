#include "../macro.S"
#include "constants.S"
SECTION_TEXT

GLOBAL_HIDDEN_FN chacha_blocks_sse2
chacha_blocks_sse2_local:
pushq %rbx
pushq %rbp
movq %rsp, %rbp
andq $~63, %rsp
subq $512, %rsp
movq $0x3320646e61707865, %rax
movq $0x6b20657479622d32, %r8
movd %rax, %xmm8
movd %r8, %xmm14
punpcklqdq %xmm14, %xmm8
movdqu 0(%rdi), %xmm9
movdqu 16(%rdi), %xmm10
movdqu 32(%rdi), %xmm11
movq 48(%rdi), %rax
movq $1, %r9
movdqa %xmm8, 0(%rsp)
movdqa %xmm9, 16(%rsp)
movdqa %xmm10, 32(%rsp)
movdqa %xmm11, 48(%rsp)
movq %rax, 64(%rsp)
cmpq $256, %rcx
jb chacha_blocks_sse2_below256
pshufd $0x00, %xmm8, %xmm0
pshufd $0x55, %xmm8, %xmm1
pshufd $0xaa, %xmm8, %xmm2
pshufd $0xff, %xmm8, %xmm3
movdqa %xmm0, 128(%rsp)
movdqa %xmm1, 144(%rsp)
movdqa %xmm2, 160(%rsp)
movdqa %xmm3, 176(%rsp)
pshufd $0x00, %xmm9, %xmm0
pshufd $0x55, %xmm9, %xmm1
pshufd $0xaa, %xmm9, %xmm2
pshufd $0xff, %xmm9, %xmm3
movdqa %xmm0, 192(%rsp)
movdqa %xmm1, 208(%rsp)
movdqa %xmm2, 224(%rsp)
movdqa %xmm3, 240(%rsp)
pshufd $0x00, %xmm10, %xmm0
pshufd $0x55, %xmm10, %xmm1
pshufd $0xaa, %xmm10, %xmm2
pshufd $0xff, %xmm10, %xmm3
movdqa %xmm0, 256(%rsp)
movdqa %xmm1, 272(%rsp)
movdqa %xmm2, 288(%rsp)
movdqa %xmm3, 304(%rsp)
pshufd $0xaa, %xmm11, %xmm0
pshufd $0xff, %xmm11, %xmm1
movdqa %xmm0, 352(%rsp)
movdqa %xmm1, 368(%rsp)
jmp chacha_blocks_sse2_atleast256
.p2align 6,,63
chacha_blocks_sse2_atleast256:
movq 48(%rsp), %rax
leaq 1(%rax), %r8
leaq 2(%rax), %r9
leaq 3(%rax), %r10
leaq 4(%rax), %rbx
movl %eax, 320(%rsp)
movl %r8d, 4+320(%rsp)
movl %r9d, 8+320(%rsp)
movl %r10d, 12+320(%rsp)
shrq $32, %rax
shrq $32, %r8
shrq $32, %r9
shrq $32, %r10
movl %eax, 336(%rsp)
movl %r8d, 4+336(%rsp)
movl %r9d, 8+336(%rsp)
movl %r10d, 12+336(%rsp)
movq %rbx, 48(%rsp)
movq 64(%rsp), %rax
movdqa 128(%rsp), %xmm0
movdqa 144(%rsp), %xmm1
movdqa 160(%rsp), %xmm2
movdqa 176(%rsp), %xmm3
movdqa 192(%rsp), %xmm4
movdqa 208(%rsp), %xmm5
movdqa 224(%rsp), %xmm6
movdqa 240(%rsp), %xmm7
movdqa 256(%rsp), %xmm8
movdqa 272(%rsp), %xmm9
movdqa 288(%rsp), %xmm10
movdqa 304(%rsp), %xmm11
movdqa 320(%rsp), %xmm12
movdqa 336(%rsp), %xmm13
movdqa 352(%rsp), %xmm14
movdqa 368(%rsp), %xmm15
chacha_blocks_sse2_mainloop1:
paddd %xmm4, %xmm0
paddd %xmm5, %xmm1
pxor %xmm0, %xmm12
pxor %xmm1, %xmm13
paddd %xmm6, %xmm2
paddd %xmm7, %xmm3
movdqa %xmm6, 96(%rsp)
pxor %xmm2, %xmm14
pxor %xmm3, %xmm15
pshuflw $0xb1,%xmm12,%xmm12
pshufhw $0xb1,%xmm12,%xmm12
pshuflw $0xb1,%xmm13,%xmm13
pshufhw $0xb1,%xmm13,%xmm13
pshuflw $0xb1,%xmm14,%xmm14
pshufhw $0xb1,%xmm14,%xmm14
pshuflw $0xb1,%xmm15,%xmm15
pshufhw $0xb1,%xmm15,%xmm15
paddd %xmm12, %xmm8
paddd %xmm13, %xmm9
paddd %xmm14, %xmm10
paddd %xmm15, %xmm11
movdqa %xmm12, 112(%rsp)
pxor %xmm8, %xmm4
pxor %xmm9, %xmm5
movdqa 96(%rsp), %xmm6
movdqa %xmm4, %xmm12
pslld $ 12, %xmm4
psrld $20, %xmm12
pxor %xmm12, %xmm4
movdqa %xmm5, %xmm12
pslld $ 12, %xmm5
psrld $20, %xmm12
pxor %xmm12, %xmm5
pxor %xmm10, %xmm6
pxor %xmm11, %xmm7
movdqa %xmm6, %xmm12
pslld $ 12, %xmm6
psrld $20, %xmm12
pxor %xmm12, %xmm6
movdqa %xmm7, %xmm12
pslld $ 12, %xmm7
psrld $20, %xmm12
pxor %xmm12, %xmm7
movdqa 112(%rsp), %xmm12
paddd %xmm4, %xmm0
paddd %xmm5, %xmm1
pxor %xmm0, %xmm12
pxor %xmm1, %xmm13
paddd %xmm6, %xmm2
paddd %xmm7, %xmm3
movdqa %xmm6, 96(%rsp)
pxor %xmm2, %xmm14
pxor %xmm3, %xmm15
movdqa %xmm12, %xmm6
pslld $ 8, %xmm12
psrld $24, %xmm6
pxor %xmm6, %xmm12
movdqa %xmm13, %xmm6
pslld $ 8, %xmm13
psrld $24, %xmm6
pxor %xmm6, %xmm13
paddd %xmm12, %xmm8
paddd %xmm13, %xmm9
movdqa %xmm14, %xmm6
pslld $ 8, %xmm14
psrld $24, %xmm6
pxor %xmm6, %xmm14
movdqa %xmm15, %xmm6
pslld $ 8, %xmm15
psrld $24, %xmm6
pxor %xmm6, %xmm15
paddd %xmm14, %xmm10
paddd %xmm15, %xmm11
movdqa %xmm12, 112(%rsp)
pxor %xmm8, %xmm4
pxor %xmm9, %xmm5
movdqa 96(%rsp), %xmm6
movdqa %xmm4, %xmm12
pslld $ 7, %xmm4
psrld $25, %xmm12
pxor %xmm12, %xmm4
movdqa %xmm5, %xmm12
pslld $ 7, %xmm5
psrld $25, %xmm12
pxor %xmm12, %xmm5
pxor %xmm10, %xmm6
pxor %xmm11, %xmm7
movdqa %xmm6, %xmm12
pslld $ 7, %xmm6
psrld $25, %xmm12
pxor %xmm12, %xmm6
movdqa %xmm7, %xmm12
pslld $ 7, %xmm7
psrld $25, %xmm12
pxor %xmm12, %xmm7
movdqa 112(%rsp), %xmm12
paddd %xmm5, %xmm0
paddd %xmm6, %xmm1
pxor %xmm0, %xmm15
pxor %xmm1, %xmm12
paddd %xmm7, %xmm2
paddd %xmm4, %xmm3
movdqa %xmm7, 96(%rsp)
pxor %xmm2, %xmm13
pxor %xmm3, %xmm14
pshuflw $0xb1,%xmm15,%xmm15
pshufhw $0xb1,%xmm15,%xmm15
pshuflw $0xb1,%xmm12,%xmm12
pshufhw $0xb1,%xmm12,%xmm12
pshuflw $0xb1,%xmm13,%xmm13
pshufhw $0xb1,%xmm13,%xmm13
pshuflw $0xb1,%xmm14,%xmm14
pshufhw $0xb1,%xmm14,%xmm14
paddd %xmm15, %xmm10
paddd %xmm12, %xmm11
paddd %xmm13, %xmm8
paddd %xmm14, %xmm9
movdqa %xmm15, 112(%rsp)
pxor %xmm10, %xmm5
pxor %xmm11, %xmm6
movdqa 96(%rsp), %xmm7
movdqa %xmm5, %xmm15
pslld $ 12, %xmm5
psrld $20, %xmm15
pxor %xmm15, %xmm5
movdqa %xmm6, %xmm15
pslld $ 12, %xmm6
psrld $20, %xmm15
pxor %xmm15, %xmm6
pxor %xmm8, %xmm7
pxor %xmm9, %xmm4
movdqa %xmm7, %xmm15
pslld $ 12, %xmm7
psrld $20, %xmm15
pxor %xmm15, %xmm7
movdqa %xmm4, %xmm15
pslld $ 12, %xmm4
psrld $20, %xmm15
pxor %xmm15, %xmm4
movdqa 112(%rsp), %xmm15
paddd %xmm5, %xmm0
paddd %xmm6, %xmm1
pxor %xmm0, %xmm15
pxor %xmm1, %xmm12
paddd %xmm7, %xmm2
paddd %xmm4, %xmm3
movdqa %xmm7, 96(%rsp)
pxor %xmm2, %xmm13
pxor %xmm3, %xmm14
movdqa %xmm15, %xmm7
pslld $ 8, %xmm15
psrld $24, %xmm7
pxor %xmm7, %xmm15
movdqa %xmm12, %xmm7
pslld $ 8, %xmm12
psrld $24, %xmm7
pxor %xmm7, %xmm12
paddd %xmm15, %xmm10
paddd %xmm12, %xmm11
movdqa %xmm13, %xmm7
pslld $ 8, %xmm13
psrld $24, %xmm7
pxor %xmm7, %xmm13
movdqa %xmm14, %xmm7
pslld $ 8, %xmm14
psrld $24, %xmm7
pxor %xmm7, %xmm14
paddd %xmm13, %xmm8
paddd %xmm14, %xmm9
movdqa %xmm15, 112(%rsp)
pxor %xmm10, %xmm5
pxor %xmm11, %xmm6
movdqa 96(%rsp), %xmm7
movdqa %xmm5, %xmm15
pslld $ 7, %xmm5
psrld $25, %xmm15
pxor %xmm15, %xmm5
movdqa %xmm6, %xmm15
pslld $ 7, %xmm6
psrld $25, %xmm15
pxor %xmm15, %xmm6
pxor %xmm8, %xmm7
pxor %xmm9, %xmm4
movdqa %xmm7, %xmm15
pslld $ 7, %xmm7
psrld $25, %xmm15
pxor %xmm15, %xmm7
movdqa %xmm4, %xmm15
pslld $ 7, %xmm4
psrld $25, %xmm15
pxor %xmm15, %xmm4
movdqa 112(%rsp), %xmm15
subq $2, %rax
jnz chacha_blocks_sse2_mainloop1
paddd 128(%rsp), %xmm0
paddd 144(%rsp), %xmm1
paddd 160(%rsp), %xmm2
paddd 176(%rsp), %xmm3
paddd 192(%rsp), %xmm4
paddd 208(%rsp), %xmm5
paddd 224(%rsp), %xmm6
paddd 240(%rsp), %xmm7
paddd 256(%rsp), %xmm8
paddd 272(%rsp), %xmm9
paddd 288(%rsp), %xmm10
paddd 304(%rsp), %xmm11
paddd 320(%rsp), %xmm12
paddd 336(%rsp), %xmm13
paddd 352(%rsp), %xmm14
paddd 368(%rsp), %xmm15
movdqa %xmm8, 384(%rsp)
movdqa %xmm9, 400(%rsp)
movdqa %xmm10, 416(%rsp)
movdqa %xmm11, 432(%rsp)
movdqa %xmm12, 448(%rsp)
movdqa %xmm13, 464(%rsp)
movdqa %xmm14, 480(%rsp)
movdqa %xmm15, 496(%rsp)
movdqa %xmm0, %xmm8
movdqa %xmm2, %xmm9
movdqa %xmm4, %xmm10
movdqa %xmm6, %xmm11
punpckhdq %xmm1, %xmm0
punpckhdq %xmm3, %xmm2
punpckhdq %xmm5, %xmm4
punpckhdq %xmm7, %xmm6
punpckldq %xmm1, %xmm8
punpckldq %xmm3, %xmm9
punpckldq %xmm5, %xmm10
punpckldq %xmm7, %xmm11
movdqa %xmm0, %xmm1
movdqa %xmm4, %xmm3
movdqa %xmm8, %xmm5
movdqa %xmm10, %xmm7
punpckhqdq %xmm2, %xmm0
punpckhqdq %xmm6, %xmm4
punpckhqdq %xmm9, %xmm8
punpckhqdq %xmm11, %xmm10
punpcklqdq %xmm2, %xmm1
punpcklqdq %xmm6, %xmm3
punpcklqdq %xmm9, %xmm5
punpcklqdq %xmm11, %xmm7
andq %rsi, %rsi
jz chacha_blocks_sse2_noinput1
movdqu 0(%rsi), %xmm2
movdqu 16(%rsi), %xmm6
movdqu 64(%rsi), %xmm9
movdqu 80(%rsi), %xmm11
movdqu 128(%rsi), %xmm12
movdqu 144(%rsi), %xmm13
movdqu 192(%rsi), %xmm14
movdqu 208(%rsi), %xmm15
pxor %xmm2, %xmm5
pxor %xmm6, %xmm7
pxor %xmm9, %xmm8
pxor %xmm11, %xmm10
pxor %xmm12, %xmm1
pxor %xmm13, %xmm3
pxor %xmm14, %xmm0
pxor %xmm15, %xmm4
movdqu %xmm5, 0(%rdx)
movdqu %xmm7, 16(%rdx)
movdqu %xmm8, 64(%rdx)
movdqu %xmm10, 80(%rdx)
movdqu %xmm1, 128(%rdx)
movdqu %xmm3, 144(%rdx)
movdqu %xmm0, 192(%rdx)
movdqu %xmm4, 208(%rdx)
movdqa 384(%rsp), %xmm0
movdqa 400(%rsp), %xmm1
movdqa 416(%rsp), %xmm2
movdqa 432(%rsp), %xmm3
movdqa 448(%rsp), %xmm4
movdqa 464(%rsp), %xmm5
movdqa 480(%rsp), %xmm6
movdqa 496(%rsp), %xmm7
movdqa %xmm0, %xmm8
movdqa %xmm2, %xmm9
movdqa %xmm4, %xmm10
movdqa %xmm6, %xmm11
punpckldq %xmm1, %xmm8
punpckldq %xmm3, %xmm9
punpckhdq %xmm1, %xmm0
punpckhdq %xmm3, %xmm2
punpckldq %xmm5, %xmm10
punpckldq %xmm7, %xmm11
punpckhdq %xmm5, %xmm4
punpckhdq %xmm7, %xmm6
movdqa %xmm8, %xmm1
movdqa %xmm0, %xmm3
movdqa %xmm10, %xmm5
movdqa %xmm4, %xmm7
punpcklqdq %xmm9, %xmm1
punpcklqdq %xmm11, %xmm5
punpckhqdq %xmm9, %xmm8
punpckhqdq %xmm11, %xmm10
punpcklqdq %xmm2, %xmm3
punpcklqdq %xmm6, %xmm7
punpckhqdq %xmm2, %xmm0
punpckhqdq %xmm6, %xmm4
movdqu 32(%rsi), %xmm2
movdqu 48(%rsi), %xmm6
movdqu 96(%rsi), %xmm9
movdqu 112(%rsi), %xmm11
movdqu 160(%rsi), %xmm12
movdqu 176(%rsi), %xmm13
movdqu 224(%rsi), %xmm14
movdqu 240(%rsi), %xmm15
pxor %xmm2, %xmm1
pxor %xmm6, %xmm5
pxor %xmm9, %xmm8
pxor %xmm11, %xmm10
pxor %xmm12, %xmm3
pxor %xmm13, %xmm7
pxor %xmm14, %xmm0
pxor %xmm15, %xmm4
movdqu %xmm1, 32(%rdx)
movdqu %xmm5, 48(%rdx)
movdqu %xmm8, 96(%rdx)
movdqu %xmm10, 112(%rdx)
movdqu %xmm3, 160(%rdx)
movdqu %xmm7, 176(%rdx)
movdqu %xmm0, 224(%rdx)
movdqu %xmm4, 240(%rdx)
addq $256, %rsi
jmp chacha_blocks_sse2_mainloop_cont
chacha_blocks_sse2_noinput1:
movdqu %xmm5, 0(%rdx)
movdqu %xmm7, 16(%rdx)
movdqu %xmm8, 64(%rdx)
movdqu %xmm10, 80(%rdx)
movdqu %xmm1, 128(%rdx)
movdqu %xmm3, 144(%rdx)
movdqu %xmm0, 192(%rdx)
movdqu %xmm4, 208(%rdx)
movdqa 384(%rsp), %xmm0
movdqa 400(%rsp), %xmm1
movdqa 416(%rsp), %xmm2
movdqa 432(%rsp), %xmm3
movdqa 448(%rsp), %xmm4
movdqa 464(%rsp), %xmm5
movdqa 480(%rsp), %xmm6
movdqa 496(%rsp), %xmm7
movdqa %xmm0, %xmm8
movdqa %xmm2, %xmm9
movdqa %xmm4, %xmm10
movdqa %xmm6, %xmm11
punpckldq %xmm1, %xmm8
punpckldq %xmm3, %xmm9
punpckhdq %xmm1, %xmm0
punpckhdq %xmm3, %xmm2
punpckldq %xmm5, %xmm10
punpckldq %xmm7, %xmm11
punpckhdq %xmm5, %xmm4
punpckhdq %xmm7, %xmm6
movdqa %xmm8, %xmm1
movdqa %xmm0, %xmm3
movdqa %xmm10, %xmm5
movdqa %xmm4, %xmm7
punpcklqdq %xmm9, %xmm1
punpcklqdq %xmm11, %xmm5
punpckhqdq %xmm9, %xmm8
punpckhqdq %xmm11, %xmm10
punpcklqdq %xmm2, %xmm3
punpcklqdq %xmm6, %xmm7
punpckhqdq %xmm2, %xmm0
punpckhqdq %xmm6, %xmm4
movdqu %xmm1, 32(%rdx)
movdqu %xmm5, 48(%rdx)
movdqu %xmm8, 96(%rdx)
movdqu %xmm10, 112(%rdx)
movdqu %xmm3, 160(%rdx)
movdqu %xmm7, 176(%rdx)
movdqu %xmm0, 224(%rdx)
movdqu %xmm4, 240(%rdx)
chacha_blocks_sse2_mainloop_cont:
addq $256, %rdx
subq $256, %rcx
cmp $256, %rcx
jae chacha_blocks_sse2_atleast256
movdqa 0(%rsp), %xmm8
movdqa 16(%rsp), %xmm9
movdqa 32(%rsp), %xmm10
movdqa 48(%rsp), %xmm11
movq $1, %r9
chacha_blocks_sse2_below256:
movq %r9, %xmm5
andq %rcx, %rcx
jz chacha_blocks_sse2_done
cmpq $64, %rcx
jae chacha_blocks_sse2_above63
movq %rdx, %r9
andq %rsi, %rsi
jz chacha_blocks_sse2_noinput2
movq %rcx, %r10
movq %rsp, %rdx
addq %r10, %rsi
addq %r10, %rdx
negq %r10
chacha_blocks_sse2_copyinput:
movb (%rsi, %r10), %al
movb %al, (%rdx, %r10)
incq %r10
jnz chacha_blocks_sse2_copyinput
movq %rsp, %rsi
chacha_blocks_sse2_noinput2:
movq %rsp, %rdx
chacha_blocks_sse2_above63:
movdqa %xmm8, %xmm0
movdqa %xmm9, %xmm1
movdqa %xmm10, %xmm2
movdqa %xmm11, %xmm3
movq 64(%rsp), %rax
chacha_blocks_sse2_mainloop2:
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
pshuflw $0xb1,%xmm3,%xmm3
pshufhw $0xb1,%xmm3,%xmm3
paddd %xmm3, %xmm2
pxor %xmm2, %xmm1
movdqa %xmm1,%xmm4
pslld $12, %xmm1
psrld $20, %xmm4
pxor %xmm4, %xmm1
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
movdqa %xmm3,%xmm4
pslld $8, %xmm3
psrld $24, %xmm4
pshufd $0x93,%xmm0,%xmm0
pxor %xmm4, %xmm3
paddd %xmm3, %xmm2
pshufd $0x4e,%xmm3,%xmm3
pxor %xmm2, %xmm1
pshufd $0x39,%xmm2,%xmm2
movdqa %xmm1,%xmm4
pslld $7, %xmm1
psrld $25, %xmm4
pxor %xmm4, %xmm1
subq $2, %rax
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
pshuflw $0xb1,%xmm3,%xmm3
pshufhw $0xb1,%xmm3,%xmm3
paddd %xmm3, %xmm2
pxor %xmm2, %xmm1
movdqa %xmm1,%xmm4
pslld $12, %xmm1
psrld $20, %xmm4
pxor %xmm4, %xmm1
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
movdqa %xmm3,%xmm4
pslld $8, %xmm3
psrld $24, %xmm4
pshufd $0x39,%xmm0,%xmm0
pxor %xmm4, %xmm3
paddd %xmm3, %xmm2
pshufd $0x4e,%xmm3,%xmm3
pxor %xmm2, %xmm1
pshufd $0x93,%xmm2,%xmm2
movdqa %xmm1,%xmm4
pslld $7, %xmm1
psrld $25, %xmm4
pxor %xmm4, %xmm1
jnz chacha_blocks_sse2_mainloop2
paddd %xmm8, %xmm0
paddd %xmm9, %xmm1
paddd %xmm10, %xmm2
paddd %xmm11, %xmm3
andq %rsi, %rsi
jz chacha_blocks_sse2_noinput3
movdqu 0(%rsi), %xmm12
movdqu 16(%rsi), %xmm13
movdqu 32(%rsi), %xmm14
movdqu 48(%rsi), %xmm15
pxor %xmm12, %xmm0
pxor %xmm13, %xmm1
pxor %xmm14, %xmm2
pxor %xmm15, %xmm3
addq $64, %rsi
chacha_blocks_sse2_noinput3:
movdqu %xmm0, 0(%rdx)
movdqu %xmm1, 16(%rdx)
movdqu %xmm2, 32(%rdx)
movdqu %xmm3, 48(%rdx)
paddq %xmm5, %xmm11
cmpq $64, %rcx
jbe chacha_blocks_sse2_mainloop2_finishup
addq $64, %rdx
subq $64, %rcx
jmp chacha_blocks_sse2_below256
chacha_blocks_sse2_mainloop2_finishup:
cmpq $64, %rcx
je chacha_blocks_sse2_done
addq %rcx, %r9
addq %rcx, %rdx
negq %rcx
chacha_blocks_sse2_copyoutput:
movb (%rdx, %rcx), %al
movb %al, (%r9, %rcx)
incq %rcx
jnz chacha_blocks_sse2_copyoutput
chacha_blocks_sse2_done:
movdqu %xmm11, 32(%rdi)
movq %rbp, %rsp
popq %rbp
popq %rbx
ret
FN_END chacha_blocks_sse2

GLOBAL_HIDDEN_FN hchacha_sse2
hchacha_sse2_local:
movq $0x3320646e61707865, %rax
movq $0x6b20657479622d32, %r8
movd %rax, %xmm0
movd %r8, %xmm4
punpcklqdq %xmm4, %xmm0
movdqu 0(%rdi), %xmm1
movdqu 16(%rdi), %xmm2
movdqu 0(%rsi), %xmm3
hchacha_sse2_mainloop:
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
pshuflw $0xb1,%xmm3,%xmm3
pshufhw $0xb1,%xmm3,%xmm3
paddd %xmm3, %xmm2
pxor %xmm2, %xmm1
movdqa %xmm1,%xmm4
pslld $12, %xmm1
psrld $20, %xmm4
pxor %xmm4, %xmm1
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
movdqa %xmm3,%xmm4
pslld $8, %xmm3
psrld $24, %xmm4
pshufd $0x93,%xmm0,%xmm0
pxor %xmm4, %xmm3
paddd %xmm3, %xmm2
pshufd $0x4e,%xmm3,%xmm3
pxor %xmm2, %xmm1
pshufd $0x39,%xmm2,%xmm2
movdqa %xmm1,%xmm4
pslld $7, %xmm1
psrld $25, %xmm4
pxor %xmm4, %xmm1
subq $2, %rcx
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
pshuflw $0xb1,%xmm3,%xmm3
pshufhw $0xb1,%xmm3,%xmm3
paddd %xmm3, %xmm2
pxor %xmm2, %xmm1
movdqa %xmm1,%xmm4
pslld $12, %xmm1
psrld $20, %xmm4
pxor %xmm4, %xmm1
paddd %xmm1, %xmm0
pxor %xmm0, %xmm3
movdqa %xmm3,%xmm4
pslld $8, %xmm3
psrld $24, %xmm4
pshufd $0x39,%xmm0,%xmm0
pxor %xmm4, %xmm3
paddd %xmm3, %xmm2
pshufd $0x4e,%xmm3,%xmm3
pxor %xmm2, %xmm1
pshufd $0x93,%xmm2,%xmm2
movdqa %xmm1,%xmm4
pslld $7, %xmm1
psrld $25, %xmm4
pxor %xmm4, %xmm1
ja hchacha_sse2_mainloop
movdqu %xmm0, 0(%rdx)
movdqu %xmm3, 16(%rdx)
ret
FN_END hchacha_sse2

GLOBAL_HIDDEN_FN_EXT chacha_sse2, 6, 16
pushq %rbp
movq %rsp, %rbp
subq $64, %rsp
andq $~63, %rsp
movdqu 0(%rdi), %xmm0
movdqu 16(%rdi), %xmm1
movdqa %xmm0, 0(%rsp)
movdqa %xmm1, 16(%rsp)
xorq %rdi, %rdi
movq %rdi, 32(%rsp)
movq 0(%rsi), %rsi
movq %rsi, 40(%rsp)
movq %r9, 48(%rsp)
movq %rsp, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %rcx
call chacha_blocks_sse2_local
pxor %xmm0, %xmm0
movdqa %xmm0, 0(%rsp)
movdqa %xmm0, 16(%rsp)
movdqa %xmm0, 32(%rsp)
movq %rbp, %rsp
popq %rbp
ret
FN_END chacha_sse2

GLOBAL_HIDDEN_FN_EXT xchacha_sse2, 6, 16
pushq %rbp
pushq %rbx
movq %rsp, %rbp
subq $64, %rsp
andq $~63, %rsp
movq %rsp, %rbx
xorq %rax, %rax
movq %rax, 32(%rbx)
movq 16(%rsi), %rax
movq %rax, 40(%rbx)
movq %r9, 48(%rbx)
pushq %rdx
pushq %rcx
pushq %r8
movq %rbx, %rdx
movq %r9, %rcx
call hchacha_sse2_local
movq %rbx, %rdi
popq %rcx
popq %rdx
popq %rsi
call chacha_blocks_sse2_local
pxor %xmm0, %xmm0
movdqa %xmm0, 0(%rbx)
movdqa %xmm0, 16(%rbx)
movdqa %xmm0, 32(%rbx)
movq %rbp, %rsp
popq %rbx
popq %rbp
ret
FN_END xchacha_sse2
