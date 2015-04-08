#include "../macro.S"
#include "constants.S"
SECTION_TEXT

GLOBAL_HIDDEN_FN chacha_blocks_avx
chacha_blocks_avx_local:
pushq %rbx
pushq %rbp
movq %rsp, %rbp
andq $~63, %rsp
subq $512, %rsp
LOAD_VAR_PIC chacha_constants, %rax
vmovdqa 0(%rax), %xmm8
vmovdqa 16(%rax), %xmm6
vmovdqa 32(%rax), %xmm7
vmovdqu 0(%rdi), %xmm9
vmovdqu 16(%rdi), %xmm10
vmovdqu 32(%rdi), %xmm11
movq 48(%rdi), %rax
movq $1, %r9
vmovdqa %xmm8, 0(%rsp)
vmovdqa %xmm9, 16(%rsp)
vmovdqa %xmm10, 32(%rsp)
vmovdqa %xmm11, 48(%rsp)
vmovdqa %xmm6, 80(%rsp)
vmovdqa %xmm7, 96(%rsp)
movq %rax, 64(%rsp)
cmpq $256, %rcx
jb chacha_blocks_avx_below256
vpshufd $0x00, %xmm8, %xmm0
vpshufd $0x55, %xmm8, %xmm1
vpshufd $0xaa, %xmm8, %xmm2
vpshufd $0xff, %xmm8, %xmm3
vmovdqa %xmm0, 128(%rsp)
vmovdqa %xmm1, 144(%rsp)
vmovdqa %xmm2, 160(%rsp)
vmovdqa %xmm3, 176(%rsp)
vpshufd $0x00, %xmm9, %xmm0
vpshufd $0x55, %xmm9, %xmm1
vpshufd $0xaa, %xmm9, %xmm2
vpshufd $0xff, %xmm9, %xmm3
vmovdqa %xmm0, 192(%rsp)
vmovdqa %xmm1, 208(%rsp)
vmovdqa %xmm2, 224(%rsp)
vmovdqa %xmm3, 240(%rsp)
vpshufd $0x00, %xmm10, %xmm0
vpshufd $0x55, %xmm10, %xmm1
vpshufd $0xaa, %xmm10, %xmm2
vpshufd $0xff, %xmm10, %xmm3
vmovdqa %xmm0, 256(%rsp)
vmovdqa %xmm1, 272(%rsp)
vmovdqa %xmm2, 288(%rsp)
vmovdqa %xmm3, 304(%rsp)
vpshufd $0xaa, %xmm11, %xmm0
vpshufd $0xff, %xmm11, %xmm1
vmovdqa %xmm0, 352(%rsp)
vmovdqa %xmm1, 368(%rsp)
jmp chacha_blocks_avx_atleast256
.p2align 6,,63
nop
nop
nop
nop
nop
chacha_blocks_avx_atleast256:
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
vmovdqa 128(%rsp), %xmm0
vmovdqa 144(%rsp), %xmm1
vmovdqa 160(%rsp), %xmm2
vmovdqa 176(%rsp), %xmm3
vmovdqa 192(%rsp), %xmm4
vmovdqa 208(%rsp), %xmm5
vmovdqa 224(%rsp), %xmm6
vmovdqa 240(%rsp), %xmm7
vmovdqa 256(%rsp), %xmm8
vmovdqa 272(%rsp), %xmm9
vmovdqa 288(%rsp), %xmm10
vmovdqa 304(%rsp), %xmm11
vmovdqa 320(%rsp), %xmm12
vmovdqa 336(%rsp), %xmm13
vmovdqa 352(%rsp), %xmm14
vmovdqa 368(%rsp), %xmm15
chacha_blocks_avx_mainloop1:
vpaddd %xmm0, %xmm4, %xmm0
vpaddd %xmm1, %xmm5, %xmm1
vpxor %xmm12, %xmm0, %xmm12
vpxor %xmm13, %xmm1, %xmm13
vpaddd %xmm2, %xmm6, %xmm2
vpaddd %xmm3, %xmm7, %xmm3
vpxor %xmm14, %xmm2, %xmm14
vpxor %xmm15, %xmm3, %xmm15
vpshufb 80(%rsp), %xmm12, %xmm12
vpshufb 80(%rsp), %xmm13, %xmm13
vpaddd %xmm8, %xmm12, %xmm8
vpaddd %xmm9, %xmm13, %xmm9
vpshufb 80(%rsp), %xmm14, %xmm14
vpshufb 80(%rsp), %xmm15, %xmm15
vpaddd %xmm10, %xmm14, %xmm10
vpaddd %xmm11, %xmm15, %xmm11
vmovdqa %xmm12, 112(%rsp)
vpxor %xmm4, %xmm8, %xmm4
vpxor %xmm5, %xmm9, %xmm5
vpslld $ 12, %xmm4, %xmm12
vpsrld $20, %xmm4, %xmm4
vpxor %xmm4, %xmm12, %xmm4
vpslld $ 12, %xmm5, %xmm12
vpsrld $20, %xmm5, %xmm5
vpxor %xmm5, %xmm12, %xmm5
vpxor %xmm6, %xmm10, %xmm6
vpxor %xmm7, %xmm11, %xmm7
vpslld $ 12, %xmm6, %xmm12
vpsrld $20, %xmm6, %xmm6
vpxor %xmm6, %xmm12, %xmm6
vpslld $ 12, %xmm7, %xmm12
vpsrld $20, %xmm7, %xmm7
vpxor %xmm7, %xmm12, %xmm7
vpaddd %xmm0, %xmm4, %xmm0
vpaddd %xmm1, %xmm5, %xmm1
vpxor 112(%rsp), %xmm0, %xmm12
vpxor %xmm13, %xmm1, %xmm13
vpaddd %xmm2, %xmm6, %xmm2
vpaddd %xmm3, %xmm7, %xmm3
vpxor %xmm14, %xmm2, %xmm14
vpxor %xmm15, %xmm3, %xmm15
vpshufb 96(%rsp), %xmm12, %xmm12
vpshufb 96(%rsp), %xmm13, %xmm13
vpaddd %xmm8, %xmm12, %xmm8
vpaddd %xmm9, %xmm13, %xmm9
vpshufb 96(%rsp), %xmm14, %xmm14
vpshufb 96(%rsp), %xmm15, %xmm15
vpaddd %xmm10, %xmm14, %xmm10
vpaddd %xmm11, %xmm15, %xmm11
vmovdqa %xmm12, 112(%rsp)
vpxor %xmm4, %xmm8, %xmm4
vpxor %xmm5, %xmm9, %xmm5
vpslld $ 7, %xmm4, %xmm12
vpsrld $25, %xmm4, %xmm4
vpxor %xmm4, %xmm12, %xmm4
vpslld $ 7, %xmm5, %xmm12
vpsrld $25, %xmm5, %xmm5
vpxor %xmm5, %xmm12, %xmm5
vpxor %xmm6, %xmm10, %xmm6
vpxor %xmm7, %xmm11, %xmm7
vpslld $ 7, %xmm6, %xmm12
vpsrld $25, %xmm6, %xmm6
vpxor %xmm6, %xmm12, %xmm6
vpslld $ 7, %xmm7, %xmm12
vpsrld $25, %xmm7, %xmm7
vpxor %xmm7, %xmm12, %xmm7
vpaddd %xmm0, %xmm5, %xmm0
vpaddd %xmm1, %xmm6, %xmm1
vpxor %xmm15, %xmm0, %xmm15
vpxor 112(%rsp), %xmm1, %xmm12
vpaddd %xmm2, %xmm7, %xmm2
vpaddd %xmm3, %xmm4, %xmm3
vpxor %xmm13, %xmm2, %xmm13
vpxor %xmm14, %xmm3, %xmm14
vpshufb 80(%rsp), %xmm15, %xmm15
vpshufb 80(%rsp), %xmm12, %xmm12
vpaddd %xmm10, %xmm15, %xmm10
vpaddd %xmm11, %xmm12, %xmm11
vpshufb 80(%rsp), %xmm13, %xmm13
vpshufb 80(%rsp), %xmm14, %xmm14
vpaddd %xmm8, %xmm13, %xmm8
vpaddd %xmm9, %xmm14, %xmm9
vmovdqa %xmm15, 112(%rsp)
vpxor %xmm5, %xmm10, %xmm5
vpxor %xmm6, %xmm11, %xmm6
vpslld $ 12, %xmm5, %xmm15
vpsrld $20, %xmm5, %xmm5
vpxor %xmm5, %xmm15, %xmm5
vpslld $ 12, %xmm6, %xmm15
vpsrld $20, %xmm6, %xmm6
vpxor %xmm6, %xmm15, %xmm6
vpxor %xmm7, %xmm8, %xmm7
vpxor %xmm4, %xmm9, %xmm4
vpslld $ 12, %xmm7, %xmm15
vpsrld $20, %xmm7, %xmm7
vpxor %xmm7, %xmm15, %xmm7
vpslld $ 12, %xmm4, %xmm15
vpsrld $20, %xmm4, %xmm4
vpxor %xmm4, %xmm15, %xmm4
vpaddd %xmm0, %xmm5, %xmm0
vpaddd %xmm1, %xmm6, %xmm1
vpxor 112(%rsp), %xmm0, %xmm15
vpxor %xmm12, %xmm1, %xmm12
vpaddd %xmm2, %xmm7, %xmm2
vpaddd %xmm3, %xmm4, %xmm3
vpxor %xmm13, %xmm2, %xmm13
vpxor %xmm14, %xmm3, %xmm14
vpshufb 96(%rsp), %xmm15, %xmm15
vpshufb 96(%rsp), %xmm12, %xmm12
vpaddd %xmm10, %xmm15, %xmm10
vpaddd %xmm11, %xmm12, %xmm11
vpshufb 96(%rsp), %xmm13, %xmm13
vpshufb 96(%rsp), %xmm14, %xmm14
vpaddd %xmm8, %xmm13, %xmm8
vpaddd %xmm9, %xmm14, %xmm9
vmovdqa %xmm15, 112(%rsp)
vpxor %xmm5, %xmm10, %xmm5
vpxor %xmm6, %xmm11, %xmm6
vpslld $ 7, %xmm5, %xmm15
vpsrld $25, %xmm5, %xmm5
vpxor %xmm5, %xmm15, %xmm5
vpslld $ 7, %xmm6, %xmm15
vpsrld $25, %xmm6, %xmm6
vpxor %xmm6, %xmm15, %xmm6
vpxor %xmm7, %xmm8, %xmm7
vpxor %xmm4, %xmm9, %xmm4
vpslld $ 7, %xmm7, %xmm15
vpsrld $25, %xmm7, %xmm7
vpxor %xmm7, %xmm15, %xmm7
vpslld $ 7, %xmm4, %xmm15
vpsrld $25, %xmm4, %xmm4
vpxor %xmm4, %xmm15, %xmm4
vmovdqa 112(%rsp), %xmm15
subq $2, %rax
jnz chacha_blocks_avx_mainloop1
vpaddd 128(%rsp), %xmm0, %xmm0
vpaddd 144(%rsp), %xmm1, %xmm1
vpaddd 160(%rsp), %xmm2, %xmm2
vpaddd 176(%rsp), %xmm3, %xmm3
vpaddd 192(%rsp), %xmm4, %xmm4
vpaddd 208(%rsp), %xmm5, %xmm5
vpaddd 224(%rsp), %xmm6, %xmm6
vpaddd 240(%rsp), %xmm7, %xmm7
vpaddd 256(%rsp), %xmm8, %xmm8
vpaddd 272(%rsp), %xmm9, %xmm9
vpaddd 288(%rsp), %xmm10, %xmm10
vpaddd 304(%rsp), %xmm11, %xmm11
vpaddd 320(%rsp), %xmm12, %xmm12
vpaddd 336(%rsp), %xmm13, %xmm13
vpaddd 352(%rsp), %xmm14, %xmm14
vpaddd 368(%rsp), %xmm15, %xmm15
vmovdqa %xmm8, 384(%rsp)
vmovdqa %xmm9, 400(%rsp)
vmovdqa %xmm10, 416(%rsp)
vmovdqa %xmm11, 432(%rsp)
vmovdqa %xmm12, 448(%rsp)
vmovdqa %xmm13, 464(%rsp)
vmovdqa %xmm14, 480(%rsp)
vmovdqa %xmm15, 496(%rsp)
vpunpckldq %xmm1, %xmm0, %xmm8
vpunpckldq %xmm3, %xmm2, %xmm9
vpunpckhdq %xmm1, %xmm0, %xmm12
vpunpckhdq %xmm3, %xmm2, %xmm13
vpunpckldq %xmm5, %xmm4, %xmm10
vpunpckldq %xmm7, %xmm6, %xmm11
vpunpckhdq %xmm5, %xmm4, %xmm14
vpunpckhdq %xmm7, %xmm6, %xmm15
vpunpcklqdq %xmm9, %xmm8, %xmm0
vpunpcklqdq %xmm11, %xmm10, %xmm1
vpunpckhqdq %xmm9, %xmm8, %xmm2
vpunpckhqdq %xmm11, %xmm10, %xmm3
vpunpcklqdq %xmm13, %xmm12, %xmm4
vpunpcklqdq %xmm15, %xmm14, %xmm5
vpunpckhqdq %xmm13, %xmm12, %xmm6
vpunpckhqdq %xmm15, %xmm14, %xmm7
andq %rsi, %rsi
jz chacha_blocks_avx_noinput1
vpxor 0(%rsi), %xmm0, %xmm0
vpxor 16(%rsi), %xmm1, %xmm1
vpxor 64(%rsi), %xmm2, %xmm2
vpxor 80(%rsi), %xmm3, %xmm3
vpxor 128(%rsi), %xmm4, %xmm4
vpxor 144(%rsi), %xmm5, %xmm5
vpxor 192(%rsi), %xmm6, %xmm6
vpxor 208(%rsi), %xmm7, %xmm7
vmovdqu %xmm0, 0(%rdx)
vmovdqu %xmm1, 16(%rdx)
vmovdqu %xmm2, 64(%rdx)
vmovdqu %xmm3, 80(%rdx)
vmovdqu %xmm4, 128(%rdx)
vmovdqu %xmm5, 144(%rdx)
vmovdqu %xmm6, 192(%rdx)
vmovdqu %xmm7, 208(%rdx)
vmovdqa 384(%rsp), %xmm0
vmovdqa 400(%rsp), %xmm1
vmovdqa 416(%rsp), %xmm2
vmovdqa 432(%rsp), %xmm3
vmovdqa 448(%rsp), %xmm4
vmovdqa 464(%rsp), %xmm5
vmovdqa 480(%rsp), %xmm6
vmovdqa 496(%rsp), %xmm7
vpunpckldq %xmm1, %xmm0, %xmm8
vpunpckldq %xmm3, %xmm2, %xmm9
vpunpckhdq %xmm1, %xmm0, %xmm12
vpunpckhdq %xmm3, %xmm2, %xmm13
vpunpckldq %xmm5, %xmm4, %xmm10
vpunpckldq %xmm7, %xmm6, %xmm11
vpunpckhdq %xmm5, %xmm4, %xmm14
vpunpckhdq %xmm7, %xmm6, %xmm15
vpunpcklqdq %xmm9, %xmm8, %xmm0
vpunpcklqdq %xmm11, %xmm10, %xmm1
vpunpckhqdq %xmm9, %xmm8, %xmm2
vpunpckhqdq %xmm11, %xmm10, %xmm3
vpunpcklqdq %xmm13, %xmm12, %xmm4
vpunpcklqdq %xmm15, %xmm14, %xmm5
vpunpckhqdq %xmm13, %xmm12, %xmm6
vpunpckhqdq %xmm15, %xmm14, %xmm7
vpxor 32(%rsi), %xmm0, %xmm0
vpxor 48(%rsi), %xmm1, %xmm1
vpxor 96(%rsi), %xmm2, %xmm2
vpxor 112(%rsi), %xmm3, %xmm3
vpxor 160(%rsi), %xmm4, %xmm4
vpxor 176(%rsi), %xmm5, %xmm5
vpxor 224(%rsi), %xmm6, %xmm6
vpxor 240(%rsi), %xmm7, %xmm7
vmovdqu %xmm0, 32(%rdx)
vmovdqu %xmm1, 48(%rdx)
vmovdqu %xmm2, 96(%rdx)
vmovdqu %xmm3, 112(%rdx)
vmovdqu %xmm4, 160(%rdx)
vmovdqu %xmm5, 176(%rdx)
vmovdqu %xmm6, 224(%rdx)
vmovdqu %xmm7, 240(%rdx)
addq $256, %rsi
jmp chacha_blocks_avx_mainloop_cont
chacha_blocks_avx_noinput1:
vmovdqu %xmm0, 0(%rdx)
vmovdqu %xmm1, 16(%rdx)
vmovdqu %xmm2, 64(%rdx)
vmovdqu %xmm3, 80(%rdx)
vmovdqu %xmm4, 128(%rdx)
vmovdqu %xmm5, 144(%rdx)
vmovdqu %xmm6, 192(%rdx)
vmovdqu %xmm7, 208(%rdx)
vmovdqa 384(%rsp), %xmm0
vmovdqa 400(%rsp), %xmm1
vmovdqa 416(%rsp), %xmm2
vmovdqa 432(%rsp), %xmm3
vmovdqa 448(%rsp), %xmm4
vmovdqa 464(%rsp), %xmm5
vmovdqa 480(%rsp), %xmm6
vmovdqa 496(%rsp), %xmm7
vpunpckldq %xmm1, %xmm0, %xmm8
vpunpckldq %xmm3, %xmm2, %xmm9
vpunpckhdq %xmm1, %xmm0, %xmm12
vpunpckhdq %xmm3, %xmm2, %xmm13
vpunpckldq %xmm5, %xmm4, %xmm10
vpunpckldq %xmm7, %xmm6, %xmm11
vpunpckhdq %xmm5, %xmm4, %xmm14
vpunpckhdq %xmm7, %xmm6, %xmm15
vpunpcklqdq %xmm9, %xmm8, %xmm0
vpunpcklqdq %xmm11, %xmm10, %xmm1
vpunpckhqdq %xmm9, %xmm8, %xmm2
vpunpckhqdq %xmm11, %xmm10, %xmm3
vpunpcklqdq %xmm13, %xmm12, %xmm4
vpunpcklqdq %xmm15, %xmm14, %xmm5
vpunpckhqdq %xmm13, %xmm12, %xmm6
vpunpckhqdq %xmm15, %xmm14, %xmm7
vmovdqu %xmm0, 32(%rdx)
vmovdqu %xmm1, 48(%rdx)
vmovdqu %xmm2, 96(%rdx)
vmovdqu %xmm3, 112(%rdx)
vmovdqu %xmm4, 160(%rdx)
vmovdqu %xmm5, 176(%rdx)
vmovdqu %xmm6, 224(%rdx)
vmovdqu %xmm7, 240(%rdx)
chacha_blocks_avx_mainloop_cont:
addq $256, %rdx
subq $256, %rcx
cmp $256, %rcx
jae chacha_blocks_avx_atleast256
vmovdqa 80(%rsp), %xmm6
vmovdqa 96(%rsp), %xmm7
vmovdqa 0(%rsp), %xmm8
vmovdqa 16(%rsp), %xmm9
vmovdqa 32(%rsp), %xmm10
vmovdqa 48(%rsp), %xmm11
movq $1, %r9
chacha_blocks_avx_below256:
vmovq %r9, %xmm5
andq %rcx, %rcx
jz chacha_blocks_avx_done
cmpq $64, %rcx
jae chacha_blocks_avx_above63
movq %rdx, %r9
andq %rsi, %rsi
jz chacha_blocks_avx_noinput2
movq %rcx, %r10
movq %rsp, %rdx
addq %r10, %rsi
addq %r10, %rdx
negq %r10
chacha_blocks_avx_copyinput:
movb (%rsi, %r10), %al
movb %al, (%rdx, %r10)
incq %r10
jnz chacha_blocks_avx_copyinput
movq %rsp, %rsi
chacha_blocks_avx_noinput2:
movq %rsp, %rdx
chacha_blocks_avx_above63:
vmovdqa %xmm8, %xmm0
vmovdqa %xmm9, %xmm1
vmovdqa %xmm10, %xmm2
vmovdqa %xmm11, %xmm3
movq 64(%rsp), %rax
chacha_blocks_avx_mainloop2:
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm7, %xmm3, %xmm3
vpshufd $0x93, %xmm0, %xmm0
vpaddd %xmm2, %xmm3, %xmm2
vpshufd $0x4e, %xmm3, %xmm3
vpxor %xmm1, %xmm2, %xmm1
vpshufd $0x39, %xmm2, %xmm2
vpslld $7, %xmm1, %xmm4
vpsrld $25, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm7, %xmm3, %xmm3
vpshufd $0x39, %xmm0, %xmm0
vpaddd %xmm2, %xmm3, %xmm2
vpshufd $0x4e, %xmm3, %xmm3
vpxor %xmm1, %xmm2, %xmm1
vpshufd $0x93, %xmm2, %xmm2
vpslld $7, %xmm1, %xmm4
vpsrld $25, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
subq $2, %rax
jnz chacha_blocks_avx_mainloop2
vpaddd %xmm0, %xmm8, %xmm0
vpaddd %xmm1, %xmm9, %xmm1
vpaddd %xmm2, %xmm10, %xmm2
vpaddd %xmm3, %xmm11, %xmm3
andq %rsi, %rsi
jz chacha_blocks_avx_noinput3
vpxor 0(%rsi), %xmm0, %xmm0
vpxor 16(%rsi), %xmm1, %xmm1
vpxor 32(%rsi), %xmm2, %xmm2
vpxor 48(%rsi), %xmm3, %xmm3
addq $64, %rsi
chacha_blocks_avx_noinput3:
vmovdqu %xmm0, 0(%rdx)
vmovdqu %xmm1, 16(%rdx)
vmovdqu %xmm2, 32(%rdx)
vmovdqu %xmm3, 48(%rdx)
vpaddq %xmm11, %xmm5, %xmm11
cmpq $64, %rcx
jbe chacha_blocks_avx_mainloop2_finishup
addq $64, %rdx
subq $64, %rcx
jmp chacha_blocks_avx_below256
chacha_blocks_avx_mainloop2_finishup:
cmpq $64, %rcx
je chacha_blocks_avx_done
addq %rcx, %r9
addq %rcx, %rdx
negq %rcx
chacha_blocks_avx_copyoutput:
movb (%rdx, %rcx), %al
movb %al, (%r9, %rcx)
incq %rcx
jnz chacha_blocks_avx_copyoutput
chacha_blocks_avx_done:
vmovdqu %xmm11, 32(%rdi)
movq %rbp, %rsp
popq %rbp
popq %rbx
ret
FN_END chacha_blocks_avx

GLOBAL_HIDDEN_FN hchacha_avx
hchacha_avx_local:
LOAD_VAR_PIC chacha_constants, %rax
vmovdqa 0(%rax), %xmm0
vmovdqa 16(%rax), %xmm6
vmovdqa 32(%rax), %xmm5
vmovdqu 0(%rdi), %xmm1
vmovdqu 16(%rdi), %xmm2
vmovdqu 0(%rsi), %xmm3
hhacha_mainloop_avx:
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm5, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $7, %xmm1, %xmm4
vpsrld $25, %xmm1, %xmm1
vpshufd $0x93, %xmm0, %xmm0
vpxor %xmm1, %xmm4, %xmm1
vpshufd $0x4e, %xmm3, %xmm3
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm6, %xmm3, %xmm3
vpshufd $0x39, %xmm2, %xmm2
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpslld $12, %xmm1, %xmm4
vpsrld $20, %xmm1, %xmm1
vpxor %xmm1, %xmm4, %xmm1
vpaddd %xmm0, %xmm1, %xmm0
vpxor %xmm3, %xmm0, %xmm3
vpshufb %xmm5, %xmm3, %xmm3
vpaddd %xmm2, %xmm3, %xmm2
vpxor %xmm1, %xmm2, %xmm1
vpshufd $0x39, %xmm0, %xmm0
vpslld $7, %xmm1, %xmm4
vpshufd $0x4e, %xmm3, %xmm3
vpsrld $25, %xmm1, %xmm1
vpshufd $0x93, %xmm2, %xmm2
vpxor %xmm1, %xmm4, %xmm1
subl $2, %ecx
jne hhacha_mainloop_avx
vmovdqu %xmm0, (%rdx)
vmovdqu %xmm3, 16(%rdx)
ret
FN_END hchacha_avx

GLOBAL_HIDDEN_FN_EXT chacha_avx, 6, 16
pushq %rbp
movq %rsp, %rbp
subq $64, %rsp
andq $~63, %rsp
vmovdqu 0(%rdi), %xmm0
vmovdqu 16(%rdi), %xmm1
vmovdqa %xmm0, 0(%rsp)
vmovdqa %xmm1, 16(%rsp)
xorq %rdi, %rdi
movq %rdi, 32(%rsp)
movq 0(%rsi), %rsi
movq %rsi, 40(%rsp)
movq %r9, 48(%rsp)
movq %rsp, %rdi
movq %rdx, %rsi
movq %rcx, %rdx
movq %r8, %rcx
call chacha_blocks_avx_local
vpxor %xmm0, %xmm0, %xmm0
vmovdqa %xmm0, 0(%rsp)
vmovdqa %xmm0, 16(%rsp)
vmovdqa %xmm0, 32(%rsp)
movq %rbp, %rsp
popq %rbp
ret
FN_END chacha_avx

GLOBAL_HIDDEN_FN_EXT xchacha_avx, 6, 16
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
call hchacha_avx_local
movq %rbx, %rdi
popq %rcx
popq %rdx
popq %rsi
call chacha_blocks_avx_local
vpxor %xmm0, %xmm0, %xmm0
vmovdqa %xmm0, 0(%rbx)
vmovdqa %xmm0, 16(%rbx)
vmovdqa %xmm0, 32(%rbx)
movq %rbp, %rsp
popq %rbx
popq %rbp
ret
FN_END xchacha_avx
