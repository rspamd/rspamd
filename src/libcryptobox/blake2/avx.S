#include "../macro.S"
#include "constants.S"

SECTION_TEXT

GLOBAL_HIDDEN_FN_EXT blake2b_blocks_avx, 4, 16
pushq %rbp
movq %rsp, %rbp
andq $-64, %rsp
pushq %r12
pushq %r13
pushq %r14
pushq %r15
pushq %rbx
subq $344, %rsp
LOAD_VAR_PIC 48+blake2b_constants, %r9
LOAD_VAR_PIC blake2b_constants_ssse3, %rax
leaq 16(%rax), %r8
vmovdqu 80(%rdi), %xmm0
cmpq $128, %rdx
vpxor (%r9), %xmm0, %xmm0
movl $128, %r9d
vmovdqu (%rax), %xmm12
cmovbe %rdx, %r9
vmovdqu (%r8), %xmm1
movq 64(%rdi), %r8
movq 72(%rdi), %rax
cmpq $0, 80(%rdi)
je blake2b_blocks_avx_L21
blake2b_blocks_avx_L2:
cmpq $128, %rdx
je blake2b_blocks_avx_L21
blake2b_blocks_avx_L3:
lea (%rsp), %r10
testq $64, %rdx
je blake2b_blocks_avx_L5
blake2b_blocks_avx_L4:
vmovdqu (%rsi), %xmm2
vmovdqu %xmm2, (%rsp)
lea 64(%rsp), %r10
vmovdqu 16(%rsi), %xmm3
vmovdqu %xmm3, 16(%rsp)
vpxor %xmm2, %xmm2, %xmm2
vmovdqu 32(%rsi), %xmm4
vmovdqu %xmm4, 32(%rsp)
vmovdqu 48(%rsi), %xmm5
vmovdqu %xmm5, 48(%rsp)
addq $64, %rsi
jmp blake2b_blocks_avx_L6
blake2b_blocks_avx_L5:
vpxor %xmm2, %xmm2, %xmm2
vmovdqu %xmm2, 64(%rsp)
vmovdqu %xmm2, 80(%rsp)
vmovdqu %xmm2, 96(%rsp)
vmovdqu %xmm2, 112(%rsp)
blake2b_blocks_avx_L6:
vmovdqu %xmm2, (%r10)
vmovdqu %xmm2, 16(%r10)
vmovdqu %xmm2, 32(%r10)
vmovdqu %xmm2, 48(%r10)
testq $32, %rdx
je blake2b_blocks_avx_L8
blake2b_blocks_avx_L7:
vmovdqu (%rsi), %xmm2
vmovdqu %xmm2, (%r10)
vmovdqu 16(%rsi), %xmm3
vmovdqu %xmm3, 16(%r10)
addq $32, %rsi
addq $32, %r10
blake2b_blocks_avx_L8:
testq $16, %rdx
je blake2b_blocks_avx_L10
blake2b_blocks_avx_L9:
vmovdqu (%rsi), %xmm2
vmovdqu %xmm2, (%r10)
addq $16, %rsi
addq $16, %r10
blake2b_blocks_avx_L10:
testq $8, %rdx
je blake2b_blocks_avx_L12
blake2b_blocks_avx_L11:
movq (%rsi), %r11
addq $8, %rsi
movq %r11, (%r10)
addq $8, %r10
blake2b_blocks_avx_L12:
testq $4, %rdx
je blake2b_blocks_avx_L14
blake2b_blocks_avx_L13:
movl (%rsi), %r11d
addq $4, %rsi
movl %r11d, (%r10)
addq $4, %r10
blake2b_blocks_avx_L14:
testq $2, %rdx
je blake2b_blocks_avx_L16
blake2b_blocks_avx_L15:
movzwl (%rsi), %r11d
addq $2, %rsi
movw %r11w, (%r10)
addq $2, %r10
blake2b_blocks_avx_L16:
testq $1, %rdx
je blake2b_blocks_avx_L18
blake2b_blocks_avx_L17:
movb (%rsi), %sil
movb %sil, (%r10)
blake2b_blocks_avx_L18:
lea (%rsp), %rsi
blake2b_blocks_avx_L21:
LOAD_VAR_PIC 32+blake2b_constants, %r10
LOAD_VAR_PIC blake2b_constants, %r11
vmovdqu (%rdi), %xmm5
vmovdqu 16(%rdi), %xmm6
vmovdqu 32(%rdi), %xmm7
vmovdqu (%r10), %xmm4
LOAD_VAR_PIC 16+blake2b_constants, %r10
vmovdqu 48(%rdi), %xmm8
vmovdqu (%r11), %xmm3
vmovdqu %xmm3, 176(%rsp)
vmovdqu (%r10), %xmm2
vmovdqu %xmm2, 160(%rsp)
vmovdqu %xmm4, 144(%rsp)
vmovdqu %xmm8, 240(%rsp)
vmovdqu %xmm7, 256(%rsp)
vmovdqu %xmm6, 224(%rsp)
vmovdqu %xmm5, 208(%rsp)
vmovdqu %xmm0, 192(%rsp)
movq %r9, 272(%rsp)
movq %rdi, 128(%rsp)
movq %rcx, 136(%rsp)
jmp blake2b_blocks_avx_L22
# align to 31 mod 64
.p2align 6
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
blake2b_blocks_avx_L25:
addq 136(%rsp), %rsi
addq $-128, %rdx
blake2b_blocks_avx_L22:
movq 272(%rsp), %rcx
addq %rcx, %r8
cmpq %rcx, %r8
lea 1(%rax), %rbx
vmovdqu (%rsi), %xmm15
vmovdqu 16(%rsi), %xmm5
vmovdqu 32(%rsi), %xmm3
vmovdqu 48(%rsi), %xmm6
cmovb %rbx, %rax
vmovd %r8, %xmm7
vpunpcklqdq %xmm5, %xmm15, %xmm2
LOAD_VAR_PIC 96+blake2b_constants, %rcx
vpunpcklqdq %xmm6, %xmm3, %xmm8
LOAD_VAR_PIC 224+blake2b_constants, %rbx
vpaddq 208(%rsp), %xmm2, %xmm0
vpaddq 224(%rsp), %xmm8, %xmm10
vmovd %rax, %xmm14
vmovdqu 256(%rsp), %xmm4
vmovdqu 240(%rsp), %xmm11
vpunpcklqdq %xmm14, %xmm7, %xmm9
vpaddq %xmm4, %xmm0, %xmm13
vpaddq %xmm11, %xmm10, %xmm2
vpxor 144(%rsp), %xmm9, %xmm0
vpxor 192(%rsp), %xmm2, %xmm10
vpxor %xmm13, %xmm0, %xmm8
vpshufd $177, %xmm8, %xmm8
vpshufd $177, %xmm10, %xmm7
vpaddq 176(%rsp), %xmm8, %xmm14
vpaddq 160(%rsp), %xmm7, %xmm9
vpxor %xmm14, %xmm4, %xmm4
vpxor %xmm9, %xmm11, %xmm11
vpshufb %xmm1, %xmm4, %xmm4
vpshufb %xmm1, %xmm11, %xmm0
vpunpckhqdq %xmm5, %xmm15, %xmm15
vpunpckhqdq %xmm6, %xmm3, %xmm6
vpaddq %xmm15, %xmm13, %xmm13
vpaddq %xmm6, %xmm2, %xmm6
vpaddq %xmm4, %xmm13, %xmm10
vpaddq %xmm0, %xmm6, %xmm15
vpxor %xmm10, %xmm8, %xmm2
vpxor %xmm15, %xmm7, %xmm8
vpshufb %xmm12, %xmm2, %xmm5
vpshufb %xmm12, %xmm8, %xmm2
vpaddq %xmm5, %xmm14, %xmm6
vpaddq %xmm2, %xmm9, %xmm7
vpxor %xmm6, %xmm4, %xmm4
vpxor %xmm7, %xmm0, %xmm9
vpaddq %xmm4, %xmm4, %xmm14
vpaddq %xmm9, %xmm9, %xmm13
vpsrlq $63, %xmm4, %xmm0
vpsrlq $63, %xmm9, %xmm11
vpor %xmm14, %xmm0, %xmm8
vpor %xmm13, %xmm11, %xmm4
vpalignr $8, %xmm8, %xmm4, %xmm0
vpalignr $8, %xmm4, %xmm8, %xmm14
vmovdqu 64(%rsi), %xmm9
vmovdqu 80(%rsi), %xmm8
vmovdqu 96(%rsi), %xmm4
vpunpcklqdq %xmm8, %xmm9, %xmm11
vpaddq %xmm11, %xmm10, %xmm10
vmovdqu 112(%rsi), %xmm11
vpaddq %xmm0, %xmm10, %xmm13
vpunpcklqdq %xmm11, %xmm4, %xmm10
vpaddq %xmm10, %xmm15, %xmm15
vpaddq %xmm14, %xmm15, %xmm15
vpalignr $8, %xmm2, %xmm5, %xmm10
vpalignr $8, %xmm5, %xmm2, %xmm5
vpxor %xmm13, %xmm10, %xmm10
vpxor %xmm15, %xmm5, %xmm2
vpshufd $177, %xmm10, %xmm10
vpshufd $177, %xmm2, %xmm2
vpaddq %xmm10, %xmm7, %xmm7
vpaddq %xmm2, %xmm6, %xmm5
vpxor %xmm7, %xmm0, %xmm6
vpxor %xmm5, %xmm14, %xmm14
vpshufb %xmm1, %xmm6, %xmm0
vpshufb %xmm1, %xmm14, %xmm6
vpunpckhqdq %xmm8, %xmm9, %xmm14
vpaddq %xmm14, %xmm13, %xmm13
vpaddq %xmm0, %xmm13, %xmm14
vpunpckhqdq %xmm11, %xmm4, %xmm13
vpxor %xmm14, %xmm10, %xmm10
vpaddq %xmm13, %xmm15, %xmm15
vpshufb %xmm12, %xmm10, %xmm13
vpaddq %xmm6, %xmm15, %xmm15
vpaddq %xmm13, %xmm7, %xmm10
vpxor %xmm15, %xmm2, %xmm2
vpxor %xmm10, %xmm0, %xmm0
vpshufb %xmm12, %xmm2, %xmm2
vpaddq %xmm2, %xmm5, %xmm5
vpxor %xmm5, %xmm6, %xmm7
vpsrlq $63, %xmm0, %xmm6
vpaddq %xmm0, %xmm0, %xmm0
vpor %xmm0, %xmm6, %xmm6
vpsrlq $63, %xmm7, %xmm0
vpaddq %xmm7, %xmm7, %xmm7
vpor %xmm7, %xmm0, %xmm0
vpalignr $8, %xmm0, %xmm6, %xmm7
vpalignr $8, %xmm6, %xmm0, %xmm6
vpunpcklqdq %xmm3, %xmm11, %xmm0
vpaddq %xmm0, %xmm14, %xmm14
vpaddq %xmm7, %xmm14, %xmm0
vpunpckhqdq %xmm4, %xmm9, %xmm14
vpaddq %xmm14, %xmm15, %xmm15
vpaddq %xmm6, %xmm15, %xmm14
vpalignr $8, %xmm13, %xmm2, %xmm15
vpxor %xmm0, %xmm15, %xmm15
vpshufd $177, %xmm15, %xmm15
vpalignr $8, %xmm2, %xmm13, %xmm2
vpxor %xmm14, %xmm2, %xmm13
vpaddq %xmm15, %xmm5, %xmm2
vpshufd $177, %xmm13, %xmm13
vpxor %xmm2, %xmm7, %xmm5
vpunpcklqdq %xmm9, %xmm8, %xmm7
vpaddq %xmm13, %xmm10, %xmm10
vpaddq %xmm7, %xmm0, %xmm9
vmovdqu 48(%rsi), %xmm0
vpshufb %xmm1, %xmm5, %xmm5
vpxor %xmm10, %xmm6, %xmm6
vpshufb %xmm1, %xmm6, %xmm6
vpaddq %xmm5, %xmm9, %xmm9
vpalignr $8, %xmm11, %xmm0, %xmm11
vpxor %xmm9, %xmm15, %xmm15
vpaddq %xmm11, %xmm14, %xmm7
vpshufb %xmm12, %xmm15, %xmm11
vpaddq %xmm6, %xmm7, %xmm14
vpaddq %xmm11, %xmm2, %xmm2
vpxor %xmm14, %xmm13, %xmm13
vpxor %xmm2, %xmm5, %xmm5
vpshufb %xmm12, %xmm13, %xmm13
vpaddq %xmm13, %xmm10, %xmm10
vpxor %xmm10, %xmm6, %xmm15
vpsrlq $63, %xmm5, %xmm6
vpaddq %xmm5, %xmm5, %xmm5
vpsrlq $63, %xmm15, %xmm7
vpor %xmm5, %xmm6, %xmm6
vpaddq %xmm15, %xmm15, %xmm15
vpor %xmm15, %xmm7, %xmm5
vpalignr $8, %xmm6, %xmm5, %xmm15
vpalignr $8, %xmm5, %xmm6, %xmm5
vpshufd $78, (%rsi), %xmm6
vpaddq %xmm6, %xmm9, %xmm9
vpunpckhqdq %xmm3, %xmm8, %xmm3
vpaddq %xmm3, %xmm14, %xmm6
vpaddq %xmm15, %xmm9, %xmm9
vpaddq %xmm5, %xmm6, %xmm8
vpalignr $8, %xmm13, %xmm11, %xmm3
vpalignr $8, %xmm11, %xmm13, %xmm11
vpxor %xmm9, %xmm3, %xmm7
vpshufd $177, %xmm7, %xmm14
vpxor %xmm8, %xmm11, %xmm13
vpshufd $177, %xmm13, %xmm3
vpaddq %xmm14, %xmm10, %xmm6
vpaddq %xmm3, %xmm2, %xmm10
vpxor %xmm6, %xmm15, %xmm2
vmovdqu 16(%rsi), %xmm15
vpshufb %xmm1, %xmm2, %xmm7
vpxor %xmm10, %xmm5, %xmm2
vpshufb %xmm1, %xmm2, %xmm5
vpunpcklqdq %xmm15, %xmm4, %xmm4
vpunpckhqdq %xmm15, %xmm0, %xmm0
vpaddq %xmm4, %xmm9, %xmm2
vpaddq %xmm0, %xmm8, %xmm8
vpaddq %xmm7, %xmm2, %xmm2
vpaddq %xmm5, %xmm8, %xmm0
vpxor %xmm2, %xmm14, %xmm15
vpxor %xmm0, %xmm3, %xmm9
vpshufb %xmm12, %xmm15, %xmm15
vpshufb %xmm12, %xmm9, %xmm3
vpaddq %xmm15, %xmm6, %xmm8
vpaddq %xmm3, %xmm10, %xmm6
vpxor %xmm8, %xmm7, %xmm10
vpxor %xmm6, %xmm5, %xmm5
vpaddq %xmm5, %xmm5, %xmm9
vpsrlq $63, %xmm10, %xmm4
vpsrlq $63, %xmm5, %xmm7
vpaddq %xmm10, %xmm10, %xmm10
vpor %xmm10, %xmm4, %xmm13
vpor %xmm9, %xmm7, %xmm11
vpalignr $8, %xmm11, %xmm13, %xmm4
vpalignr $8, %xmm13, %xmm11, %xmm7
vpalignr $8, %xmm15, %xmm3, %xmm9
vpalignr $8, %xmm3, %xmm15, %xmm10
blake2b_blocks_avx_L23:
movzbl (%rcx), %edi
movzbl 2(%rcx), %r9d
movzbl 4(%rcx), %r10d
movzbl 6(%rcx), %r11d
vmovq (%rdi,%rsi), %xmm5
vpinsrq $1, (%r9,%rsi), %xmm5, %xmm14
vmovq (%r10,%rsi), %xmm3
vpinsrq $1, (%r11,%rsi), %xmm3, %xmm15
vpaddq %xmm14, %xmm2, %xmm2
vpaddq %xmm15, %xmm0, %xmm0
vpaddq %xmm4, %xmm2, %xmm2
vpaddq %xmm7, %xmm0, %xmm0
vpxor %xmm2, %xmm9, %xmm11
vpxor %xmm0, %xmm10, %xmm10
vpshufd $177, %xmm11, %xmm3
movzbl 1(%rcx), %r12d
movzbl 5(%rcx), %r14d
vpshufd $177, %xmm10, %xmm5
vpaddq %xmm3, %xmm6, %xmm6
vpaddq %xmm5, %xmm8, %xmm9
movzbl 3(%rcx), %r13d
vpxor %xmm6, %xmm4, %xmm14
movzbl 7(%rcx), %r15d
vpxor %xmm9, %xmm7, %xmm15
vmovq (%r12,%rsi), %xmm4
vmovq (%r14,%rsi), %xmm11
vpinsrq $1, (%r13,%rsi), %xmm4, %xmm7
vpinsrq $1, (%r15,%rsi), %xmm11, %xmm13
vpshufb %xmm1, %xmm14, %xmm8
vpshufb %xmm1, %xmm15, %xmm14
vpaddq %xmm7, %xmm2, %xmm2
vpaddq %xmm13, %xmm0, %xmm0
vpaddq %xmm8, %xmm2, %xmm4
vpaddq %xmm14, %xmm0, %xmm7
vpxor %xmm4, %xmm3, %xmm10
vpxor %xmm7, %xmm5, %xmm3
vpshufb %xmm12, %xmm10, %xmm11
vpshufb %xmm12, %xmm3, %xmm10
vpaddq %xmm11, %xmm6, %xmm13
vpaddq %xmm10, %xmm9, %xmm9
movzbl 8(%rcx), %edi
vpxor %xmm13, %xmm8, %xmm8
movzbl 12(%rcx), %r10d
vpxor %xmm9, %xmm14, %xmm2
movzbl 10(%rcx), %r9d
vpsrlq $63, %xmm8, %xmm6
movzbl 14(%rcx), %r11d
vpsrlq $63, %xmm2, %xmm0
vpaddq %xmm8, %xmm8, %xmm5
vpaddq %xmm2, %xmm2, %xmm14
vmovq (%rdi,%rsi), %xmm15
vpor %xmm5, %xmm6, %xmm8
vmovq (%r10,%rsi), %xmm3
vpor %xmm14, %xmm0, %xmm6
vpinsrq $1, (%r9,%rsi), %xmm15, %xmm5
vpinsrq $1, (%r11,%rsi), %xmm3, %xmm0
vpalignr $8, %xmm8, %xmm6, %xmm2
vpalignr $8, %xmm6, %xmm8, %xmm14
vpalignr $8, %xmm10, %xmm11, %xmm8
vpalignr $8, %xmm11, %xmm10, %xmm11
vpaddq %xmm5, %xmm4, %xmm4
vpaddq %xmm0, %xmm7, %xmm7
vpaddq %xmm2, %xmm4, %xmm15
vpaddq %xmm14, %xmm7, %xmm0
vpxor %xmm15, %xmm8, %xmm6
vpxor %xmm0, %xmm11, %xmm10
vpshufd $177, %xmm6, %xmm6
vpshufd $177, %xmm10, %xmm8
movzbl 9(%rcx), %r12d
movzbl 13(%rcx), %r14d
vpaddq %xmm6, %xmm9, %xmm4
vpaddq %xmm8, %xmm13, %xmm7
movzbl 11(%rcx), %r13d
vpxor %xmm4, %xmm2, %xmm9
movzbl 15(%rcx), %r15d
vpxor %xmm7, %xmm14, %xmm2
vmovq (%r12,%rsi), %xmm14
addq $16, %rcx
vmovq (%r14,%rsi), %xmm3
vpshufb %xmm1, %xmm9, %xmm13
vpinsrq $1, (%r13,%rsi), %xmm14, %xmm5
vpinsrq $1, (%r15,%rsi), %xmm3, %xmm9
vpshufb %xmm1, %xmm2, %xmm11
vpaddq %xmm5, %xmm15, %xmm15
vpaddq %xmm9, %xmm0, %xmm0
vpaddq %xmm13, %xmm15, %xmm2
vpaddq %xmm11, %xmm0, %xmm0
vpxor %xmm2, %xmm6, %xmm6
vpxor %xmm0, %xmm8, %xmm8
vpshufb %xmm12, %xmm6, %xmm14
vpshufb %xmm12, %xmm8, %xmm15
vpaddq %xmm14, %xmm4, %xmm8
vpaddq %xmm15, %xmm7, %xmm6
vpxor %xmm8, %xmm13, %xmm4
vpxor %xmm6, %xmm11, %xmm11
vpaddq %xmm4, %xmm4, %xmm10
vpsrlq $63, %xmm4, %xmm7
vpsrlq $63, %xmm11, %xmm13
vpaddq %xmm11, %xmm11, %xmm4
vpor %xmm10, %xmm7, %xmm3
vpor %xmm4, %xmm13, %xmm11
vpalignr $8, %xmm11, %xmm3, %xmm4
vpalignr $8, %xmm3, %xmm11, %xmm7
vpalignr $8, %xmm15, %xmm14, %xmm10
vpalignr $8, %xmm14, %xmm15, %xmm9
cmpq %rbx, %rcx
jb blake2b_blocks_avx_L23
blake2b_blocks_avx_L24:
movq 32(%rsi), %r13
movq (%rsi), %r10
movq 48(%rsi), %r9
vmovd %r13, %xmm13
vpinsrq $1, %r9, %xmm13, %xmm14
vmovd %r10, %xmm3
movq 16(%rsi), %rbx
vpinsrq $1, %rbx, %xmm3, %xmm15
vpaddq %xmm14, %xmm0, %xmm0
vpaddq %xmm7, %xmm0, %xmm3
vpxor %xmm3, %xmm10, %xmm10
vpaddq %xmm15, %xmm2, %xmm2
vpaddq %xmm4, %xmm2, %xmm5
vpshufd $177, %xmm10, %xmm15
vpxor %xmm5, %xmm9, %xmm9
vpshufd $177, %xmm9, %xmm9
vpaddq %xmm15, %xmm8, %xmm14
vpaddq %xmm9, %xmm6, %xmm0
vpxor %xmm14, %xmm7, %xmm7
vpxor %xmm0, %xmm4, %xmm8
vpshufb %xmm1, %xmm7, %xmm4
vpshufb %xmm1, %xmm8, %xmm2
vmovq 8(%rsi), %xmm7
movq %r8, 288(%rsp)
movq 24(%rsi), %r8
vpinsrq $1, %r8, %xmm7, %xmm6
vpinsrq $1, %r10, %xmm7, %xmm7
vpaddq %xmm6, %xmm5, %xmm13
movq 40(%rsi), %rcx
movq 56(%rsi), %rdi
vpaddq %xmm2, %xmm13, %xmm13
vmovd %rcx, %xmm5
vpxor %xmm13, %xmm9, %xmm9
vpinsrq $1, %rdi, %xmm5, %xmm10
vpshufb %xmm12, %xmm9, %xmm5
vpaddq %xmm10, %xmm3, %xmm3
vpaddq %xmm4, %xmm3, %xmm11
vpaddq %xmm5, %xmm0, %xmm3
vpxor %xmm11, %xmm15, %xmm8
vpshufb %xmm12, %xmm8, %xmm10
vpaddq %xmm10, %xmm14, %xmm8
vpxor %xmm3, %xmm2, %xmm14
vpxor %xmm8, %xmm4, %xmm9
vpsrlq $63, %xmm14, %xmm4
vpsrlq $63, %xmm9, %xmm0
vpaddq %xmm14, %xmm14, %xmm14
movq 64(%rsi), %r15
vpor %xmm14, %xmm4, %xmm6
vpaddq %xmm9, %xmm9, %xmm4
vmovq 96(%rsi), %xmm9
vpor %xmm4, %xmm0, %xmm2
movq 112(%rsi), %r14
vmovd %r15, %xmm15
vpinsrq $1, %r14, %xmm9, %xmm0
vpinsrq $1, %rbx, %xmm9, %xmm9
vpalignr $8, %xmm6, %xmm2, %xmm4
vpalignr $8, %xmm2, %xmm6, %xmm2
vpaddq %xmm0, %xmm11, %xmm11
movq 80(%rsi), %r11
vpinsrq $1, %r11, %xmm15, %xmm14
vpaddq %xmm2, %xmm11, %xmm11
vpalignr $8, %xmm10, %xmm5, %xmm15
vpalignr $8, %xmm5, %xmm10, %xmm5
vpxor %xmm11, %xmm5, %xmm10
vpaddq %xmm14, %xmm13, %xmm13
vpaddq %xmm4, %xmm13, %xmm6
vpshufd $177, %xmm10, %xmm14
vpxor %xmm6, %xmm15, %xmm13
vpaddq %xmm14, %xmm3, %xmm0
vpshufd $177, %xmm13, %xmm13
vpaddq %xmm13, %xmm8, %xmm15
vpxor %xmm0, %xmm2, %xmm8
vpxor %xmm15, %xmm4, %xmm3
vpshufb %xmm1, %xmm8, %xmm5
vpshufb %xmm1, %xmm3, %xmm4
vmovq 72(%rsi), %xmm8
movq %rax, 296(%rsp)
movq 88(%rsi), %rax
vpinsrq $1, %rax, %xmm8, %xmm2
movq 104(%rsi), %r12
vpaddq %xmm2, %xmm6, %xmm6
vpinsrq $1, %r12, %xmm8, %xmm8
vmovd %r12, %xmm3
vpaddq %xmm4, %xmm6, %xmm10
vpxor %xmm10, %xmm13, %xmm13
movq %rsi, 280(%rsp)
movq 120(%rsi), %rsi
vpinsrq $1, %rsi, %xmm3, %xmm6
vpshufb %xmm12, %xmm13, %xmm3
vpaddq %xmm6, %xmm11, %xmm11
vpaddq %xmm5, %xmm11, %xmm6
vpxor %xmm6, %xmm14, %xmm14
vpshufb %xmm12, %xmm14, %xmm2
vpaddq %xmm3, %xmm15, %xmm14
vpaddq %xmm2, %xmm0, %xmm0
vpaddq %xmm8, %xmm6, %xmm6
vpxor %xmm14, %xmm4, %xmm4
vpxor %xmm0, %xmm5, %xmm13
vpsrlq $63, %xmm4, %xmm5
vpsrlq $63, %xmm13, %xmm15
vpaddq %xmm4, %xmm4, %xmm4
vpaddq %xmm13, %xmm13, %xmm13
vpor %xmm4, %xmm5, %xmm11
vpor %xmm13, %xmm15, %xmm5
vpalignr $8, %xmm5, %xmm11, %xmm15
vmovd %r11, %xmm4
vpalignr $8, %xmm11, %xmm5, %xmm5
vmovd %r14, %xmm11
vpinsrq $1, %r13, %xmm11, %xmm13
vpinsrq $1, %r15, %xmm4, %xmm11
vpaddq %xmm5, %xmm6, %xmm6
vpaddq %xmm13, %xmm10, %xmm10
vpaddq %xmm15, %xmm10, %xmm10
vpalignr $8, %xmm3, %xmm2, %xmm13
vpxor %xmm10, %xmm13, %xmm8
vmovd %rsi, %xmm13
vpshufd $177, %xmm8, %xmm8
vpalignr $8, %xmm2, %xmm3, %xmm3
vpxor %xmm6, %xmm3, %xmm2
vpaddq %xmm8, %xmm0, %xmm3
vpaddq %xmm11, %xmm10, %xmm10
vpxor %xmm3, %xmm15, %xmm0
vpshufd $177, %xmm2, %xmm2
vpshufb %xmm1, %xmm0, %xmm0
vpaddq %xmm2, %xmm14, %xmm14
vpxor %xmm14, %xmm5, %xmm5
vpshufb %xmm1, %xmm5, %xmm15
vpaddq %xmm0, %xmm10, %xmm5
vpinsrq $1, %r9, %xmm13, %xmm10
vpaddq %xmm10, %xmm6, %xmm6
vpaddq %xmm15, %xmm6, %xmm13
vpxor %xmm5, %xmm8, %xmm10
vpxor %xmm13, %xmm2, %xmm8
vpshufb %xmm12, %xmm10, %xmm4
vpshufb %xmm12, %xmm8, %xmm6
vpaddq %xmm4, %xmm3, %xmm8
vpaddq %xmm6, %xmm14, %xmm2
vpxor %xmm8, %xmm0, %xmm14
vpxor %xmm2, %xmm15, %xmm15
vpaddq %xmm14, %xmm14, %xmm0
vpsrlq $63, %xmm14, %xmm3
vpsrlq $63, %xmm15, %xmm14
vpor %xmm0, %xmm3, %xmm10
vpaddq %xmm15, %xmm15, %xmm3
vpor %xmm3, %xmm14, %xmm0
vpaddq %xmm7, %xmm5, %xmm14
vpalignr $8, %xmm10, %xmm0, %xmm11
vmovd %rax, %xmm5
vpaddq %xmm11, %xmm14, %xmm7
vpinsrq $1, %rcx, %xmm5, %xmm14
vpalignr $8, %xmm0, %xmm10, %xmm15
vpaddq %xmm9, %xmm7, %xmm3
vmovd %rdi, %xmm9
vpinsrq $1, %r8, %xmm9, %xmm10
vpaddq %xmm14, %xmm13, %xmm13
vpaddq %xmm15, %xmm13, %xmm5
vpalignr $8, %xmm6, %xmm4, %xmm13
vpalignr $8, %xmm4, %xmm6, %xmm4
vpxor %xmm7, %xmm13, %xmm14
vpxor %xmm5, %xmm4, %xmm6
vpshufd $177, %xmm14, %xmm13
vpshufd $177, %xmm6, %xmm14
vpaddq %xmm13, %xmm2, %xmm6
vpaddq %xmm14, %xmm8, %xmm4
vpaddq %xmm10, %xmm5, %xmm5
vpxor %xmm6, %xmm11, %xmm2
vpxor %xmm4, %xmm15, %xmm8
vpshufb %xmm1, %xmm2, %xmm2
vpshufb %xmm1, %xmm8, %xmm8
vpaddq %xmm2, %xmm3, %xmm7
vpaddq %xmm8, %xmm5, %xmm5
vpxor %xmm7, %xmm13, %xmm13
vpxor %xmm5, %xmm14, %xmm14
vpshufb %xmm12, %xmm13, %xmm13
vpshufb %xmm12, %xmm14, %xmm14
vpaddq %xmm13, %xmm6, %xmm10
vpaddq %xmm14, %xmm4, %xmm0
vpxor %xmm10, %xmm2, %xmm2
vpxor %xmm0, %xmm8, %xmm8
vpaddq %xmm2, %xmm2, %xmm6
vpaddq %xmm8, %xmm8, %xmm15
vpsrlq $63, %xmm2, %xmm4
vpsrlq $63, %xmm8, %xmm11
vpor %xmm6, %xmm4, %xmm3
vpor %xmm15, %xmm11, %xmm9
vpxor %xmm0, %xmm7, %xmm0
vpxor 208(%rsp), %xmm0, %xmm7
vpxor %xmm10, %xmm5, %xmm0
vpalignr $8, %xmm9, %xmm3, %xmm4
vpalignr $8, %xmm13, %xmm14, %xmm5
vpalignr $8, %xmm3, %xmm9, %xmm3
vpxor %xmm5, %xmm4, %xmm6
vpalignr $8, %xmm14, %xmm13, %xmm8
vpxor %xmm8, %xmm3, %xmm9
vmovdqu %xmm7, 208(%rsp)
vpxor 224(%rsp), %xmm0, %xmm2
vpxor 256(%rsp), %xmm6, %xmm7
vpxor 240(%rsp), %xmm9, %xmm10
movq 296(%rsp), %rax
movq 288(%rsp), %r8
movq 280(%rsp), %rsi
vmovdqu %xmm2, 224(%rsp)
vmovdqu %xmm7, 256(%rsp)
vmovdqu %xmm10, 240(%rsp)
cmpq $128, %rdx
ja blake2b_blocks_avx_L25
blake2b_blocks_avx_L26:
vmovdqu 240(%rsp), %xmm8
vmovdqu 256(%rsp), %xmm7
vmovdqu 224(%rsp), %xmm6
vmovdqu 208(%rsp), %xmm5
movq 128(%rsp), %rdi
vmovdqu %xmm5, (%rdi)
vmovdqu %xmm6, 16(%rdi)
vmovdqu %xmm7, 32(%rdi)
vmovdqu %xmm8, 48(%rdi)
movq %r8, 64(%rdi)
movq %rax, 72(%rdi)
addq $344, %rsp
popq %rbx
popq %r15
popq %r14
popq %r13
popq %r12
movq %rbp, %rsp
popq %rbp
ret
FN_END blake2b_blocks_avx