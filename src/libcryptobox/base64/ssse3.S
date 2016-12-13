/*
 * Generated from https://github.com/aklomp/base64/blob/master/lib/arch/ssse3/
 * using gcc6 -march=core2 -mtune=core2 -O3 -S
 */


#include "../macro.S"


#ifdef LINUX
#define PROGBITS @progbits
#else
#define PROGBITS
#endif

.comm _base64_table_dec, 256, 5

	.file	"ssse3.c"
	.text
	.p2align 4,,15
GLOBAL_HIDDEN_FN_EXT base64_decode_ssse3,4,1
base64_decode_ssse3_local:
.LFB4658:
	.cfi_startproc
	movdqa	.LC0(%rip), %xmm11
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	xorl	%r10d, %r10d
	movdqa	.LC1(%rip), %xmm2
	pushq	%rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	movdqa	.LC2(%rip), %xmm10
	movdqa	.LC3(%rip), %xmm9
	movdqa	.LC4(%rip), %xmm8
	movdqa	.LC5(%rip), %xmm7
	movdqa	.LC6(%rip), %xmm6
	movdqa	.LC7(%rip), %xmm5
	movdqa	.LC8(%rip), %xmm4
	movdqa	.LC9(%rip), %xmm3
.L2:
	cmpq	$23, %rsi
	ja	.L4
.L25:
	leaq	-1(%rsi), %rbx
	testq	%rsi, %rsi
	je	.L21
	movzbl	(%rdi), %eax
	leaq	_base64_table_dec(%rip), %r9
	movzbl	(%r9,%rax), %eax
	cmpb	$-3, %al
	ja	.L11
	leal	0(,%rax,4), %r8d
	testq	%rbx, %rbx
	je	.L21
	movzbl	1(%rdi), %eax
	movzbl	(%r9,%rax), %eax
	cmpb	$-3, %al
	ja	.L15
.L27:
	leaq	-3(%rsi), %rbp
	movl	%eax, %r11d
	sall	$4, %eax
	shrb	$4, %r11b
	orl	%r11d, %r8d
	cmpq	$1, %rbx
	movb	%r8b, (%rdx)
	leaq	1(%r10), %r11
	je	.L16
	movzbl	2(%rdi), %r8d
	movzbl	(%r9,%r8), %r8d
	cmpb	$-3, %r8b
	ja	.L23
	leaq	2(%r10), %rbx
	movl	%r8d, %r11d
	subq	$4, %rsi
	shrb	$2, %r11b
	sall	$6, %r8d
	orl	%r11d, %eax
	testq	%rbp, %rbp
	movb	%al, 1(%rdx)
	je	.L19
	movzbl	3(%rdi), %eax
	leaq	4(%rdi), %r11
	movzbl	(%r9,%rax), %eax
	cmpb	$-3, %al
	ja	.L24
	orl	%eax, %r8d
	addq	$3, %r10
	addq	$3, %rdx
	movb	%r8b, -1(%rdx)
	cmpq	$23, %rsi
	movq	%r11, %rdi
	jbe	.L25
.L4:
	movdqu	(%rdi), %xmm1
	movdqa	%xmm1, %xmm0
	movdqa	%xmm1, %xmm12
	movdqa	%xmm1, %xmm13
	pcmpgtb	%xmm2, %xmm12
	movdqa	%xmm1, %xmm14
	pcmpgtb	%xmm11, %xmm0
	pcmpgtb	%xmm10, %xmm13
	pcmpgtb	%xmm7, %xmm14
	pandn	%xmm12, %xmm0
	movdqa	%xmm1, %xmm12
	pand	%xmm6, %xmm0
	pcmpgtb	%xmm9, %xmm12
	pandn	%xmm12, %xmm13
	movdqa	%xmm1, %xmm12
	pand	%xmm5, %xmm13
	por	%xmm13, %xmm0
	pcmpgtb	%xmm8, %xmm12
	pandn	%xmm14, %xmm12
	pand	%xmm4, %xmm12
	por	%xmm12, %xmm0
	movdqa	%xmm1, %xmm12
	pcmpeqb	%xmm3, %xmm12
	pand	.LC10(%rip), %xmm12
	por	%xmm12, %xmm0
	movdqa	%xmm1, %xmm12
	pcmpeqb	%xmm2, %xmm12
	pand	.LC11(%rip), %xmm12
	por	%xmm12, %xmm0
	pxor	%xmm12, %xmm12
	pcmpeqb	%xmm0, %xmm12
	pmovmskb	%xmm12, %eax
	testl	%eax, %eax
	je	.L26
	movzbl	(%rdi), %eax
	leaq	_base64_table_dec(%rip), %r9
	leaq	-1(%rsi), %rbx
	movzbl	(%r9,%rax), %eax
	cmpb	$-3, %al
	ja	.L11
	leal	0(,%rax,4), %r8d
	movzbl	1(%rdi), %eax
	movzbl	(%r9,%rax), %eax
	cmpb	$-3, %al
	jbe	.L27
.L15:
	movl	$-1, %eax
	popq	%rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 16
	popq	%rbp
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L26:
	.cfi_restore_state
	paddb	%xmm1, %xmm0
	addq	$16, %rdi
	addq	$12, %rdx
	movdqa	.LC12(%rip), %xmm13
	movdqa	%xmm0, %xmm1
	addq	$12, %r10
	subq	$16, %rsi
	movdqa	.LC13(%rip), %xmm12
	pand	%xmm0, %xmm13
	psrld	$16, %xmm1
	pand	%xmm0, %xmm12
	psrld	$2, %xmm13
	pslld	$12, %xmm12
	por	%xmm13, %xmm1
	pslld	$26, %xmm0
	por	%xmm12, %xmm1
	por	%xmm1, %xmm0
	pshufb	.LC14(%rip), %xmm0
	movups	%xmm0, -12(%rdx)
	jmp	.L2
	.p2align 4,,10
	.p2align 3
.L19:
	movq	%rbx, %r10
.L21:
	movl	$1, %eax
.L5:
	popq	%rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 16
	movq	%r10, (%rcx)
	popq	%rbp
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L11:
	.cfi_restore_state
	xorl	%eax, %eax
	jmp	.L5
	.p2align 4,,10
	.p2align 3
.L16:
	movq	%r11, %r10
	movl	$1, %eax
	jmp	.L5
	.p2align 4,,10
	.p2align 3
.L23:
	xorl	%eax, %eax
	cmpb	$-2, %r8b
	movq	%r11, %r10
	jne	.L5
	testq	%rbp, %rbp
	movl	$1, %eax
	je	.L5
	movzbl	3(%rdi), %eax
	cmpb	$-2, (%r9,%rax)
	sete	%dl
	xorl	%eax, %eax
	cmpq	$4, %rsi
	sete	%al
	andl	%edx, %eax
	jmp	.L5
	.p2align 4,,10
	.p2align 3
.L24:
	cmpb	$-2, %al
	movq	%rbx, %r10
	sete	%dl
	xorl	%eax, %eax
	testq	%rsi, %rsi
	sete	%al
	andl	%edx, %eax
	jmp	.L5
	.cfi_endproc
.LFE4658:
	.section	.rodata.cst16,"aM",PROGBITS,16
	.align 16
.LC0:
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.byte	57
	.align 16
.LC1:
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.byte	47
	.align 16
.LC2:
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.byte	90
	.align 16
.LC3:
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.byte	64
	.align 16
.LC4:
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.byte	122
	.align 16
.LC5:
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.byte	96
	.align 16
.LC6:
	.quad	289360691352306692
	.quad	289360691352306692
	.align 16
.LC7:
	.quad	-4629771061636907073
	.quad	-4629771061636907073
	.align 16
.LC8:
	.quad	-5063812098665367111
	.quad	-5063812098665367111
	.align 16
.LC9:
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.byte	43
	.align 16
.LC10:
	.quad	1374463283923456787
	.quad	1374463283923456787
	.align 16
.LC11:
	.quad	1157442765409226768
	.quad	1157442765409226768
	.align 16
.LC12:
	.quad	17732923536900096
	.quad	17732923536900096
	.align 16
.LC13:
	.quad	69269232566016
	.quad	69269232566016
	.align 16
.LC14:
	.byte	3
	.byte	2
	.byte	1
	.byte	7
	.byte	6
	.byte	5
	.byte	11
	.byte	10
	.byte	9
	.byte	15
	.byte	14
	.byte	13
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.ident	"GCC: (Debian 6.2.1-5) 6.2.1 20161124"
