/*
 * Generated from https://github.com/aklomp/base64/blob/master/lib/arch/avx2/
 * using gcc6 -march=core-avx2 -mtune=core-avx2 -O3 -S
 */

#include "../macro.S"

#ifdef LINUX
#define PROGBITS @progbits
#else
#define PROGBITS
#endif
.comm _base64_table_dec, 256, 5
	.file	"avx2.c"
	.text
	.p2align 4,,15
GLOBAL_HIDDEN_FN_EXT base64_decode_avx2,4,1
base64_decode_avx2_local:
.LFB4659:
	.cfi_startproc
	vmovdqa	.LC0(%rip), %ymm15
	leaq	8(%rsp), %r10
	.cfi_def_cfa 10, 0
	andq	$-32, %rsp
	vmovdqa	.LC1(%rip), %ymm6
	vmovdqa	.LC2(%rip), %ymm14
	pushq	-8(%r10)
	vmovdqa	.LC3(%rip), %ymm13
	pushq	%rbp
	vmovdqa	.LC4(%rip), %ymm12
	vmovdqa	.LC5(%rip), %ymm11
	vmovdqa	.LC6(%rip), %ymm10
	vmovdqa	.LC7(%rip), %ymm9
	vmovdqa	.LC8(%rip), %ymm8
	.cfi_escape 0x10,0x6,0x2,0x76,0
	movq	%rsp, %rbp
	pushq	%r12
	vmovdqa	.LC9(%rip), %ymm7
	pushq	%r10
	.cfi_escape 0xf,0x3,0x76,0x70,0x6
	.cfi_escape 0x10,0xc,0x2,0x76,0x78
	xorl	%r10d, %r10d
	pushq	%rbx
	.cfi_escape 0x10,0x3,0x2,0x76,0x68
.L2:
	cmpq	$44, %rsi
	ja	.L4
.L26:
	leaq	-1(%rsi), %rbx
	testq	%rsi, %rsi
	je	.L22
	movzbl	(%rdi), %eax
	leaq	_base64_table_dec(%rip), %r11
	movzbl	(%r11,%rax), %eax
	cmpb	$-3, %al
	ja	.L11
	leal	0(,%rax,4), %r8d
	testq	%rbx, %rbx
	je	.L22
	movzbl	1(%rdi), %eax
	movzbl	(%r11,%rax), %eax
	cmpb	$-3, %al
	ja	.L15
.L28:
	movl	%eax, %r9d
	leaq	-3(%rsi), %r12
	sall	$4, %eax
	shrb	$4, %r9b
	orl	%r9d, %r8d
	leaq	1(%r10), %r9
	movb	%r8b, (%rdx)
	cmpq	$1, %rbx
	je	.L16
	movzbl	2(%rdi), %r8d
	movzbl	(%r11,%r8), %r8d
	cmpb	$-3, %r8b
	ja	.L24
	movl	%r8d, %r9d
	leaq	2(%r10), %rbx
	sall	$6, %r8d
	subq	$4, %rsi
	shrb	$2, %r9b
	orl	%r9d, %eax
	movb	%al, 1(%rdx)
	testq	%r12, %r12
	je	.L19
	movzbl	3(%rdi), %eax
	leaq	4(%rdi), %r9
	movzbl	(%r11,%rax), %eax
	cmpb	$-3, %al
	ja	.L25
	orl	%eax, %r8d
	addq	$3, %r10
	addq	$3, %rdx
	movq	%r9, %rdi
	movb	%r8b, -1(%rdx)
	cmpq	$44, %rsi
	jbe	.L26
.L4:
	vmovdqu	(%rdi), %ymm0
	vpcmpgtb	%ymm6, %ymm0, %ymm1
	vpcmpgtb	%ymm15, %ymm0, %ymm2
	vpcmpgtb	%ymm14, %ymm0, %ymm4
	vpcmpgtb	%ymm12, %ymm0, %ymm3
	vpandn	%ymm1, %ymm2, %ymm2
	vpcmpgtb	%ymm13, %ymm0, %ymm1
	vpand	%ymm7, %ymm2, %ymm2
	vpandn	%ymm1, %ymm4, %ymm4
	vpcmpgtb	%ymm11, %ymm0, %ymm1
	vpand	.LC10(%rip), %ymm4, %ymm4
	vpor	%ymm4, %ymm2, %ymm2
	vpandn	%ymm1, %ymm3, %ymm3
	vpcmpeqb	%ymm6, %ymm0, %ymm1
	vpand	.LC11(%rip), %ymm3, %ymm3
	vpand	%ymm10, %ymm1, %ymm5
	vpcmpeqb	%ymm9, %ymm0, %ymm1
	vpand	%ymm8, %ymm1, %ymm1
	vpor	%ymm1, %ymm5, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vpxor	%xmm2, %xmm2, %xmm2
	vpor	%ymm3, %ymm1, %ymm1
	vpcmpeqb	%ymm2, %ymm1, %ymm2
	vpmovmskb	%ymm2, %eax
	testl	%eax, %eax
	je	.L27
	movzbl	(%rdi), %eax
	leaq	_base64_table_dec(%rip), %r11
	leaq	-1(%rsi), %rbx
	movzbl	(%r11,%rax), %eax
	cmpb	$-3, %al
	ja	.L11
	leal	0(,%rax,4), %r8d
	movzbl	1(%rdi), %eax
	movzbl	(%r11,%rax), %eax
	cmpb	$-3, %al
	jbe	.L28
.L15:
	movl	$-1, %eax
	vzeroupper
	popq	%rbx
	popq	%r10
	.cfi_remember_state
	.cfi_def_cfa 10, 0
	popq	%r12
	popq	%rbp
	leaq	-8(%r10), %rsp
	.cfi_def_cfa 7, 8
	ret
	.p2align 4,,10
	.p2align 3
.L27:
	.cfi_restore_state
	vpaddb	%ymm1, %ymm0, %ymm0
	addq	$32, %rdi
	addq	$24, %rdx
	addq	$24, %r10
	vpand	.LC12(%rip), %ymm0, %ymm3
	vpsrld	$16, %ymm0, %ymm2
	subq	$32, %rsi
	vpand	.LC13(%rip), %ymm0, %ymm1
	vpslld	$26, %ymm0, %ymm0
	vpsrld	$2, %ymm3, %ymm3
	vpslld	$12, %ymm1, %ymm1
	vpor	%ymm3, %ymm2, %ymm2
	vpor	%ymm0, %ymm1, %ymm0
	vmovdqa	.LC15(%rip), %ymm1
	vpor	%ymm2, %ymm0, %ymm0
	vpshufb	.LC14(%rip), %ymm0, %ymm0
	vpermd	%ymm0, %ymm1, %ymm0
	vmovdqu	%ymm0, -24(%rdx)
	jmp	.L2
	.p2align 4,,10
	.p2align 3
.L19:
	movq	%rbx, %r10
.L22:
	movl	$1, %eax
.L5:
	movq	%r10, (%rcx)
	vzeroupper
	popq	%rbx
	popq	%r10
	.cfi_remember_state
	.cfi_def_cfa 10, 0
	popq	%r12
	popq	%rbp
	leaq	-8(%r10), %rsp
	.cfi_def_cfa 7, 8
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
	movq	%r9, %r10
	movl	$1, %eax
	jmp	.L5
	.p2align 4,,10
	.p2align 3
.L24:
	movq	%r9, %r10
	xorl	%eax, %eax
	cmpb	$-2, %r8b
	jne	.L5
	movl	$1, %eax
	testq	%r12, %r12
	je	.L5
	movzbl	3(%rdi), %eax
	cmpb	$-2, (%r11,%rax)
	sete	%dl
	xorl	%eax, %eax
	cmpq	$4, %rsi
	sete	%al
	andl	%edx, %eax
	jmp	.L5
	.p2align 4,,10
	.p2align 3
.L25:
	cmpb	$-2, %al
	movq	%rbx, %r10
	sete	%dl
	xorl	%eax, %eax
	testq	%rsi, %rsi
	sete	%al
	andl	%edx, %eax
	jmp	.L5
	.cfi_endproc
.LFE4659:
	.section	.rodata.cst32,"aM",PROGBITS,32
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
	.quad	1157442765409226768
	.quad	1157442765409226768
	.quad	1157442765409226768
	.quad	1157442765409226768
	.align 16
.LC7:
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
.LC8:
	.quad	1374463283923456787
	.quad	1374463283923456787
	.quad	1374463283923456787
	.quad	1374463283923456787
	.align 16
.LC9:
	.quad	289360691352306692
	.quad	289360691352306692
	.quad	289360691352306692
	.quad	289360691352306692
	.align 16
.LC10:
	.quad	-4629771061636907073
	.quad	-4629771061636907073
	.quad	-4629771061636907073
	.quad	-4629771061636907073
	.align 16
.LC11:
	.quad	-5063812098665367111
	.quad	-5063812098665367111
	.quad	-5063812098665367111
	.quad	-5063812098665367111
	.align 16
.LC12:
	.quad	17732923536900096
	.quad	17732923536900096
	.quad	17732923536900096
	.quad	17732923536900096
	.align 16
.LC13:
	.quad	69269232566016
	.quad	69269232566016
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
	.align 16
.LC15:
	.long	0
	.long	1
	.long	2
	.long	4
	.long	5
	.long	6
	.long	-1
	.long	-1
	.ident	"GCC: (Debian 6.2.1-5) 6.2.1 20161124"
