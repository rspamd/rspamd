#include "platform_config.h"

#if !defined(HAVE_SLASHMACRO) && !defined(HAVE_DOLLARMACRO)
	#error Unknown gnu as macro parameter convention! Run ./configure
#endif

#if defined(__MACH__)
	.macro FN name
	#if defined(HAVE_SLASHMACRO)
		\name:
		_\name:
	#elif defined(HAVE_DOLLARMACRO)
		$0:
		_$0:
	#endif
	.endm

	.macro FN_EXT name, args, xmmused
	#if defined(HAVE_SLASHMACRO)
		FN \name
	#elif defined(HAVE_DOLLARMACRO)
		FN $0
	#endif
	.endm

	.macro FN_END name
	.endm

	.macro HIDDEN name
	#if defined(HAVE_AS_PRIVATE_EXTERN)
	#if defined(HAVE_SLASHMACRO)
		.private_extern \name
		.private_extern _\name
	#elif defined(HAVE_DOLLARMACRO)
		.private_extern $0
		.private_extern _$0
	#endif
	#endif
	.endm
#else
	.macro FN name
		\name:
		_\name:
	.endm

	.macro FN_EXT name, args, xmmused
		FN \name
	.endm

	.macro FN_END name
		.size \name, .-\name
		.size _\name, .-_\name
		.type \name, @function
	 	.type _\name, @function
	.endm

	.macro HIDDEN name
	#if defined(HAVE_AS_HIDDEN)
		.hidden \name
		.hidden _\name
	#endif
	.endm

	/* set NX for stack */
	.section .note.GNU-stack,"",@progbits
#endif
#if defined(__MACH__)
	.macro SECTION_TEXT
		.section __TEXT,__text,regular
	.endm

	.macro SECTION_RODATA
		.section __TEXT,__text,regular
	.endm
#else
	/* put everything in the code segment to simplify things */
	.macro SECTION_TEXT
		.text
	.endm

	.macro SECTION_RODATA
		.text
	.endm
#endif

/* declare a global function */
.macro GLOBAL name
#if defined(HAVE_SLASHMACRO)
	.globl \name
	.globl _\name
#elif defined(HAVE_DOLLARMACRO)
	.globl $0
	.globl _$0
#endif
.endm

.macro FN_LOCAL_PREFIX name
#if defined(HAVE_SLASHMACRO)
	FN LOCAL_PREFIX(\name)
#elif defined(HAVE_DOLLARMACRO)
	FN LOCAL_PREFIX($0)
#endif
.endm

.macro FN_EXT_LOCAL_PREFIX name, args, xmmused
#if defined(HAVE_SLASHMACRO)
	FN_EXT LOCAL_PREFIX(\name), \args, \xmmused
#elif defined(HAVE_DOLLARMACRO)
	FN_EXT LOCAL_PREFIX($0), $1, $2
#endif
.endm

.macro FN_END_LOCAL_PREFIX name
#if defined(HAVE_SLASHMACRO)
	FN_END LOCAL_PREFIX(\name)
#elif defined(HAVE_DOLLARMACRO)
	FN_END LOCAL_PREFIX($0)
#endif
.endm

.macro GLOBAL_LOCAL_PREFIX name
#if defined(HAVE_SLASHMACRO)
	GLOBAL LOCAL_PREFIX(\name)
	HIDDEN LOCAL_PREFIX(\name)
#elif defined(HAVE_DOLLARMACRO)
	GLOBAL LOCAL_PREFIX($0)
	HIDDEN LOCAL_PREFIX($0)
#endif
.endm

.macro GLOBAL_HIDDEN_FN name
#if defined(HAVE_SLASHMACRO)
	GLOBAL \name
	HIDDEN \name
	FN \name
#elif defined(HAVE_DOLLARMACRO)
	GLOBAL $0
	HIDDEN $0
	FN $0
#endif
.endm

.macro GLOBAL_HIDDEN_FN_EXT name, args, xmmused
#if defined(HAVE_SLASHMACRO)
	GLOBAL \name
	HIDDEN \name
	FN_EXT \name, \args, \xmmused
#elif defined(HAVE_DOLLARMACRO)
	GLOBAL $0
	HIDDEN $0
	FN_EXT $0, $1, $2
#endif
.endm

/* pic support */
.macro LOAD_VAR_PIC var, reg
#if !defined(__LP64__)
	#if defined(HAVE_SLASHMACRO)
		call 1f
		1:
		popl \reg
		leal \var - 1b(\reg), \reg
	#elif defined(HAVE_DOLLARMACRO)
		call 1f
		1:
		popl $1
		leal $0 - 1b($1), $1
	#endif
#else
	#if defined(HAVE_SLASHMACRO)
		leaq \var(%rip), \reg
	#elif defined(HAVE_DOLLARMACRO)
		leaq $0(%rip), $1
	#endif
#endif
.endm
