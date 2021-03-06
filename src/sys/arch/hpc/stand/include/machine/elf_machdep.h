/*	$NetBSD: elf_machdep.h,v 1.2 2004/08/06 18:33:09 uch Exp $	*/

/* Windows CE architecture */
#define	ELFSIZE		32

#ifdef MIPS
#include "../../../../hpcmips/include/elf_machdep.h"
#endif
#ifdef SHx
#include "../../../../hpcsh/include/elf_machdep.h"
#endif
#ifdef ARM
#include "../../../../arm/include/elf_machdep.h"
#endif
