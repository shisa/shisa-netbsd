# $NetBSD: GENERIC.MP,v 1.1 2003/11/15 04:03:00 petrov Exp $
#
# GENERIC Sparc64 kernel configuration with multiprocessor support.
#

include 	"arch/sparc64/conf/GENERIC32"

#ident 	"GENERIC.MP-$Revision: 1.1 $"

include 	"arch/sparc64/conf/std.sparc64-64"

options 	MULTIPROCESSOR		# include multiprocessor support
cpu* 		at mainbus0		# declare additional CPUs

options 	COMPAT_NETBSD32		# NetBSD/sparc binary compatibility
options 	COMPAT_SVR4_32		# SunOS 5.x 32-bit binary compatibility

# DEBUG options
#options 	LOCKDEBUG
#options 	DIAGNOSTIC
#makeoptions	DEBUG="-g"
#options 	DEBUG
#options 	SYSCALL_DEBUG
