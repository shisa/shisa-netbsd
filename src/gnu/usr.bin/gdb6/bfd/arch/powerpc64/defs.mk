# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative-gdb,v 1.1 2006/05/29 19:10:58 nathanw Exp 
# Generated from: NetBSD: mknative.common,v 1.8 2006/05/26 19:17:21 mrg Exp 
#
G_libbfd_la_DEPENDENCIES=elf64-ppc.lo elf64-gen.lo elf64.lo elf.lo elflink.lo elf-strtab.lo elf-eh-frame.lo dwarf1.lo elf32-ppc.lo elf-vxworks.lo elf32.lo coff-rs6000.lo xcofflink.lo coff64-rs6000.lo aix5ppc-core.lo elf32-gen.lo cpu-rs6000.lo cpu-powerpc.lo ofiles
G_libbfd_la_OBJECTS=archive.lo archures.lo bfd.lo bfdio.lo bfdwin.lo  cache.lo coffgen.lo corefile.lo format.lo init.lo libbfd.lo  opncls.lo reloc.lo section.lo syms.lo targets.lo hash.lo  linker.lo srec.lo binary.lo tekhex.lo ihex.lo stabs.lo  stab-syms.lo merge.lo dwarf2.lo simple.lo archive64.lo
G_DEFS=-DHAVE_CONFIG_H
G_INCLUDES=-I. -I${GNUHOSTDIST}/bfd -I${GNUHOSTDIST}/bfd/../include  -I${GNUHOSTDIST}/bfd/../intl -I../intl
G_TDEFAULTS=-DDEFAULT_VECTOR=bfd_elf64_powerpc_vec -DSELECT_VECS='&bfd_elf64_powerpc_vec,&bfd_elf64_powerpcle_vec,&bfd_elf32_powerpc_vec,&bfd_elf32_powerpcle_vec,&rs6000coff_vec,&rs6000coff64_vec,&bfd_elf64_little_generic_vec,&bfd_elf64_big_generic_vec,&bfd_elf32_little_generic_vec,&bfd_elf32_big_generic_vec' -DSELECT_ARCHITECTURES='&bfd_rs6000_arch,&bfd_powerpc_arch' -DHAVE_bfd_elf64_powerpc_vec -DHAVE_bfd_elf64_powerpcle_vec -DHAVE_bfd_elf32_powerpc_vec -DHAVE_bfd_elf32_powerpcle_vec -DHAVE_rs6000coff_vec -DHAVE_rs6000coff64_vec -DHAVE_bfd_elf64_little_generic_vec -DHAVE_bfd_elf64_big_generic_vec -DHAVE_bfd_elf32_little_generic_vec -DHAVE_bfd_elf32_big_generic_vec