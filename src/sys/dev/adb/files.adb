# 
#	$NetBSD: files.adb,v 1.1 2007/01/17 23:20:16 macallan Exp $
#
# Apple Desktop Bus protocol and drivers

defflag	adbdebug.h	ADB_DEBUG
defflag	adbdebug.h	ADBKBD_DEBUG
defflag	adbdebug.h	ADBMS_DEBUG
defflag adbdebug.h	ADBKBD_POWER_PANIC

define adb_bus {}

device nadb {}
attach nadb at adb_bus
file dev/adb/adb_bus.c		nadb needs-flag

device adbkbd : wskbddev, wsmousedev
attach adbkbd at nadb
file dev/adb/adb_kbd.c		adbkbd needs-flag

device adbms : wsmousedev
attach adbms at nadb
file dev/adb/adb_ms.c		adbms needs-flag