#	$NetBSD: Makefile,v 1.8 2004/09/07 23:51:50 lukem Exp $

.include <bsd.own.mk>

DIST=	${NETBSDSRCDIR}/gnu/dist/postfix/man/man5
.PATH:	${DIST}

MAN=	access.5 canonical.5 relocated.5 \
	transport.5 virtual.5 pcre_table.5 regexp_table.5 \
	cidr_table.5 header_checks.5
MAN+=	postconf.5

MLINKS=	header_checks.5 body_checks.5

# XXX notyet:
# aliases.5
# This would conflict with the one installed by sendmail. It isn't
# clear what to do with it. The missing documentation is not too
# interesting given that the sendmail docs are in place, though. The
# format is identical.
# The base install does include support for these:
# ldap_table.5 mysql_table.5 pgsql_table.5

.include <bsd.man.mk>
