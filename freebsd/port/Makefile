# New ports collection makefile for:	rspamd
# Date created:							2010-03-24
# Whom:									Vsevolod Stakhov <vsevolod@FreeBSD.org>
#
# $FreeBSD$
#

PORTNAME=		rspamd
PORTVERSION=	0.3.0
CATEGORIES=		mail
MASTER_SITES=	SF/${PORTNAME}/${PORTNAME}/${PORTNAME}-${PORTVERSION}

MAINTAINER=		vsevolod@FreeBSD.org
COMMENT=		Fast spam filtering system

RUN_DEPENDS=	${SITE_PERL}/IO/Socket/SSL.pm:${PORTSDIR}/security/p5-IO-Socket-SSL \
				${SITE_PERL}/IO/String.pm:${PORTSDIR}/devel/p5-IO-String
LIB_DEPENDS=	pcre.0:${PORTSDIR}/devel/pcre \
				gmime-2.0:${PORTSDIR}/mail/gmime2 \
				event-1.4:${PORTSDIR}/devel/libevent

USE_GNOME=		glib20
USE_CMAKE=		yes
USE_LDCONFIG=	yes
WANT_PERL=		yes
USE_PERL5=		yes

OPTIONS=		RSPAMD_GPERF "Enable google perf-tools profiling" off \
				RSPAMD_JUDY "Enable judy arrays usage for performance" off \
				RSPAMD_OPTFLAGS "Turn on compiler optimizations" off \
				RSPAMD_REDIRECTOR "Install HTTP redirector" off \
				RSPAMD_STATIC "Build static version of rspamd" off

MAN3=			Mail::Rspamd::Client.3
CMAKE_ARGS+=	-DETC_PREFIX=${PREFIX}/etc -DPREFIX=${PREFIX}
PLIST_SUB+=		ETCDIR=etc/rspamd

.include <bsd.port.pre.mk>

.if defined(WITH_RSPAMD_GPERF)
CMAKE_ARGS+=	-DENABLE_GPERF_TOOLS=ON
LIB_DEPENDS+=	profiler.0:${PORTSDIR}/devel/google-perftools
.endif

.if defined(WITH_RSPAMD_JUDY)
LIB_DEPENDS+=	Judy:${PORTSDIR}/devel/judy
.endif

USE_LUA=	5.1-
PLIST_SUB+=		LUA=""

.if defined(WITH_RSPAMD_OPTFLAGS)
CMAKE_ARGS+=	-DENABLE_OPTIMIZATION=ON
.endif

.if defined(WITH_RSPAMD_REDIRECTOR)
CMAKE_ARGS+=	-DENABLE_REDIRECTOR=ON
PLIST_SUB+=		REDIRECTOR=""
RUN_DEPENDS+=	${SITE_PERL}/POE/Component/Client/DNS.pm:${PORTSDIR}/dns/p5-POE-Component-Client-DNS \
				${SITE_PERL}/POE/Component/Client/HTTP.pm:${PORTSDIR}/www/p5-POE-Component-Client-HTTP \
				${SITE_PERL}/POE/Component/Server/HTTP.pm:${PORTSDIR}/www/p5-POE-Component-Server-HTTP \
				${SITE_PERL}/${PERL_ARCH}/Cache/Memcached/Fast.pm:${PORTSDIR}/databases/p5-Cache-Memcached-Fast \
				${SITE_PERL}/Proc/PidUtil.pm:${PORTSDIR}/sysutils/p5-Proc-PidUtil \
				${SITE_PERL}/Proc/Daemon.pm:${PORTSDIR}/devel/p5-Proc-Daemon \
				${SITE_PERL}/${PERL_ARCH}/Digest/SHA256.pm:${PORTSDIR}/security/p5-Digest-SHA256 \
				${SITE_PERL}/SWF/File.pm:${PORTSDIR}/graphics/p5-SWF-File
.else
PLIST_SUB+=		REDIRECTOR="@comment"
.endif

.if defined(WITH_RSPAMD_STATIC)
CMAKE_ARGS+=	-DENABLE_STATIC=ON
PLIST_SUB+=		CPLUGINS="@comment"
USE_LDCONFIG=	no
.else
PLIST_SUB+=		CPLUGINS=""
.endif

.if ${OSVERSION} < 600000
CMAKE_ARGS+= -DCMAKE_EXE_LINKER_FLAGS=-lpthread
.endif

.include <bsd.port.post.mk>
