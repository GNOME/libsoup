## Process this file with automake to produce Makefile.in

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DLIBEXECDIR=\"$(libexecdir)\"	\
	-I$(top_srcdir)			\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(GNUTLS_CFLAGS)

MARSHAL_GENERATED = soup-marshal.c soup-marshal.h

soup-marshal.h: soup-marshal.list
	( @GLIB_GENMARSHAL@ --prefix=soup_marshal soup-marshal.list --header > soup-marshal.tmp \
	&& mv soup-marshal.tmp soup-marshal.h ) \
	|| ( rm -f soup-marshal.tmp && exit 1 )

soup-marshal.c: soup-marshal.h
	( (echo '#include "soup-marshal.h"'; @GLIB_GENMARSHAL@ --prefix=soup_marshal soup-marshal.list --body) > soup-marshal.tmp \
	&& mv soup-marshal.tmp soup-marshal.c ) \
	|| ( rm -f soup-marshal.tmp && exit 1 )

BUILT_SOURCES = $(MARSHAL_GENERATED)

CLEANFILES = $(MARSHAL_GENERATED)

libsoupincludedir = $(includedir)/libsoup-2.2/libsoup

libsoupinclude_HEADERS =	\
	soup.h			\
	soup-address.h		\
	soup-connection.h	\
	soup-context.h		\
	soup-error.h		\
	soup-headers.h		\
	soup-message.h		\
	soup-method.h		\
	soup-misc.h     	\
	soup-server-auth.h	\
	soup-server-message.h	\
	soup-server.h		\
	soup-socket.h		\
	soup-uri.h

lib_LTLIBRARIES = libsoup-2.2.la

libsoup_2_2_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_2_2_la_LIBADD =		\
	$(GLIB_LIBS)		\
	$(GNUTLS_LIBS)

libsoup_2_2_la_SOURCES =		\
	$(MARSHAL_GENERATED)		\
	md5-utils.h			\
	md5-utils.c			\
	soup-address.c			\
	soup-auth.h			\
	soup-auth.c			\
	soup-auth-basic.h		\
	soup-auth-basic.c		\
	soup-auth-digest.h		\
	soup-auth-digest.c		\
	soup-auth-ntlm.h		\
	soup-auth-ntlm.c		\
	soup-connection.c		\
	soup-context.c			\
	soup-dns.h			\
	soup-dns.c			\
	soup-error.c			\
	soup-gnutls.h			\
	soup-gnutls.c			\
	soup-headers.c			\
	soup-message.c			\
	soup-message-client-io.c	\
	soup-message-handlers.c		\
	soup-message-io.c		\
	soup-message-private.h		\
	soup-method.c			\
	soup-misc.c     		\
	soup-private.h     		\
	soup-queue.h			\
	soup-queue.c			\
	soup-server.c			\
	soup-server-auth.c		\
	soup-server-message.c		\
	soup-socket.c			\
	soup-ssl.h			\
	soup-ssl.c			\
	soup-uri.c

EXTRA_DIST= soup-marshal.list
