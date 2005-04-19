## Process this file with automake to produce Makefile.in

if OS_WIN32
LIBWS2_32 = -lws2_32
NO_UNDEFINED = -no-undefined
endif

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"libsoup\" 	\
	-I$(top_srcdir)			\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(LIBGNUTLS_CFLAGS)

MARSHAL_GENERATED = soup-marshal.c soup-marshal.h

soup-marshal.h: soup-marshal.list
	( @GLIB_GENMARSHAL@ --prefix=soup_marshal $(srcdir)/soup-marshal.list --header > soup-marshal.tmp \
	&& mv soup-marshal.tmp soup-marshal.h ) \
	|| ( rm -f soup-marshal.tmp && exit 1 )

soup-marshal.c: soup-marshal.h
	( (echo '#include "soup-marshal.h"'; @GLIB_GENMARSHAL@ --prefix=soup_marshal $(srcdir)/soup-marshal.list --body) > soup-marshal.tmp \
	&& mv soup-marshal.tmp soup-marshal.c ) \
	|| ( rm -f soup-marshal.tmp && exit 1 )

BUILT_SOURCES = $(MARSHAL_GENERATED)

CLEANFILES = $(MARSHAL_GENERATED)

libsoupincludedir = $(includedir)/libsoup-2.4/libsoup

libsoupinclude_HEADERS =	\
	soup.h			\
	soup-address.h		\
	soup-connection.h	\
	soup-headers.h		\
	soup-message.h		\
	soup-message-filter.h	\
	soup-message-queue.h	\
	soup-method.h		\
	soup-misc.h     	\
	soup-portability.h	\
	soup-server-auth.h	\
	soup-server-message.h	\
	soup-server.h		\
	soup-session.h		\
	soup-session-async.h	\
	soup-session-sync.h	\
	soup-soap-message.h	\
	soup-soap-response.h	\
	soup-socket.h		\
	soup-status.h		\
	soup-types.h		\
	soup-uri.h

lib_LTLIBRARIES = libsoup-2.4.la

libsoup_2_4_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE) $(NO_UNDEFINED)

libsoup_2_4_la_LIBADD =			\
	$(GLIB_LIBS)			\
	$(XML_LIBS)			\
	$(LIBGNUTLS_LIBS_STATIC)	\
	$(LIBGNUTLS_LIBS)		\
	$(LIBWS2_32)

libsoup_2_4_la_SOURCES =		\
	$(MARSHAL_GENERATED)		\
	soup-address.c			\
	soup-auth.h			\
	soup-auth.c			\
	soup-auth-basic.h		\
	soup-auth-basic.c		\
	soup-auth-digest.h		\
	soup-auth-digest.c		\
	soup-connection.c		\
	soup-connection-ntlm.h		\
	soup-connection-ntlm.c		\
	soup-dns.h			\
	soup-dns.c			\
	soup-gnutls.c			\
	soup-headers.c			\
	soup-md5-utils.h		\
	soup-md5-utils.c		\
	soup-message.c			\
	soup-message-client-io.c	\
	soup-message-filter.c		\
	soup-message-handlers.c		\
	soup-message-io.c		\
	soup-message-private.h		\
	soup-message-queue.c		\
	soup-message-server-io.c	\
	soup-method.c			\
	soup-misc.c     		\
	soup-nossl.c     		\
	soup-server.c			\
	soup-server-auth.c		\
	soup-server-message.c		\
	soup-session.c			\
	soup-session-async.c		\
	soup-session-sync.c		\
	soup-soap-message.c		\
	soup-soap-response.c		\
	soup-socket.c			\
	soup-ssl.h			\
	soup-status.c			\
	soup-uri.c

EXTRA_DIST= soup-marshal.list
