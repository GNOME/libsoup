## Process this file with automake to produce Makefile.in

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DLIBEXECDIR=\"$(libexecdir)\"	\
	-I$(top_srcdir)			\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(GNUTLS_CFLAGS)

libsoupincludedir = $(includedir)/libsoup-2.2/libsoup

libsoupinclude_HEADERS =	\
	soup.h			\
	soup-address.h		\
	soup-context.h		\
	soup-error.h		\
	soup-headers.h		\
	soup-message.h		\
	soup-method.h		\
	soup-misc.h     	\
	soup-ntlm.h		\
	soup-server-auth.h	\
	soup-server.h		\
	soup-socket.h		\
	soup-uri.h

lib_LTLIBRARIES = libsoup-2.2.la

libsoup_2_2_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_2_2_la_LIBADD =		\
	$(GLIB_LIBS)		\
	$(GNUTLS_LIBS)

libsoup_2_2_la_SOURCES =	\
	md5-utils.h		\
	md5-utils.c		\
	soup-address.c		\
	soup-auth.h		\
	soup-auth.c		\
	soup-context.c		\
	soup-dns.h		\
	soup-dns.c		\
	soup-error.c		\
	soup-gnutls.h		\
	soup-gnutls.c		\
	soup-headers.c		\
	soup-message.c		\
	soup-method.c		\
	soup-misc.c     	\
	soup-ntlm.c     	\
	soup-private.h     	\
	soup-queue.h		\
	soup-queue.c		\
	soup-server.c		\
	soup-server-auth.c	\
	soup-socket.c		\
	soup-socks.h		\
	soup-socks.c		\
	soup-ssl.h		\
	soup-ssl.c		\
	soup-transfer.h		\
	soup-transfer.c		\
	soup-uri.c
