## Process this file with automake to produce Makefile.in

@SET_MAKE@

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DBINDIR=\"$(bindir)\"		\
	-I$(top_srcdir)/src		\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)

libsoupincludedir = $(includedir)/soup/libsoup

libsoupinclude_HEADERS =	\
	soup.h			\
	soup-context.h		\
	soup-dav.h		\
	soup-dav-server.h	\
	soup-env.h		\
	soup-fault.h		\
	soup-message.h		\
	soup-misc.h     	\
	soup-parser.h		\
	soup-serializer.h	\
	soup-server.h		\
	soup-socket.h		\
	soup-uri.h

lib_LTLIBRARIES = libsoup.la

libsoup_la_LDFLAGS = -version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_la_LIBADD =		\
	$(GLIB_LIBS)		\
	$(XML_LIBS)

libsoup_la_SOURCES =		\
	md5-utils.h		\
	md5-utils.c		\
	soup-auth.h		\
	soup-auth.c		\
	soup-context.c		\
	soup-dav.c		\
	soup-dav-server.c	\
	soup-env.c		\
	soup-fault.c		\
	soup-headers.h		\
	soup-headers.c		\
	soup-message.c		\
	soup-misc.c     	\
	soup-ntlm.h     	\
	soup-ntlm.c     	\
	soup-parser.c		\
	soup-private.h     	\
	soup-queue.h		\
	soup-queue.c		\
	soup-serializer.c	\
	soup-server.c		\
	soup-socket.c		\
	soup-socks.h		\
	soup-socks.c		\
	soup-ssl.h		\
	soup-ssl.c		\
	soup-transfer.h		\
	soup-transfer.c		\
	soup-uri.c

EXTRA_DIST = 

