## Process this file with automake to produce Makefile.in

@SET_MAKE@

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	@SOUP_DEBUG_FLAGS@

soupincludedir = $(includedir)/soup

lib_LTLIBRARIES = libsoup.la

libsoup_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libsoup_la_SOURCES =		\
	soup-context.c		\
	soup-headers.h		\
	soup-headers.c		\
	soup-message.c		\
	soup-misc.c     	\
	soup-nss.h		\
	soup-nss.c		\
	soup-openssl.h		\
	soup-openssl.c		\
	soup-private.h     	\
	soup-queue.c		\
	soup-serializer.c	\
	soup-server.c		\
	soup-socks.h		\
	soup-socks.c		\
	soup-ssl.h		\
	soup-ssl.c		\
	soup-uri.c

soupinclude_HEADERS =		\
	soup.h			\
	soup-context.h		\
	soup-message.h		\
	soup-misc.h     	\
	soup-queue.h		\
	soup-serializer.h	\
	soup-server.h		\
	soup-uri.h

EXTRA_DIST = 

