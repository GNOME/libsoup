## Process this file with automake to produce Makefile.in

@SET_MAKE@

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	@SOUP_DEBUG_FLAGS@

soupincludedir = $(includedir)/soup

lib_LTLIBRARIES = libsoup.la

libsoup_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -release $(LT_RELEASE)

libsoup_la_SOURCES =	\
	soup-context.c	\
	soup-queue.c	\
	soup-message.c	\
	soup-uri.c	\
	soup-misc.c     \
	soup-ssl.c	\
	soup-socks.c

soupinclude_HEADERS =	\
	soup.h		\
	soup-context.h	\
	soup-queue.h	\
	soup-message.h	\
	soup-uri.h	\
	soup-misc.h     \
	soup-ssl.h	\
	soup-socks.h

EXTRA_DIST = soup-private.h

