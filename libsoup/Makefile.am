## Process this file with automake to produce Makefile.in

@SET_MAKE@

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DBINDIR=\"$(bindir)\"		\
	@SOUP_DEBUG_FLAGS@		\
	@GNET_CFLAGS@			\
	@XML_CFLAGS@			\
	@OPENSSL_CFLAGS@		\
	@NSS_CFLAGS@

soupincludedir = $(includedir)/soup

lib_LTLIBRARIES = libsoup.la

libsoup_la_LDFLAGS = -version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_la_LIBADD =		\
	$(GNET_LIBS)		\
	$(XML_LIBS)

libsoup_la_SOURCES =		\
	soup-context.c		\
	soup-headers.h		\
	soup-headers.c		\
	soup-message.c		\
	soup-misc.c     	\
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

bin_PROGRAMS = soup-ssl-proxy

soup_ssl_proxy_LDADD =		\
	$(OPENSSL_LIBS)		\
	$(NSS_LIBS)		\
	$(GLIB_LIBS)

soup_ssl_proxy_SOURCES =	\
	soup-nss.h		\
	soup-nss.c		\
	soup-openssl.h		\
	soup-openssl.c		\
	soup-ssl-proxy.c

EXTRA_DIST = 

