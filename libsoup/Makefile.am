## Process this file with automake to produce Makefile.in

@SET_MAKE@

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DBINDIR=\"$(bindir)\"		\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(OPENSSL_CFLAGS)		\
	$(NSS_CFLAGS)			\
	$(APACHE_CFLAGS)

soupincludedir = $(includedir)/soup

soupinclude_HEADERS =		\
	soup.h			\
	soup-context.h		\
	soup-message.h		\
	soup-misc.h     	\
	soup-serializer.h	\
	soup-server.h		\
	soup-socket.h		\
	soup-uri.h

lib_LTLIBRARIES = libsoup.la libsoup-apache.la

libsoup_la_LDFLAGS = -version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_la_LIBADD =		\
	$(GLIB_LIBS)		\
	$(XML_LIBS)

libsoup_la_SOURCES =		\
	md5-utils.h		\
	md5-utils.c		\
	soup-cgi.c		\
	soup-context.c		\
	soup-digest.h		\
	soup-digest.c		\
	soup-headers.h		\
	soup-headers.c		\
	soup-message.c		\
	soup-misc.c     	\
	soup-private.h     	\
	soup-queue.c		\
	soup-serializer.c	\
	soup-server.c		\
	soup-socket.c		\
	soup-socks.h		\
	soup-socks.c		\
	soup-ssl.h		\
	soup-ssl.c		\
	soup-uri.c

libsoup_apache_la_LDFLAGS = 	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_apache_la_LIBADD =	\
	$(APACHE_LIBS)		\
	-L.libs -lsoup

libsoup_apache_la_SOURCES =	\
	soup-apache.c

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

