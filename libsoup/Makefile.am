## Process this file with automake to produce Makefile.in

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DBINDIR=\"$(bindir)\"		\
	-I$(top_srcdir)			\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(NSS_CFLAGS)			\
	$(OPENSSL_CFLAGS)

libsoupincludedir = $(includedir)/soup-2.0/libsoup

libsoupinclude_HEADERS =	\
	soup.h			\
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

lib_LTLIBRARIES = libsoup-2.0.la

libsoup_2_0_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_2_0_la_LIBADD =		\
	$(GLIB_LIBS)		\
	$(NSS_LIBS)

libsoup_2_0_la_SOURCES =	\
	md5-utils.h		\
	md5-utils.c		\
	soup-auth.h		\
	soup-auth.c		\
	soup-context.c		\
	soup-error.c		\
	soup-headers.c		\
	soup-message.c		\
	soup-method.c		\
	soup-misc.c     	\
	soup-nss.h		\
	soup-nss.c		\
	soup-ntlm.c     	\
	soup-private.h     	\
	soup-queue.h		\
	soup-queue.c		\
	soup-server.c		\
	soup-server-auth.c	\
	soup-socket.c		\
	soup-socket-unix.c	\
	soup-socks.h		\
	soup-socks.c		\
	soup-ssl.h		\
	soup-ssl.c		\
	soup-transfer.h		\
	soup-transfer.c		\
	soup-uri.c

noinst_PROGRAMS = libsoup-ssl-proxy

libsoup_ssl_proxy_LDADD =	\
	$(LINK_STATIC)		\
	$(OPENSSL_LIBS)		\
	$(GLIB_LIBS)		\
	$(LINK_DYNAMIC)

libsoup_ssl_proxy_SOURCES =	\
	soup-openssl.h		\
	soup-openssl.c		\
	soup-ssl-proxy.c

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_PROGRAM) libsoup-ssl-proxy $(DESTDIR)$(bindir)/$(SSL_PROXY_NAME)
