## Process this file with automake to produce Makefile.in

INCLUDES = 				\
	-DG_LOG_DOMAIN=\"SOUP\" 	\
	-DSYSCONFDIR=\"$(sysconfdir)\" 	\
	-DLIBEXECDIR=\"$(libexecdir)\"	\
	-I$(top_srcdir)			\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(GNUTLS_CFLAGS)		\
	$(NSS_CFLAGS)			\
	$(OPENSSL_CFLAGS)

EXTRA_DIST =	\
	soup-openssl.c	\
	soup-openssl.h \
	soup-ssl-proxy.c

libsoupincludedir = $(includedir)/soup-2.0/libsoup

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

lib_LTLIBRARIES = libsoup-2.0.la

libsoup_2_0_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE)

libsoup_2_0_la_LIBADD =		\
	$(GLIB_LIBS)		\
	$(GNUTLS_LIBS)		\
	$(NSS_LIBS)

libsoup_2_0_la_SOURCES =	\
	md5-utils.h		\
	md5-utils.c		\
	soup-address.c		\
	soup-auth.h		\
	soup-auth.c		\
	soup-context.c		\
	soup-error.c		\
	soup-gnutls.h		\
	soup-gnutls.c		\
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
	soup-socks.h		\
	soup-socks.c		\
	soup-ssl.h		\
	soup-ssl.c		\
	soup-transfer.h		\
	soup-transfer.c		\
	soup-uri.c

if BUILD_PROXY
noinst_PROGRAMS = libsoup-ssl-proxy

# workaround for libtool flag re-ordering
libsoup-ssl-proxy$(EXEEXT): $(libsoup_ssl_proxy_OBJECTS) $(libsoup_ssl_proxy_DEPENDENCIES)
	@rm -f libsoup-ssl-proxy$(EXEEXT)
	$(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@ $(libsoup_ssl_proxy_LDFLAGS) $(libsoup_ssl_proxy_OBJECTS) $(libsoup_ssl_proxy_LDADD) $(LIBS)

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
	$(mkinstalldirs) $(DESTDIR)$(libexecdir)
	$(INSTALL_PROGRAM) libsoup-ssl-proxy $(DESTDIR)$(libexecdir)/$(SSL_PROXY_NAME)
else
install-exec-hook:
endif
