INCLUDES =		\
	-I$(top_srcdir)	\
	$(GLIB_CFLAGS)

LIBS = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la

noinst_PROGRAMS =	\
	auth-test	\
	dns		\
	get		\
	revserver	\
	simple-httpd	\
	simple-proxy	\
	uri-parsing

auth_test_SOURCES = auth-test.c
dns_SOURCES = dns.c
get_SOURCES = get.c
simple_httpd_SOURCES = simple-httpd.c
simple_proxy_SOURCES = simple-proxy.c
revserver_SOURCES = revserver.c
uri_parsing_SOURCES = uri-parsing.c

EXTRA_DIST = libsoup.supp test-cert.pem test-key.pem
