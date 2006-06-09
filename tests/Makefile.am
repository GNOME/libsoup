INCLUDES =		\
	-I$(top_srcdir)	\
	$(XML_CFLAGS)	\
	$(GLIB_CFLAGS)

LIBS = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la

noinst_PROGRAMS =	\
	auth-test	\
	date		\
	dict		\
	dns		\
	get		\
	getbug		\
	revserver	\
	simple-httpd	\
	simple-proxy	\
	uri-parsing

auth_test_SOURCES = auth-test.c apache-wrapper.c
date_SOURCES = date.c
dict_SOURCES = dict.c
dns_SOURCES = dns.c
get_SOURCES = get.c
getbug_SOURCES = getbug.c
revserver_SOURCES = revserver.c
simple_httpd_SOURCES = simple-httpd.c
simple_proxy_SOURCES = simple-proxy.c
uri_parsing_SOURCES = uri-parsing.c

if HAVE_APACHE
APACHE_TESTS = auth-test
endif

TESTS = date uri-parsing $(APACHE_TESTS)

EXTRA_DIST =		\
	libsoup.supp	\
	test-cert.pem	\
	test-key.pem	\
	htdigest	\
	htpasswd	\
	httpd.conf.in
