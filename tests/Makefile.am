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
	header-parsing  \
	revserver	\
	simple-httpd	\
	simple-proxy	\
	uri-parsing	\
	$(XMLRPC_TESTS)

auth_test_SOURCES = auth-test.c apache-wrapper.c apache-wrapper.h
date_SOURCES = date.c
dict_SOURCES = dict.c
dns_SOURCES = dns.c
get_SOURCES = get.c
getbug_SOURCES = getbug.c
header_parsing_SOURCES = header-parsing.c
revserver_SOURCES = revserver.c
simple_httpd_SOURCES = simple-httpd.c
simple_proxy_SOURCES = simple-proxy.c
uri_parsing_SOURCES = uri-parsing.c
xmlrpc_test_SOURCES = xmlrpc-test.c apache-wrapper.c apache-wrapper.h

if HAVE_APACHE
APACHE_TESTS = auth-test
endif
if HAVE_XMLRPC_EPI_PHP
XMLRPC_TESTS = xmlrpc-test
endif

TESTS = date header-parsing uri-parsing $(APACHE_TESTS) $(XMLRPC_TESTS)

EXTRA_DIST =		\
	libsoup.supp	\
	test-cert.pem	\
	test-key.pem	\
	htdigest	\
	htpasswd	\
	httpd.conf.in	\
	xmlrpc-server.php
