INCLUDES =		\
	-I$(top_srcdir)	\
	-DSRCDIR=\""$(srcdir)"\" \
	$(XML_CFLAGS)	\
	$(GLIB_CFLAGS)	\
	$(LIBGNUTLS_CFLAGS)

LIBS = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la

noinst_PROGRAMS =	\
	context-test	\
	date		\
	dict		\
	dns		\
	get		\
	getbug		\
	header-parsing  \
	ntlm-test	\
	revserver	\
	simple-httpd	\
	simple-proxy	\
	uri-parsing	\
	$(APACHE_TESTS)	\
	$(SSL_TESTS)	\
	$(XMLRPC_TESTS)

auth_test_SOURCES = auth-test.c apache-wrapper.c apache-wrapper.h
context_test_SOURCES = context-test.c
date_SOURCES = date.c
dict_SOURCES = dict.c
dns_SOURCES = dns.c
get_SOURCES = get.c
getbug_SOURCES = getbug.c
header_parsing_SOURCES = header-parsing.c
ntlm_test_SOURCES = ntlm-test.c
proxy_test_SOURCES = proxy-test.c apache-wrapper.c apache-wrapper.h
pull_api_SOURCES = pull-api.c apache-wrapper.c apache-wrapper.h
revserver_SOURCES = revserver.c
simple_httpd_SOURCES = simple-httpd.c
simple_proxy_SOURCES = simple-proxy.c
ssl_test_SOURCES = ssl-test.c
uri_parsing_SOURCES = uri-parsing.c
xmlrpc_test_SOURCES = xmlrpc-test.c apache-wrapper.c apache-wrapper.h

if HAVE_APACHE
APACHE_TESTS = auth-test proxy-test pull-api
endif
if HAVE_SSL
SSL_TESTS = ssl-test
endif
if HAVE_XMLRPC_EPI_PHP
XMLRPC_TESTS = xmlrpc-test
endif

TESTS = context-test date header-parsing uri-parsing ntlm-test $(APACHE_TESTS) $(SSL_TESTS) $(XMLRPC_TESTS)

EXTRA_DIST =		\
	libsoup.supp	\
	test-cert.pem	\
	test-key.pem	\
	htdigest	\
	htpasswd	\
	httpd.conf.in	\
	index.txt	\
	xmlrpc-server.php

kill-httpd:
	$(APACHE_HTTPD) -d `pwd` -f httpd.conf -k stop
