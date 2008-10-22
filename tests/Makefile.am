INCLUDES =		\
	-I$(top_srcdir)	\
	-DSRCDIR=\""$(srcdir)"\" \
	-DLIBSOUP_DISABLE_DEPRECATED \
	$(SOUP_MAINTAINER_FLAGS) \
	$(XML_CFLAGS)	\
	$(GLIB_CFLAGS)	\
	$(LIBGNUTLS_CFLAGS)

LIBS =			\
	$(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la \
	$(GLIB_LIBS)

noinst_PROGRAMS =	\
	chunk-test	\
	context-test	\
	continue-test	\
	date		\
	dns		\
	forms-test	\
	get		\
	getbug		\
	header-parsing  \
	misc-test	\
	ntlm-test	\
	redirect-test	\
	simple-httpd	\
	simple-proxy	\
	uri-parsing	\
	$(CURL_TESTS)	\
	$(APACHE_TESTS)	\
	$(SSL_TESTS)	\
	$(XMLRPC_TESTS)

TEST_SRCS = test-utils.c test-utils.h

auth_test_SOURCES = auth-test.c $(TEST_SRCS)
chunk_test_SOURCES = chunk-test.c $(TEST_SRCS)
context_test_SOURCES = context-test.c $(TEST_SRCS)
continue_test_SOURCES = continue-test.c $(TEST_SRCS)
date_SOURCES = date.c $(TEST_SRCS)
dns_SOURCES = dns.c
forms_test_SOURCES = forms-test.c $(TEST_SRCS)
get_SOURCES = get.c
getbug_SOURCES = getbug.c
header_parsing_SOURCES = header-parsing.c $(TEST_SRCS)
misc_test_SOURCES = misc-test.c $(TEST_SRCS)
ntlm_test_SOURCES = ntlm-test.c $(TEST_SRCS)
proxy_test_SOURCES = proxy-test.c $(TEST_SRCS)
pull_api_SOURCES = pull-api.c $(TEST_SRCS)
range_test_SOURCES = range-test.c $(TEST_SRCS)
redirect_test_SOURCES = redirect-test.c $(TEST_SRCS)
server_auth_test_SOURCES = server-auth-test.c $(TEST_SRCS)
simple_httpd_SOURCES = simple-httpd.c
simple_proxy_SOURCES = simple-proxy.c
ssl_test_SOURCES = ssl-test.c $(TEST_SRCS)
uri_parsing_SOURCES = uri-parsing.c $(TEST_SRCS)
xmlrpc_test_SOURCES = xmlrpc-test.c $(TEST_SRCS)
xmlrpc_server_test_SOURCES = xmlrpc-server-test.c $(TEST_SRCS)

if HAVE_APACHE
APACHE_TESTS = auth-test proxy-test pull-api range-test
endif
if HAVE_CURL
CURL_TESTS = forms-test server-auth-test
endif
if HAVE_SSL
SSL_TESTS = ssl-test
endif
if HAVE_XMLRPC_EPI_PHP
XMLRPC_TESTS = xmlrpc-test xmlrpc-server-test
endif

TESTS =			\
	chunk-test	\
	context-test	\
	continue-test	\
	date		\
	header-parsing	\
	misc-test	\
	ntlm-test	\
	redirect-test	\
	uri-parsing	\
	$(APACHE_TESTS)	\
	$(CURL_TESTS)	\
	$(SSL_TESTS)	\
	$(XMLRPC_TESTS)

EXTRA_DIST =		\
	libsoup.supp	\
	test-cert.pem	\
	test-key.pem	\
	htdigest	\
	htpasswd	\
	httpd.conf.in	\
	index.txt	\
	xmlrpc-server.php

if MISSING_REGRESSION_TEST_PACKAGES
check-local: check-TESTS
	@echo ""
	@echo "NOTE: some tests were not run due to missing packages:" $(MISSING_REGRESSION_TEST_PACKAGES)
	@echo ""
endif

kill-httpd:
	$(APACHE_HTTPD) -d `pwd` -f httpd.conf -k stop
