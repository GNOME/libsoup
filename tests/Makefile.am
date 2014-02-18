include $(top_srcdir)/glib-tap.mk

AM_CPPFLAGS =		\
	-I$(top_srcdir)	\
	$(GLIB_CFLAGS)

LIBS =			\
	$(top_builddir)/libsoup/libsoup-2.4.la \
	$(GLIB_LIBS)

test_programs =			\
	auth-test		\
	cache-test		\
	chunk-test		\
	chunk-io-test		\
	coding-test		\
	connection-test		\
	context-test		\
	continue-test		\
	cookies-test		\
	date			\
	forms-test		\
	header-parsing		\
	misc-test		\
	multipart-test		\
	no-ssl-test		\
	ntlm-test		\
	proxy-test		\
	pull-api		\
	range-test		\
	redirect-test		\
	requester-test		\
	resource-test		\
	session-test		\
	server-auth-test	\
	server-test		\
	sniffing-test		\
	socket-test		\
	ssl-test		\
	streaming-test		\
	timeout-test		\
	tld-test		\
	uri-parsing		\
	xmlrpc-server-test	\
	xmlrpc-test

test_extra_programs =		\
	ntlm-test-helper	\
	$(TESTS)

test_data =			\
	index.txt		\
	soup-tests.gresource	\
	test-cert.pem		\
	test-key.pem		\
	xmlrpc-server.php

noinst_LTLIBRARIES += libtest.la

libtest_la_SOURCES =	\
	test-utils.c	\
	test-utils.h

LDADD = libtest.la

if HAVE_APACHE
if HAVE_APACHE_2_2
httpd_conf_in = httpd.conf.22.in
else
httpd_conf_in = httpd.conf.24.in
endif
httpd.conf: $(httpd_conf_in)
	$(AM_V_GEN) sed -e 's,[@]srcdir@,$(srcdir),' \
	    -e 's,[@]builddir@,$(builddir),' \
	    -e 's,[@]APACHE_MODULE_DIR@,$(APACHE_MODULE_DIR),' \
	    -e 's,[@]APACHE_PHP_MODULE_DIR@,$(APACHE_PHP_MODULE_DIR),' \
	    -e 's,[@]APACHE_PHP_MODULE@,$(APACHE_PHP_MODULE),' \
	    -e 's,[@]IF_HAVE_PHP@,$(IF_HAVE_PHP),' \
	    -e 's,[@]APACHE_SSL_MODULE_DIR@,$(APACHE_SSL_MODULE_DIR),' \
	    $< > $@ || rm -f $@

BUILT_SOURCES += httpd.conf
test_data +=			\
	htdigest		\
	htpasswd		\
	httpd.conf
endif

RESOURCES = $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/soup-tests.gresource.xml)

soup-tests.gresource: soup-tests.gresource.xml $(RESOURCES)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) --target=$@ --sourcedir=$(srcdir) $<

EXTRA_DIST +=			 \
	htdigest		 \
	htpasswd		 \
	httpd.conf.22.in	 \
	httpd.conf.24.in	 \
	index.txt		 \
	libsoup.supp		 \
	soup-tests.gresource.xml \
	test-cert.pem		 \
	test-key.pem		 \
	xmlrpc-server.php	 \
	$(RESOURCES)

DISTCLEANFILES += soup-tests.gresource httpd.conf

TESTS_ENVIRONMENT += SOUP_TESTS_IN_MAKE_CHECK=1

check: start-httpd

check-local: check-TESTS
	@$(MAKE) kill-httpd

.PHONY: start-httpd kill-httpd

start-httpd:
if HAVE_APACHE_2_2
	@$(APACHE_HTTPD) -d $(abs_srcdir) -c "PidFile `pwd`/httpd.pid" -f `pwd`/httpd.conf -k start;
endif
if HAVE_APACHE_2_4
	@$(APACHE_HTTPD) -d $(abs_srcdir) -c "DefaultRuntimeDir `pwd`" -c "PidFile `pwd`/httpd.pid" -f `pwd`/httpd.conf -k start;
endif

kill-httpd:
if HAVE_APACHE_2_2
	@if [ -f httpd.pid ]; then \
		$(APACHE_HTTPD) -d $(abs_srcdir) -c "PidFile `pwd`/httpd.pid" -f `pwd`/httpd.conf -k stop; \
	fi
endif
if HAVE_APACHE_2_4
	@if [ -f httpd.pid ]; then \
		$(APACHE_HTTPD) -d $(abs_srcdir) -c "DefaultRuntimeDir `pwd`" -c "PidFile `pwd`/httpd.pid" -f `pwd`/httpd.conf -k stop; \
	fi
endif
