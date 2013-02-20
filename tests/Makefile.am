INCLUDES =		\
	-I$(top_srcdir)	\
	-DSRCDIR=\""$(abs_srcdir)"\" \
	-DBUILDDIR=\""$(builddir)"\" \
	$(SOUP_MAINTAINER_FLAGS) \
	$(XML_CFLAGS)	\
	$(GLIB_CFLAGS)

LIBS =			\
	$(top_builddir)/libsoup/libsoup-2.4.la \
	$(LIBGNUTLS_LIBS) \
	$(GLIB_LIBS)

TESTS =				\
	auth-test		\
	cache-test		\
	chunk-test		\
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
	ntlm-test		\
	proxy-test		\
	pull-api		\
	range-test		\
	redirect-test		\
	requester-test		\
	resource-test		\
	session-test		\
	server-auth-test	\
	sniffing-test		\
	socket-test		\
	ssl-test		\
	streaming-test		\
	timeout-test		\
	tld-test		\
	uri-parsing		\
	xmlrpc-server-test	\
	xmlrpc-test

noinst_PROGRAMS =		\
	$(TESTS)		\
	dns			\
	get			\
	ntlm-test-helper	\
	simple-httpd		\
	simple-proxy

noinst_DATA = soup-tests.gresource

noinst_LTLIBRARIES = libtest.la

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

BUILT_SOURCES = httpd.conf
endif

soup-tests.gresource: soup-tests.gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/soup-tests.gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) --target=$@ --sourcedir=$(srcdir)  $<

RESOURCES =			\
	resources/atom.xml	\
	resources/home.gif	\
	resources/html_binary.html \
	resources/mbox		\
	resources/mbox.gz	\
	resources/mbox.raw	\
	resources/mbox.zlib	\
	resources/ps_binary.ps	\
	resources/rss20.xml	\
	resources/test.html	\
	resources/text_binary.txt

EXTRA_DIST =			 \
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

DISTCLEANFILES = soup-tests.gresource httpd.conf

TESTS_ENVIRONMENT = \
	SOUP_TESTS_IN_MAKE_CHECK=1

check: start-httpd

check-local: check-TESTS
	@$(MAKE) kill-httpd
if MISSING_REGRESSION_TEST_PACKAGES
	@echo ""
	@echo "NOTE: some tests were not run due to missing packages:" $(MISSING_REGRESSION_TEST_PACKAGES)
	@echo ""
endif

.PHONY: start-httpd kill-httpd

start-httpd:
if HAVE_APACHE
	@$(APACHE_HTTPD) -d `pwd` -f httpd.conf -k start;
endif

kill-httpd:
if HAVE_APACHE
	@if [ -f httpd.pid ]; then \
		$(APACHE_HTTPD) -d `pwd` -f httpd.conf -k stop; \
	fi
endif
