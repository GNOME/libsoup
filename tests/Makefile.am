INCLUDES =		\
	-I$(top_srcdir)	\
	$(GLIB_CFLAGS)

LIBS = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la

noinst_PROGRAMS = get revserver simple-httpd simple-proxy

get_SOURCES = get.c
revserver_SOURCES = revserver.c
simple_httpd_SOURCES = simple-httpd.c
simple_proxy_SOURCES = simple-proxy.c

check_PROGRAMS = auth-test uri-parsing

auth_test_SOURCES = auth-test.c
uri_parsing_SOURCES = uri-parsing.c
