INCLUDES =		\
	-I$(top_srcdir)	\
	$(GLIB_CFLAGS)

noinst_PROGRAMS = get timeserver

get_SOURCES = get.c

get_LDADD = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la

timeserver_SOURCES = timeserver.c

timeserver_LDADD = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la

check_PROGRAMS = auth-test

auth_test_SOURCES = auth-test.c
auth_test_LDADD = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la
