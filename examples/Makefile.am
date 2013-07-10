AM_CPPFLAGS =		\
	-I$(top_srcdir)	\
	-DSRCDIR=\""$(abs_srcdir)"\" \
	-DBUILDDIR=\""$(builddir)"\" \
	$(GLIB_CFLAGS)

LIBS =			\
	$(top_builddir)/libsoup/libsoup-2.4.la \
	$(GLIB_LIBS)

noinst_PROGRAMS =		\
	get			\
	simple-httpd		\
	simple-proxy
