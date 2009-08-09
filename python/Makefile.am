AUTOMAKE_OPTIONS=1.5
ACLOCAL_AMFLAGS=-I m4

INCLUDES =			\
	$(PYTHON_INCLUDES)	\
	$(PYGOBJECT_CFLAGS)	\
	$(SOUP_CFLAGS)

noinst_LTLIBRARIES = soup.la
soup_la_LDFLAGS = -module -avoid-version -export-symbols-regex initsoup
soup_la_LIBADD = $(SOUP_LIBS)
soup_la_SOURCES = libsoupmodule.c
nodist_soup_la_SOURCES = libsoup.c
libsoup.c: libsoup.defs *.override
CLEANFILES = libsoup.c
EXTRA_DIST = *.override

.defs.c:
	(cd $(srcdir)\
	 && pygtk-codegen-2.0 \
		--register $(GIO_DEFS) \
		--override $*.override \
		--prefix py$* $*.defs) > gen-$*.c \
	&& cp gen-$*.c $*.c \
	&& rm -f gen-$*.c
