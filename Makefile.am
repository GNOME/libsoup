## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

SUBDIRS = libsoup tests docs

EXTRA_DIST = libsoup.pc.in gtk-doc.make

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

pkgconfigdir = $(libdir)/pkgconfig

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkgconfigdir)
	$(INSTALL) libsoup.pc $(DESTDIR)$(pkgconfigdir)/libsoup-$(SOUP_API_VERSION).pc

