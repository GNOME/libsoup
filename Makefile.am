## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

SUBDIRS = libsoup tests docs

EXTRA_DIST = libsoup-$(SOUP_API_VERSION).pc.in gtk-doc.make

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsoup-$(SOUP_API_VERSION).pc

