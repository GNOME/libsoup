## Process this file with automake to produce Makefile.in
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = libsoup po tests examples docs win32

EXTRA_DIST =				\
	libsoup-2.4.pc.in		\
	libsoup-gnome-2.4.pc.in		\
	gtk-doc.make			\
	libsoup-zip.in			\
	glib-tap.mk			\
	tap-driver.sh			\
	tap-test			\
	Makefile.glib			\
	meson.build			\
	meson_options.txt		\
	get_apache_module_dirs.py	\
	config.h.win32

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --enable-introspection --disable-vala

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = libsoup-2.4.pc

if BUILD_LIBSOUP_GNOME
pkgconfig_DATA += libsoup-gnome-2.4.pc
endif

@CODE_COVERAGE_RULES@
