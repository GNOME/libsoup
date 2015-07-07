## Process this file with automake to produce Makefile.in

EXTRA_DIST =

include $(GLIB_MAKEFILE)

if OS_WIN32
LIBWS2_32 = -lws2_32
endif

AM_CPPFLAGS = 				\
	-DG_LOG_DOMAIN=\"libsoup\" 	\
	-DLOCALEDIR=\"$(localedir)\"	\
	-I$(top_srcdir)			\
	-I$(top_builddir)		\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(SQLITE_CFLAGS)		\
	$(CODE_COVERAGE_CFLAGS)

libsoupincludedir = $(includedir)/libsoup-2.4/libsoup

soup_headers =			\
	soup.h			\
	soup-address.h		\
	soup-auth.h		\
	soup-auth-domain.h	\
	soup-auth-domain-basic.h  \
	soup-auth-domain-digest.h \
	soup-auth-manager.h	\
	soup-cache.h		\
	soup-content-decoder.h	\
	soup-content-sniffer.h	\
	soup-cookie.h		\
	soup-cookie-jar.h	\
	soup-cookie-jar-db.h	\
	soup-cookie-jar-text.h	\
	soup-date.h		\
	soup-form.h		\
	soup-headers.h		\
	soup-logger.h		\
	soup-message.h		\
	soup-message-body.h	\
	soup-message-headers.h	\
	soup-method.h		\
	soup-misc.h     	\
	soup-multipart.h     	\
	soup-multipart-input-stream.h \
	soup-password-manager.h	\
	soup-portability.h	\
	soup-proxy-resolver.h	\
	soup-proxy-resolver-default.h	\
	soup-proxy-uri-resolver.h \
	soup-request.h		\
	soup-request-data.h	\
	soup-request-file.h	\
	soup-request-http.h	\
	soup-requester.h	\
	soup-server.h		\
	soup-session.h		\
	soup-session-async.h	\
	soup-session-feature.h	\
	soup-session-sync.h	\
	soup-socket.h		\
	soup-status.h		\
	soup-tld.h		\
	soup-types.h		\
	soup-uri.h		\
	soup-value-utils.h	\
	soup-websocket.h	\
	soup-websocket-connection.h	\
	soup-xmlrpc.h

libsoupinclude_HEADERS =	\
	$(soup_headers)		\
	soup-enum-types.h

nodist_libsoupinclude_HEADERS =	\
	soup-version.h

lib_LTLIBRARIES = libsoup-2.4.la

libsoup_2_4_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE) \
	-no-undefined \
	-export-symbols $(srcdir)/libsoup-2.4.sym \
	$(CODE_COVERAGE_LDFLAGS)

EXTRA_DIST += libsoup-2.4.sym

libsoup_2_4_la_LIBADD =			\
	$(GLIB_LIBS)			\
	$(LIBWS2_32)			\
	$(XML_LIBS)			\
	$(SQLITE_LIBS)

libsoup_2_4_la_SOURCES =		\
	soup-address.c			\
	soup-auth.c			\
	soup-auth-basic.h		\
	soup-auth-basic.c		\
	soup-auth-digest.h		\
	soup-auth-digest.c		\
	soup-auth-ntlm.h		\
	soup-auth-ntlm.c		\
	soup-auth-domain.c		\
	soup-auth-domain-basic.c	\
	soup-auth-domain-digest.c	\
	soup-auth-manager.c		\
	soup-body-input-stream.h	\
	soup-body-input-stream.c	\
	soup-body-output-stream.h	\
	soup-body-output-stream.c	\
	soup-cache.c			\
	soup-cache-client-input-stream.h\
	soup-cache-client-input-stream.c\
	soup-cache-input-stream.h	\
	soup-cache-input-stream.c	\
	soup-cache-private.h		\
	soup-client-input-stream.h	\
	soup-client-input-stream.c	\
	soup-connection.h		\
	soup-connection.c		\
	soup-connection-auth.h		\
	soup-connection-auth.c		\
	soup-content-decoder.c		\
	soup-content-processor.h	\
	soup-content-processor.c	\
	soup-content-sniffer.c		\
	soup-content-sniffer-stream.h	\
	soup-content-sniffer-stream.c	\
	soup-converter-wrapper.h	\
	soup-converter-wrapper.c	\
	soup-cookie.c			\
	soup-cookie-jar.c		\
	soup-cookie-jar-db.c		\
	soup-cookie-jar-text.c		\
	soup-date.c			\
	soup-directory-input-stream.h	\
	soup-directory-input-stream.c	\
	soup-enum-types.h		\
	soup-enum-types.c		\
	soup-filter-input-stream.c	\
	soup-filter-input-stream.h	\
	soup-form.c			\
	soup-headers.c			\
	soup-io-stream.h		\
	soup-io-stream.c		\
	soup-logger.c			\
	soup-message.c			\
	soup-message-body.c		\
	soup-message-client-io.c	\
	soup-message-headers.c		\
	soup-message-io.c		\
	soup-message-private.h		\
	soup-message-queue.h		\
	soup-message-queue.c		\
	soup-message-server-io.c	\
	soup-method.c     		\
	soup-misc.c     		\
	soup-misc-private.h		\
	soup-multipart.c	     	\
	soup-multipart-input-stream.c	\
	soup-password-manager.c		\
	soup-path-map.h     		\
	soup-path-map.c     		\
	soup-proxy-resolver.c		\
	soup-proxy-resolver-default.c	\
	soup-proxy-resolver-wrapper.h	\
	soup-proxy-resolver-wrapper.c	\
	soup-proxy-uri-resolver.c	\
	soup-request.c			\
	soup-request-data.c		\
	soup-request-file.c		\
	soup-request-http.c		\
	soup-requester.c		\
	soup-server.c			\
	soup-session.c			\
	soup-session-async.c		\
	soup-session-feature.c		\
	soup-session-private.h		\
	soup-session-sync.c		\
	soup-socket.c			\
	soup-socket-private.h		\
	soup-socket-properties.c	\
	soup-status.c			\
	soup-tld.c			\
	soup-tld-private.h		\
	soup-uri.c			\
	soup-value-utils.c		\
	soup-version.c			\
	soup-websocket.c		\
	soup-websocket-connection.c	\
	soup-xmlrpc.c

# TLD rules
EXTRA_DIST += tld-parser.py

TLD_DATA_FILE=$(top_srcdir)/data/effective_tld_names.dat

tld_data.inc: tld-parser.py $(TLD_DATA_FILE)
	$(srcdir)/tld-parser.py $(TLD_DATA_FILE) tld_data.inc

if BUILD_LIBSOUP_GNOME

libsoupgnomeincludedir = $(includedir)/libsoup-gnome-2.4/libsoup

libsoupgnomeinclude_HEADERS =	\
	soup-cookie-jar-sqlite.h\
	soup-gnome.h		\
	soup-gnome-features.h

lib_LTLIBRARIES += libsoup-gnome-2.4.la

libsoup_gnome_2_4_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE) \
	-no-undefined \
	-export-symbols $(srcdir)/libsoup-gnome-2.4.sym

EXTRA_DIST += libsoup-gnome-2.4.sym

libsoup_gnome_2_4_la_LIBADD =		\
	libsoup-2.4.la			\
	$(GLIB_LIBS)

libsoup_gnome_2_4_la_SOURCES =		\
	soup-cookie-jar-sqlite.c	\
	soup-gnome-features.c		\
	soup-proxy-resolver-gnome.h	\
	soup-proxy-resolver-gnome.c	\
	soup-password-manager-gnome.h	\
	soup-password-manager-gnome.c

endif

GLIB_GENERATED = soup-enum-types.c soup-enum-types.h
BUILT_SOURCES = \
	$(GLIB_GENERATED)   \
	tld_data.inc

soup_enum_types_sources = $(libsoupinclude_HEADERS) $(libsoupgnomeinclude_HEADERS)
soup_enum_types_MKENUMS_C_FLAGS = --fhead "\#define LIBSOUP_USE_UNSTABLE_REQUEST_API"

#
# Introspection support
#
include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=.

if HAVE_INTROSPECTION

# Core library
gi_soup_files = \
	$(filter-out soup.h soup-enum-types.% soup-proxy-resolver.h,\
	   $(soup_headers) $(filter-out %.h, $(libsoup_2_4_la_SOURCES)))
gi_built_soup_files = soup-enum-types.h

Soup-2.4.gir: libsoup-2.4.la
Soup_2_4_gir_INCLUDES = Gio-2.0
Soup_2_4_gir_CFLAGS = $(AM_CPPFLAGS) -DLIBSOUP_USE_UNSTABLE_REQUEST_API
Soup_2_4_gir_LIBS = libsoup-2.4.la
Soup_2_4_gir_EXPORT_PACKAGES = libsoup-2.4
Soup_2_4_gir_SCANNERFLAGS = --c-include "libsoup/soup.h"
Soup_2_4_gir_FILES = \
	$(addprefix $(srcdir)/, $(gi_soup_files)) \
        $(foreach f,$(gi_built_soup_files), \
	   $(if $(shell test -f $(addprefix $(srcdir)/,$(f)) && echo yes), \
	      $(addprefix $(srcdir)/,$(f)), \
	      $(f)))

INTROSPECTION_GIRS += Soup-2.4.gir

if ENABLE_VAPIGEN
libsoup-2.4.vapi: Soup-2.4.gir Soup-2.4.metadata
	$(VAPIGEN) --metadatadir=$(top_srcdir)/libsoup --pkg gio-2.0 --library=libsoup-2.4 $^

vapidir=$(VAPIDIR)
vapi_DATA=libsoup-2.4.vapi
CLEANFILES += $(vapi_DATA)
endif

if BUILD_LIBSOUP_GNOME

# GNOME extensions
gi_soup_gnome_files = $(filter-out soup-gnome.h,\
		          $(libsoupgnomeinclude_HEADERS) \
	                  $(filter-out %.h, $(libsoup_gnome_2_4_la_SOURCES)))
SoupGNOME-2.4.gir: libsoup-gnome-2.4.la Soup-2.4.gir
SoupGNOME_2_4_gir_SCANNERFLAGS =			\
	--identifier-prefix=Soup			\
	--symbol-prefix=soup				\
	--c-include "libsoup/soup-gnome.h"		\
	--include-uninstalled=$(builddir)/Soup-2.4.gir
SoupGNOME_2_4_gir_CFLAGS = $(AM_CPPFLAGS)
SoupGNOME_2_4_gir_LIBS = libsoup-gnome-2.4.la libsoup-2.4.la
SoupGNOME_2_4_gir_FILES = $(addprefix $(srcdir)/,$(gi_soup_gnome_files))
SoupGNOME_2_4_gir_EXPORT_PACKAGES = libsoup-gnome-2.4

INTROSPECTION_GIRS += SoupGNOME-2.4.gir

endif

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES = $(gir_DATA) $(typelib_DATA) $(BUILT_SOURCES)

endif

# We only do this check on Linux, so we don't have to worry about
# different "nm" output on other platforms
if OS_LINUX
check-local:
	@echo Checking libsoup-2.4.so symbols
	@nm $(builddir)/.libs/libsoup-2.4.so | \
		grep "^[[:xdigit:]]\+ [BGTRS] " | \
		sed "s/^[[:xdigit:]]\+ [BGTRS] //" | \
		env LC_ALL=C sort -u | \
		diff -U0 $(srcdir)/libsoup-2.4.sym - >&2
endif
