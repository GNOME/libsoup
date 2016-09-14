## Process this file with automake to produce Makefile.in

EXTRA_DIST =
CLEANFILES =


include $(GLIB_MAKEFILE)

if OS_WIN32
LIBWS2_32 = -lws2_32
endif

SOUP_COMMON_CPPFLAGS =			\
	-DG_LOG_DOMAIN=\"libsoup\"	\
	-DLIBSOUP_COMPILATION

AM_CPPFLAGS = 				\
	$(SOUP_COMMON_CPPFLAGS)		\
	-DLOCALEDIR=\"$(localedir)\"	\
	-I$(top_srcdir)			\
	-I$(top_builddir)		\
	$(SOUP_DEBUG_FLAGS)		\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(SQLITE_CFLAGS)		\
	$(CODE_COVERAGE_CFLAGS)		\
	$(KRB5_CFLAGS)

libsoupincludedir = $(includedir)/libsoup-2.4/libsoup

soup_headers =			\
	soup.h			\
	soup-address.h		\
	soup-auth.h		\
	soup-auth-domain.h	\
	soup-auth-domain-basic.h  \
	soup-auth-domain-digest.h \
	soup-auth-manager.h	\
	soup-autocleanups.h	\
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
	soup-xmlrpc.h		\
	soup-xmlrpc-old.h

libsoupinclude_HEADERS =	\
	$(soup_headers)		\
	soup-enum-types.h

nodist_libsoupinclude_HEADERS =	\
	soup-version.h

lib_LTLIBRARIES = libsoup-2.4.la

libsoup_2_4_la_CFLAGS = $(AM_CFLAGS) $(SOUP_HIDDEN_VISIBILITY_CFLAGS)

libsoup_2_4_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE) \
	-no-undefined \
	-export-dynamic \
	$(CODE_COVERAGE_LDFLAGS)

libsoup_2_4_la_LIBADD =			\
	$(GLIB_LIBS)			\
	$(LIBWS2_32)			\
	$(XML_LIBS)			\
	$(SQLITE_LIBS)			\
	$(KRB5_LIBS)

libsoup_2_4_la_SOURCES =		\
	gconstructor.h			\
	soup-address.c			\
	soup-auth.c			\
	soup-auth-basic.h		\
	soup-auth-basic.c		\
	soup-auth-digest.h		\
	soup-auth-digest.c		\
	soup-auth-ntlm.h		\
	soup-auth-ntlm.c		\
	soup-auth-negotiate.h		\
	soup-auth-negotiate.c		\
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
	soup-init.c			\
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
	soup-xmlrpc.c			\
	soup-xmlrpc-old.c

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

libsoup_gnome_2_4_la_CFLAGS = $(AM_CFLAGS) $(SOUP_HIDDEN_VISIBILITY_CFLAGS)

libsoup_gnome_2_4_la_LDFLAGS =	\
	-version-info $(SOUP_CURRENT):$(SOUP_REVISION):$(SOUP_AGE) \
	-no-undefined \
	-export-dynamic

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
soup_enum_types_MKENUMS_H_FLAGS = --fhead "\#include <libsoup/soup-version.h>\n\#define GLIB_MKENUMS_EXTERN _SOUP_EXTERN\n"

#
# Introspection support
#
include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=.

if HAVE_INTROSPECTION

SOUP_UNSTABLE_REQUEST_CFLAG = -DLIBSOUP_USE_UNSTABLE_REQUEST_API

# Core library
gi_soup_files = \
	$(filter-out soup.h soup-enum-types.% soup-proxy-resolver.h,\
	   $(soup_headers) $(filter-out %.h, $(libsoup_2_4_la_SOURCES)))
gi_built_soup_files = soup-enum-types.h soup-version.h

Soup-2.4.gir: libsoup-2.4.la
Soup_2_4_gir_INCLUDES = Gio-2.0
Soup_2_4_gir_CFLAGS = $(AM_CPPFLAGS) $(SOUP_UNSTABLE_REQUEST_CFLAG)
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
libsoup-2.4.vapi: Soup-2.4.gir Soup-2.4.metadata Soup-2.4-custom.vala
	$(VAPIGEN) --metadatadir=$(top_srcdir)/libsoup --pkg gio-2.0 --library=libsoup-2.4 $^

vapidir=$(VAPIDIR)
vapi_DATA=libsoup-2.4.vapi libsoup-2.4.deps
CLEANFILES += libsoup-2.4.vapi
endif

EXTRA_DIST += Soup-2.4.metadata Soup-2.4-custom.vala libsoup-2.4.deps

if BUILD_LIBSOUP_GNOME

SOUPGNOME_GIR_SCANNER_BASE_FLAGS =	\
	--identifier-prefix=Soup	\
	--symbol-prefix=soup

# GNOME extensions
gi_soup_gnome_files = $(filter-out soup-gnome.h,\
		          $(libsoupgnomeinclude_HEADERS) \
	                  $(filter-out %.h, $(libsoup_gnome_2_4_la_SOURCES)))
SoupGNOME-2.4.gir: libsoup-gnome-2.4.la Soup-2.4.gir
SoupGNOME_2_4_gir_SCANNERFLAGS =			\
	$(SOUPGNOME_GIR_SCANNER_BASE_FLAGS)		\
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

CLEANFILES+= $(gir_DATA) $(typelib_DATA) $(BUILT_SOURCES)

endif

# ------ MSVC Project File Generation ------
MSVCPROJS = soup soup-gnome

soup_FILES = $(libsoup_2_4_la_SOURCES)
soup_EXCLUDES = dummy

soup_HEADERS_DIR = $(libsoupincludedir)
soup_HEADERS_INST = $(libsoupinclude_HEADERS) $(nodist_libsoupinclude_HEADERS)
soup_HEADERS_EXCLUDES = dummy

soup_gnome_FILES = $(libsoup_gnome_2_4_la_SOURCES)
soup_gnome_EXCLUDES = dummy

soup_gnome_HEADERS_DIR = $(libsoupgnomeincludedir)
soup_gnome_HEADERS_INST = $(libsoupgnomeinclude_HEADERS)
soup_gnome_HEADERS_EXCLUDES = dummy

include $(top_srcdir)/build/Makefile.msvcproj

if HAVE_INTROSPECTION
# Introspection Items for MSVC
MSVC_INTROSPECT_GIRS = Soup-2.4.gir
if BUILD_LIBSOUP_GNOME
MSVC_INTROSPECT_GIRS += SoupGNOME-2.4.gir
endif

BASE_MSVC_GIR_CFLAGS =		\
	$(SOUP_COMMON_CPPFLAGS)	\
	-I../..

INTROSPECTION_INTERMEDIATE_ITEMS = 					\
	$(top_builddir)/build/win32/Soup-2.4.gir.msvc.introspect	\
	$(top_builddir)/build/win32/Soup_2_4_gir_list			\
	$(top_builddir)/build/win32/SoupGNOME-2.4.gir.msvc.introspect	\
	$(top_builddir)/build/win32/SoupGNOME_2_4_gir_list

# libsoup
Soup_2_4_gir_MSVC_FILES = $(gi_soup_files) $(gi_built_soup_files)
Soup_2_4_gir_MSVC_EXPORT_PACKAGES = $(Soup_2_4_gir_EXPORT_PACKAGES)
Soup_2_4_gir_MSVC_INCLUDE_GIRS = $(Soup_2_4_gir_INCLUDES)
Soup_2_4_gir_MSVC_LIBS = soup-2.4
Soup_2_4_gir_MSVC_CFLAGS =  $(BASE_MSVC_GIR_CFLAGS) $(SOUP_UNSTABLE_REQUEST_CFLAG)
Soup_2_4_gir_MSVC_SCANNERFLAGS = --c-include \"libsoup/soup.h\"

if BUILD_LIBSOUP_GNOME
# libsoup-gnome
SoupGNOME_2_4_gir_MSVC_FILES = $(gi_soup_gnome_files)
SoupGNOME_2_4_gir_MSVC_GIR_DEPS = Soup-2.4.gir
SoupGNOME_2_4_gir_MSVC_EXPORT_PACKAGES = $(SoupGNOME_2_4_gir_EXPORT_PACKAGES)
SoupGNOME_2_4_gir_MSVC_LIBS = soup-gnome-2.4 soup-2.4
SoupGNOME_2_4_gir_MSVC_CFLAGS = $(BASE_MSVC_GIR_CFLAGS)
SoupGNOME_2_4_gir_MSVC_SCANNERFLAGS =	i	\
	$(SOUPGNOME_GIR_SCANNER_BASE_FLAGS)	\
	 --c-include \"libsoup/soup-gnome.h\"	\
	--include-uninstalled=./Soup-2.4.gir
endif

include $(top_srcdir)/build/Makefile.msvc-introspection
else
INTROSPECTION_INTERMEDIATE_ITEMS =
endif

dist-hook: \
	$(top_builddir)/build/win32/vs9/soup.vcproj		\
	$(top_builddir)/build/win32/vs9/soup.headers		\
	$(top_builddir)/build/win32/vs9/soup-gnome.vcproj	\
	$(top_builddir)/build/win32/vs9/soup-gnome.headers	\
	$(INTROSPECTION_INTERMEDIATE_ITEMS)
