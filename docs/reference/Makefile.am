## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

# The name of the module
DOC_MODULE=libsoup-2.4

# The top-level SGML file.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR=../../libsoup

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=--deprecated-guards=SOUP_DISABLE_DEPRECATED --rebuild-types --ignore-decorators='SOUP_DEPRECATED\w*\s*\([^)]*\)|SOUP_DEPRECATED\w*|SOUP_AVAILABLE\w*'

# Extra options to supply to gtkdoc-scangobj.
SCANGOBJ_OPTIONS=

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=
CFILE_GLOB=

# Header files to ignore when scanning.
IGNORE_HFILES= soup.h soup-marshal.h soup-enum-types.h \
	soup-message-private.h soup-session-private.h \
	soup-auth-basic.h soup-auth-digest.h soup-auth-ntlm.h \
	soup-connection.h soup-connection-auth.h \
	soup-message-queue.h soup-path-map.h soup-gnome-features.h \
	soup-proxy-resolver.h soup-proxy-resolver-gnome.h \
	soup-proxy-resolver-static.h soup-directory-input-stream.h \
	soup-http-input-stream.h soup-password-manager.h \
	soup-password-manager-gnome.h soup-converter-wrapper.h \
	soup-body-input-stream.h soup-body-output-stream.h \
	soup-client-input-stream.h soup-content-processor.h \
	soup-content-sniffer-stream.h soup-io-stream.h \
	soup-cache-input-stream.h soup-filter-input-stream.h \
	soup-cookie-jar-sqlite.h soup-requester.h soup-tld-private.h \
	soup-misc-private.h

# Images to copy into HTML directory.
HTML_IMAGES = 

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files =				\
	build-howto.xml			\
	client-howto.xml		\
	server-howto.xml		\
	session-porting.xml

# Other files to distribute.
extra_files =


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS =				\
	-I$(top_srcdir)			\
	-I$(top_builddir)		\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(GNUTLS_CFLAGS)

GTKDOC_LIBS =						\
	$(top_builddir)/libsoup/libsoup-2.4.la		\
	$(GLIB_LIBS)

# include common portion ...
include $(top_srcdir)/gtk-doc.make

# kludges
$(srcdir)/tmpl/*.sgml:

clean: clean-am
	rm -rf tmpl
