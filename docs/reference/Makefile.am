## Process this file with automake to produce Makefile.in
AUTOMAKE_OPTIONS = 1.6

# The name of the module
DOC_MODULE=libsoup

# The top-level SGML file.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.sgml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting functions and macros.
DOC_SOURCE_DIR=../../libsoup

# Extra options to supply to gtkdoc-scan.
SCAN_OPTIONS=

# Extra options to supply to gtkdoc-mkdb.
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-fixref.
FIXXREF_OPTIONS=

# Used for dependencies.
HFILE_GLOB=
CFILE_GLOB=

# Header files to ignore when scanning.
IGNORE_HFILES= soup.h soup-marshal.h soup-types.h

# Images to copy into HTML directory.
HTML_IMAGES = 

# Extra XML files that are included by $(DOC_MAIN_SGML_FILE).
content_files = 

# Other files to distribute.
extra_files =


# CFLAGS and LDFLAGS for compiling scan program. Only needed
# if $(DOC_MODULE).types is non-empty.
GTKDOC_CFLAGS =				\
	-I$(top_srcdir)			\
	$(GLIB_CFLAGS)			\
	$(XML_CFLAGS)			\
	$(GNUTLS_CFLAGS)

GTKDOC_LIBS = $(top_builddir)/libsoup/libsoup-$(SOUP_API_VERSION).la


# If you need to override some of the declarations, place them in the
# $(DOC_MODULE)-overrides.txt file and uncomment the second line here.
DOC_OVERRIDES =
#DOC_OVERRIDES = $(DOC_MODULE)-overrides.txt


# include common portion ...
include $(top_srcdir)/gtk-doc.make

