## Process this file with automake to produce Makefile.in

# This file mostly lifted from glib

# The name of the module.
DOC_MODULE=soup

# The top-level SGML file.
DOC_MAIN_SGML_FILE=soup-docs.sgml

# The directory containing the source code. Relative to $(srcdir)
DOC_SOURCE_DIR=../../src

# Extra options to supply to gtkdoc-scan
SCAN_OPTIONS=--deprecated-guards="G_DISABLE_DEPRECATED"

# Extra options to supply to gtkdoc-mkdb
MKDB_OPTIONS=

# Extra options to supply to gtkdoc-fixxref
FIXXREF_OPTIONS=

# Used for dependencies
HFILE_GLOB=$(shell find $(top_srcdir) -name '*.h' -print)
CFILE_GLOB=$(shell find $(top_srcdir) -name '*.c' -print)

# Headers to ignore
IGNORE_HFILES=			\
	soup-private.h		\
	#

# Extra files to add when scanning
EXTRA_HFILES=

# Images to copy into HTML directory
HTML_IMAGES =  				\
	#

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE)
content_files =				\
	#

# Other files to distribute
extra_files =				\
	#

####################################
# Everything below here is generic #
####################################

TARGET_DIR=$(HTML_DIR)/$(DOC_MODULE)

EXTRA_DIST = 				\
	$(content_files)		\
	$(extra_files)			\
	$(HTML_IMAGES)			\
	$(DOC_MAIN_SGML_FILE)		\
	$(DOC_MODULE)-sections.txt	\
	#

DOC_STAMPS=				\
	scan-build.stamp		\
	tmpl-build.stamp		\
	sgml-build.stamp		\
	html-build.stamp		\
	$(srcdir)/tmpl.stamp		\
	$(srcdir)/sgml.stamp		\
	$(srcdir)/html.stamp		\
	#

if ENABLE_GTK_DOC
all-local: html-build.stamp

#### scan ####

scan-build.stamp: $(HFILE_GLOB)
	@echo '*** Scanning header files ***'
	cd $(srcdir) && \
	  gtkdoc-scan --module=$(DOC_MODULE) --source-dir=$(DOC_SOURCE_DIR) --ignore-headers="$(IGNORE_HFILES)" $(SCAN_OPTIONS) $(EXTRA_HFILES)
	touch scan-build.stamp

$(srcdir)/$(DOC_MODULE)-decl.txt: scan-build.stamp
	@true

#### templates ####

tmpl-build.stamp: $(srcdir)/$(DOC_MODULE)-decl.txt $(srcdir)/$(DOC_MODULE)-sections.txt
	@echo '*** Rebuilding template files ***'
	cd $(srcdir) && gtkdoc-mktmpl --module=$(DOC_MODULE)
	touch tmpl-build.stamp

$(srcdir)/tmpl.stamp: tmpl-build.stamp
	@true

#### sgml ####

sgml-build.stamp: $(srcdir)/tmpl.stamp $(CFILE_GLOB)
	@echo '*** Building SGML ***'
	cd $(srcdir) && \
	gtkdoc-mkdb --module=$(DOC_MODULE) --source-dir=$(DOC_SOURCE_DIR) $(MKDB_OPTIONS)
	touch sgml-build.stamp

$(srcdir)/sgml.stamp: sgml-build.stamp
	@true

#### html ####

html-build.stamp: $(srcdir)/sgml.stamp $(srcdir)/$(DOC_MAIN_SGML_FILE) $(content_files)
	@echo '*** Building HTML ***'
	test -d $(srcdir)/html || mkdir $(srcdir)/html
	cd $(srcdir)/html && gtkdoc-mkhtml $(DOC_MODULE) ../$(DOC_MAIN_SGML_FILE)
	test "x$(HTML_IMAGES)" = "x" || ( cd $(srcdir) && cp $(HTML_IMAGES) html )
	@echo '-- Fixing Crossreferences' 
	cd $(srcdir) && gtkdoc-fixxref --module-dir=html --html-dir=$(HTML_DIR) $(FIXXREF_OPTIONS)
	touch html-build.stamp
endif

##############

clean-local:
	rm -f *~ *.bak *-unused.txt $(DOC_STAMPS)

maintainer-clean-local: clean
	cd $(srcdir) && rm -rf tmpl sgml html $(DOC_MODULE)-decl-list.txt $(DOC_MODULE)-decl.txt $(DOC_MODULE)-unused.txt $(DOC_MODULE)-undocumented.txt

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(TARGET_DIR)
	(installfiles=`echo $(srcdir)/html/*.html`; \
	if test "$$installfiles" = '$(srcdir)/html/*.html'; \
	then echo '-- Nothing to install' ; \
	else \
	  for i in $$installfiles; do \
	    echo '-- Installing '$$i ; \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(TARGET_DIR); \
	  done; \
	  echo '-- Installing $(srcdir)/html/index.sgml' ; \
	  $(INSTALL_DATA) $(srcdir)/html/index.sgml $(DESTDIR)$(TARGET_DIR); \
	fi)

#
# Require gtk-doc when making dist
#
if ENABLE_GTK_DOC
dist-check-gtkdoc:
else
dist-check-gtkdoc:
	@echo "*** gtk-doc must be installed and enabled in order to make dist"
	@false
endif

dist-hook: dist-check-gtkdoc dist-hook-local

.PHONY : dist-hook-local
