## Process this file with automake to produce Makefile.in

SUBDIRS = src docs

# I want to include tests in the distributed version, but that requires
# some automake deep magic to stop it trying to include generated files in
# the automated dependency logic. (hint: OMIT_DEPENDENCIES did SFA)
#DIST_SUBDIRS = $(SUBDIRS) tests

EXTRA_DIST = 			\
	autogen.sh 		\
	soupConf.sh.in 		\
	soup_apacheConf.sh.in 	\
	soup_wsdlConf.sh.in 	\
	soup.m4			\
	soup.pc.in 		\
	soup.spec.in

bin_SCRIPTS = soup-config

soupConf.sh: $(top_srcdir)/soupConf.sh.in Makefile
	sed -e 's?\@SOUP_LIBDIR\@?$(SOUP_LIBDIR)?g' \
	    -e 's?\@SOUP_INCLUDEDIR\@?$(SOUP_INCLUDEDIR)?g' \
	    -e 's?\@VERSION\@?$(VERSION)?g' \
	    -e 's?\@SOUP_LIBS\@?$(SOUP_LIBS)?g' \
	      < $(top_srcdir)/soupConf.sh.in > soupConf.tmp \
	  && mv soupConf.tmp soupConf.sh

soup_apacheConf.sh: $(top_srcdir)/soup_apacheConf.sh.in Makefile
	sed -e 's?\@SOUP_APACHE_LIBDIR\@?$(SOUP_APACHE_LIBDIR)?g' \
	    -e 's?\@SOUP_APACHE_INCLUDEDIR\@?$(SOUP_APACHE_INCLUDEDIR)?g' \
	    -e 's?\@VERSION\@?$(VERSION)?g' \
	    -e 's?\@SOUP_APACHE_LIBS\@?$(SOUP_APACHE_LIBS)?g' \
	      < $(top_srcdir)/soup_apacheConf.sh.in > soup_apacheConf.tmp \
	  && mv soup_apacheConf.tmp soup_apacheConf.sh

soup_wsdlConf.sh: $(top_srcdir)/soup_wsdlConf.sh.in Makefile
	sed -e 's?\@SOUP_WSDL_LIBDIR\@?$(SOUP_WSDL_LIBDIR)?g' \
	    -e 's?\@SOUP_WSDL_INCLUDEDIR\@?$(SOUP_WSDL_INCLUDEDIR)?g' \
	    -e 's?\@VERSION\@?$(VERSION)?g' \
	    -e 's?\@SOUP_WSDL_LIBS\@?$(SOUP_WSDL_LIBS)?g' \
	      < $(top_srcdir)/soup_wsdlConf.sh.in > soup_wsdlConf.tmp \
	  && mv soup_wsdlConf.tmp soup_wsdlConf.sh

confexecdir = $(libdir)
confexec_DATA = soupConf.sh soup_apacheConf.sh soup_wsdlConf.sh

m4datadir = $(datadir)/aclocal
m4data_DATA = soup.m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = soup.pc

examples:
	$(MAKE) -C tests

dist-hook: soup.spec
	cp soup.spec $(distdir)

rpms: distcheck
	rpm -ta $(top_builddir)/@PACKAGE@-@VERSION@.tar.gz

CLEANFILES = soupConf.sh soup_apacheConf.sh soup_wsdlConf.sh
