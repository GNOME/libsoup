## Process this file with automake to produce Makefile.in

SUBDIRS = src tests

EXTRA_DIST = autogen.sh soupConf.sh.in soup.pc.in soup.spec.in

bin_SCRIPTS = soup-config

soupConf.sh: $(top_srcdir)/soupConf.sh.in Makefile
	sed -e 's?\@SOUP_LIBDIR\@?$(SOUP_LIBDIR)?g' \
	    -e 's?\@SOUP_INCLUDEDIR\@?$(SOUP_INCLUDEDIR)?g' \
	    -e 's?\@VERSION\@?$(VERSION)?g' \
	    -e 's?\@SOUP_LIBS\@?$(SOUP_LIBS)?g' \
	      < $(top_srcdir)/soupConf.sh.in > soupConf.tmp \
	  && mv soupConf.tmp soupConf.sh

confexecdir = $(libdir)
confexec_DATA = soupConf.sh

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = soup.pc

dist-hook: soup.spec
	cp soup.spec $(distdir)

rpms: distcheck
	rpm -ta $(top_builddir)/@PACKAGE@-@VERSION@.tar.gz

CLEANFILES = soupConf.sh
