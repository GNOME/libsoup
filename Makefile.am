## Process this file with automake to produce Makefile.in

SUBDIRS = src tests

EXTRA_DIST = autogen.sh soupConf.sh.in soup.pc.in soup.spec.in

bin_SCRIPTS = soup-config

confexecdir = $(libdir)
confexec_DATA = soupConf.sh

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = soup.pc

dist-hook: soup.spec
	cp soup.spec $(distdir)

rpms: distcheck
	rpm -ta $(top_builddir)/@PACKAGE@-@VERSION@.tar.gz
