GENERATED_ITEMS = \
	soup.vcxproj			\
	soup-gnome.vcxproj		\
	soup.vcxproj.filters		\
	soup-gnome.vcxproj.filters	\
	soup-install.props

MSVC_HEADERS_LIST = soup.vs10.headers soup-gnome.vs10.headers

EXTRA_DIST = \
	libsoup.sln			\
	get.vcxproj			\
	simple-httpd.vcxproj		\
	simple-proxy.vcxproj		\
	soup-install.vcxproj		\
	soup-install.vcxproj.filters	\
	get.vcxproj.filters		\
	simple-httpd.vcxproj.filters	\
	simple-proxy.vcxproj.filters	\
	soup-build-defines.props	\
	soup-dll-build-defines.props	\
	soup-gen-srcs.props		\
	soup-version-paths.props	\
	soup.vcxprojin			\
	soup-gnome.vcxprojin		\
	soup.vcxproj.filtersin		\
	soup-gnome.vcxproj.filtersin	\
	soup-install.propsin		\
	$(GENERATED_ITEMS)

soup-install.props: $(top_srcdir)/win32/vs10/soup-install.propsin $(MSVC_HEADERS_LIST)
	-$(RM) $(top_builddir)/win32/vs11/soup-install.props
	-$(RM) $(top_builddir)/win32/vs12/soup-install.props
	-$(RM) $(top_builddir)/win32/vs14/soup-install.props
	-$(RM) $(top_builddir)/win32/vs15/soup-install.props
	$(CPP) -P - <$(top_srcdir)/win32/vs10/soup-install.propsin >$@
	rm $(MSVC_HEADERS_LIST)

DISTCLEANFILES = $(GENERATED_ITEMS)
