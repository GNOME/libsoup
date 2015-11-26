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

soup-install.props: $(top_srcdir)/build/win32/vs10/soup-install.propsin $(MSVC_HEADERS_LIST)
	$(CPP) -P - <$(top_srcdir)/build/win32/vs10/soup-install.propsin >$@
	rm $(MSVC_HEADERS_LIST)

DISTCLEANFILES = $(GENERATED_ITEMS)
