GENERATED_ITEMS = \
	soup.vcproj		\
	soup-gnome.vcproj	\
	soup-install.vsprops

MSVC_HEADERS_LIST = soup.headers soup-gnome.headers

EXTRA_DIST = \
	libsoup.sln			\
	get.vcproj			\
	simple-httpd.vcproj		\
	simple-proxy.vcproj		\
	soup-install.vcproj		\
	soup-build-defines.vsprops	\
	soup-dll-build-defines.vsprops	\
	soup-gen-srcs.vsprops		\
	soup-version-paths.vsprops	\
	soup.vcprojin			\
	soup-gnome.vcprojin		\
	soup-install.vspropsin		\
	$(GENERATED_ITEMS)

soup-install.vsprops: $(top_srcdir)/build/win32/vs9/soup-install.vspropsin $(MSVC_HEADERS_LIST)
	$(CPP) -P - <$(top_srcdir)/build/win32/vs9/soup-install.vspropsin >$@
	rm $(MSVC_HEADERS_LIST)

DISTCLEANFILES = $(GENERATED_ITEMS)
