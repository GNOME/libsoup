# NMake Makefile to build Introspection Files for Pango

!include detectenv-msvc.mak

APIVERSION = 2.4

CHECK_PACKAGE = gio-2.0

!include introspection-msvc.mak

!if "$(BUILD_INTROSPECTION)" == "TRUE"

INTROSPECTION_TARGETS = Soup-$(APIVERSION).gir Soup-$(APIVERSION).typelib SoupGNOME-$(APIVERSION).gir SoupGNOME-$(APIVERSION).typelib

all: setbuildenv $(INTROSPECTION_TARGETS)

install-introspection: all
	@-copy Soup-$(APIVERSION).gir $(G_IR_INCLUDEDIR)
	@-copy /b Soup-$(APIVERSION).typelib $(G_IR_TYPELIBDIR)
	@-copy SoupGNOME-$(APIVERSION).gir $(G_IR_INCLUDEDIR)
	@-copy /b SoupGNOME-$(APIVERSION).typelib $(G_IR_TYPELIBDIR)

setbuildenv:
	@set PYTHONPATH=$(PREFIX)\lib\gobject-introspection
	@set PATH=vs$(VSVER)\$(CFG)\$(PLAT)\bin;$(PREFIX)\bin;$(PATH)
	@set PKG_CONFIG_PATH=$(PKG_CONFIG_PATH)
	@set LIB=vs$(VSVER)\$(CFG)\$(PLAT)\bin;$(PREFIX)\lib;$(LIB)

!include introspection.body.mak

!else
all:
	@-echo $(ERROR_MSG)
!endif

clean:
	@-del /f/q $(INTROSPECTION_TARGETS)
