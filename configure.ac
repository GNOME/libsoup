dnl *******************************************
dnl *** Initialize automake and set version ***
dnl *******************************************

m4_define([soup_major_version], [2])
m4_define([soup_minor_version], [56])
m4_define([soup_micro_version], [0])

AC_PREREQ(2.63)
AC_INIT([libsoup],[soup_major_version.soup_minor_version.soup_micro_version],[http://bugzilla.gnome.org/enter_bug.cgi?product=libsoup])
AC_CONFIG_SRCDIR([libsoup-2.4.pc.in])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.11 foreign no-dist-gzip dist-xz -Wno-portability])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],)

AC_PROG_MAKE_SET

SOUP_MAJOR_VERSION=soup_major_version
SOUP_MINOR_VERSION=soup_minor_version
SOUP_MICRO_VERSION=soup_micro_version
AC_SUBST(SOUP_MAJOR_VERSION)
AC_SUBST(SOUP_MINOR_VERSION)
AC_SUBST(SOUP_MICRO_VERSION)

SOUP_API_VERSION=2.4
AC_SUBST(SOUP_API_VERSION)

# Increment on interface addition. Reset on removal.
SOUP_AGE=8

# Increment on interface add, remove, or change.
SOUP_CURRENT=9

# Increment on source change. Reset when CURRENT changes.
SOUP_REVISION=0

AC_SUBST(SOUP_CURRENT)
AC_SUBST(SOUP_REVISION)
AC_SUBST(SOUP_AGE)

dnl ***************************
dnl *** Set debugging flags ***
dnl ***************************

debug_default=minimum

# Declare --enable-* args and collect ac_help strings
AC_ARG_ENABLE(debug,
	      AS_HELP_STRING([--enable-debug=[no/minimum/yes]],
			     [turn on debugging (default=$debug_default)]),,
	      enable_debug=$debug_default)

# Set the debug flags
if test "x$enable_debug" = "xyes"; then
	test "$cflags_set" = set || CFLAGS="$CFLAGS -g"
	SOUP_DEBUG_FLAGS="-DG_ENABLE_DEBUG"
else
	if test "x$enable_debug" = "xno"; then
		SOUP_DEBUG_FLAGS="-DG_DISABLE_ASSERT -DG_DISABLE_CHECKS"
	fi
fi

AC_SUBST(SOUP_DEBUG_FLAGS)

dnl ***************************
dnl *** Checks for programs ***
dnl ***************************

AC_PROG_CC
AC_PROG_INSTALL

# Initialize libtool
LT_INIT([win32-dll])

dnl ***********************
dnl *** Checks for glib ***
dnl ***********************

GLIB_REQUIRED=2.38.0
AM_PATH_GLIB_2_0($GLIB_REQUIRED,,,gobject gio)
if test "$GLIB_LIBS" = ""; then
   AC_MSG_ERROR(GLIB $GLIB_REQUIRED or later is required to build libsoup)
fi
GLIB_CFLAGS="$GLIB_CFLAGS -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_38"

GLIB_MAKEFILE='$(top_srcdir)/Makefile.glib'
AC_SUBST(GLIB_MAKEFILE)

GLIB_TESTS

PKG_CHECK_MODULES(XML, libxml-2.0)
AC_SUBST(XML_CFLAGS)
AC_SUBST(XML_LIBS)

PKG_CHECK_MODULES(SQLITE, sqlite3)
AC_SUBST(SQLITE_CFLAGS)
AC_SUBST(SQLITE_LIBS)

dnl ***********************
dnl *** Check for Win32 ***
dnl ***********************

AC_MSG_CHECKING([for Win32])
case "$host" in
  *-*-mingw*)
    os_win32=yes
    os_linux=yes
    CFLAGS="$CFLAGS -D_REENTRANT"
    ;;
  *-*-linux*)
    os_win32=no
    os_linux=yes
    ;;
  *)
    os_win32=no
    os_linux=no
    ;;
esac
AC_MSG_RESULT([$os_win32])
AM_CONDITIONAL(OS_WIN32, [test $os_win32 = yes])
AM_CONDITIONAL(OS_LINUX, [test $os_linux = yes])

dnl ************************
dnl *** gettext/intltool ***
dnl ************************
IT_PROG_INTLTOOL([0.35.0])
GETTEXT_PACKAGE=libsoup
AC_SUBST([GETTEXT_PACKAGE])
AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[The gettext domain name])

dnl *******************
dnl *** Misc checks ***
dnl *******************
AC_CHECK_FUNCS(gmtime_r)

dnl *********************
dnl *** GNOME support ***
dnl *********************
AC_MSG_CHECKING(whether to build libsoup-gnome)
AC_ARG_WITH(gnome,
	    AS_HELP_STRING([--without-gnome], [Do not build libsoup-gnome]),
	    :, [if test $os_win32 = yes; then with_gnome=no; else with_gnome=yes; fi])
AC_MSG_RESULT($with_gnome)

AM_CONDITIONAL(BUILD_LIBSOUP_GNOME, test $with_gnome != no)

if test $with_gnome != no; then
	AC_DEFINE(HAVE_GNOME, 1, [Defined if GNOME support is enabled])
fi
AC_SUBST(HAVE_GNOME)


dnl ***************
dnl *** gtk-doc ***
dnl ***************
# gtkdocize greps for ^GTK_DOC_CHECK and parses it, so you need to have
# it on it's own line.
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK([1.20], [--flavour no-tmpl])
],[])

dnl *****************************
dnl *** gobject-introspection ***
dnl *****************************
GOBJECT_INTROSPECTION_CHECK([0.9.5])

if test "$found_introspection" != "yes" -a "$enable_vala" = ""; then
	enable_vala=no
fi
VAPIGEN_CHECK()

AC_MSG_CHECKING([for glib-networking (glib TLS implementation)])
save_CFLAGS="$CFLAGS"
save_LIBS="$LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"
LIBS="$LIBS $GLIB_LIBS"
AC_RUN_IFELSE([AC_LANG_PROGRAM([#include <gio/gio.h>],
			       [return !g_tls_backend_supports_tls (g_tls_backend_get_default ());])],
	      [have_glib_networking=yes],
	      [have_glib_networking=no],
	      [have_glib_networking="unknown (cross-compiling)"])
CFLAGS="$save_CFLAGS"
LIBS="$save_LIBS"
AC_MSG_RESULT($have_glib_networking)

AC_ARG_ENABLE(tls-check,
	      AS_HELP_STRING([--disable-tls-check], [Don't error out if glib-networking is unavailable]))
if test "$enable_tls_check" != "no" -a "$have_glib_networking" = "no"; then
	AC_MSG_ERROR([libsoup requires glib-networking for TLS support.

If you are building a package, you can pass --disable-tls-check to
allow building libsoup anyway (since glib-networking is not actually
required at compile time), but you should be sure to add a runtime
dependency on it.])
fi

dnl ******************************
dnl *** Stuff for regression tests
dnl ******************************
AC_MSG_NOTICE([checking for programs needed for regression tests])

AC_ARG_WITH(apache-httpd,
	    AS_HELP_STRING([--with-apache-httpd], [Path to apache httpd (for tests)]),
	    APACHE_HTTPD="$withval",
	    [AC_PATH_PROGS(APACHE_HTTPD, httpd2 httpd apache2 apache, no, ${PATH}:/usr/sbin)])
if test "$APACHE_HTTPD" != "no"; then
    AC_MSG_CHECKING([Apache version])
    apache_version=`$APACHE_HTTPD -v 2>/dev/null | sed -ne 's/Server version: Apache\///p'`
    case $apache_version in
    2.2.*)
	AC_MSG_RESULT([$apache_version (ok)])
 	apache_version=2.2
	;;
    2.4.*)
	AC_MSG_RESULT([$apache_version (ok)])
 	apache_version=2.4
	;;
    *)
	AC_MSG_RESULT([$apache_version (ignoring)])
	APACHE_HTTPD="no"
	;;
    esac
fi
AC_SUBST(APACHE_HTTPD)
AC_DEFINE_UNQUOTED(APACHE_HTTPD, "$APACHE_HTTPD", [Apache httpd])

if test "$APACHE_HTTPD" != "no"; then
    AC_MSG_CHECKING([for Apache module directory])
    AC_ARG_WITH(apache-module-dir,
		AS_HELP_STRING([--with-apache-module-dir], [Apache modules dirs (for tests)]),
		apache_module_dirs="$withval",
		[apache_prefix=`dirname \`dirname $APACHE_HTTPD\``
		mpm=`$APACHE_HTTPD -V -C "ServerName localhost" | sed -ne 's/^Server MPM: */-/p' | tr 'A-Z' 'a-z'`
		# This only works with bash, but should fail harmlessly in sh
		apache_module_dirs=`echo $apache_prefix/lib{64,}/{apache,apache2,http,http2,httpd}{$mpm,}{/modules,}`])
    for dir in $apache_module_dirs; do
        if test -f $dir/mod_auth_digest.so; then
	    APACHE_MODULE_DIR="$dir"
        fi
        if test -f $dir/mod_ssl.so; then
	    APACHE_SSL_MODULE_DIR="$dir"
	    IF_HAVE_APACHE_SSL=""
        fi
        if test -f $dir/mod_php5.so; then
	    APACHE_PHP_MODULE_DIR="$dir"
	    APACHE_PHP_MODULE=mod_php5.so
        fi
        if test -f $dir/libphp5.so; then
	    APACHE_PHP_MODULE_DIR="$dir"
	    APACHE_PHP_MODULE=libphp5.so
        fi
    done
    AC_MSG_RESULT($APACHE_MODULE_DIR)
    AC_SUBST(APACHE_MODULE_DIR)
    AC_SUBST(APACHE_SSL_MODULE_DIR)
    AC_SUBST(APACHE_PHP_MODULE_DIR)
    AC_SUBST(APACHE_PHP_MODULE)
fi

if test "$APACHE_HTTPD" != "no" -a -n "$APACHE_MODULE_DIR" -a -n "$APACHE_SSL_MODULE_DIR"; then
    AC_DEFINE(HAVE_APACHE, 1, [Whether or not apache can be used for tests])
    if test $apache_version = 2.2; then
        AC_DEFINE(HAVE_APACHE_2_2, 1, [Apache is 2.2.x])
    else
        AC_DEFINE(HAVE_APACHE_2_4, 1, [Apache is 2.4.x])
    fi
    have_apache=1
else
    have_apache=0
fi
AM_CONDITIONAL(HAVE_APACHE, test "$have_apache" = 1)
AM_CONDITIONAL(HAVE_APACHE_2_2, test "$have_apache" = 1 -a "$apache_version" = 2.2)
AM_CONDITIONAL(HAVE_APACHE_2_4, test "$have_apache" = 1 -a "$apache_version" = 2.4)

if test "$have_apache" = 1; then
    AC_CHECK_PROGS(PHP, php php5)

    AC_MSG_CHECKING([for Apache PHP module])
    if test -f $APACHE_PHP_MODULE_DIR/$APACHE_PHP_MODULE; then
	have_php=yes
	IF_HAVE_PHP=""
    else
	have_php=no
	IF_HAVE_PHP="\#"
    fi
    AC_MSG_RESULT($have_php)
    AC_SUBST(IF_HAVE_PHP)

    if test "$have_php" = yes; then
	AC_MSG_CHECKING([for php-xmlrpc])
	if $PHP --rf xmlrpc_server_create | grep -q "does not exist"; then
	    have_php_xmlrpc=no
	else
	    have_php_xmlrpc=yes
	    AC_DEFINE(HAVE_PHP_XMLRPC, 1, [Have php-xmlrpc])
	fi
	AC_MSG_RESULT($have_php_xmlrpc)
    fi
fi

AC_PATH_PROG(CURL, curl, no)
if test "$CURL" != no; then
    AC_DEFINE(HAVE_CURL, 1, [Whether or not curl can be used for tests])
fi

dnl **********************************************************
dnl *** path of NTLM single-sign-on helper ntlm_auth
dnl **********************************************************
AC_ARG_WITH(ntlm-auth,
	    AC_HELP_STRING([--with-ntlm-auth=PATH],[Where to look for ntlm_auth, path points to ntlm_auth installation (default: /usr/bin/ntlm_auth)]),
	    ntlm_auth="$withval",
	    [if test $os_win32 = yes; then ntlm_auth="no"; else ntlm_auth="/usr/bin/ntlm_auth"; fi])
if test "$ntlm_auth" != "no"; then
    AC_DEFINE(USE_NTLM_AUTH, 1, [Whether or not use Samba's 'winbind' daemon helper 'ntlm_auth' for NTLM single-sign-on])
    if test "$ntlm_auth" = "yes"; then
	dnl --with-ntlm-auth (without path) used, use default path
	ntlm_auth="/usr/bin/ntlm_auth"
    fi
fi
AC_SUBST(ntlm_auth)
AC_DEFINE_UNQUOTED(NTLM_AUTH, "$ntlm_auth", [Samba's 'winbind' daemon helper 'ntlm_auth' which can be used for NTLM single-sign-on])

AX_CODE_COVERAGE

dnl **********************
dnl *** GSSAPI support ***
dnl **********************
AC_ARG_WITH(gssapi,
	    AS_HELP_STRING([--with-gssapi],
	    [Build with GSSAPI support [default=auto]]))

if test "$with_gssapi" != "no"; then
    AC_ARG_WITH(krb5-config,
		AS_HELP_STRING([--with-krb5-config=PATH],[Where to look for krb5-config, path points to krb5-config installation (default: /usr/kerberos/bin/)]),
		KRB5_CONFIG="$withval",
		[AC_PATH_PROGS(KRB5_CONFIG, krb5-config, no, ${PATH}:/usr/kerberos/bin)])

    if test "$KRB5_CONFIG" != "no"; then
	KRB5_LIBS="`${KRB5_CONFIG} --libs gssapi`"
	KRB5_CFLAGS="`${KRB5_CONFIG} --cflags gssapi`"
	AC_SUBST(KRB5_CFLAGS)
	AC_SUBST(KRB5_LIBS)
	if test "$KRB5_CONFIG" != none; then
	    AC_DEFINE(LIBSOUP_HAVE_GSSAPI, 1, [Whether or not GSSAPI libs are available])
	fi
    else
	if test "$with_gssapi" = "yes"; then
	    AC_MSG_ERROR([GSSAPI support requested but failed to found krb5-config. Try to set KRB5_CONFIG.])
	fi
    fi
fi

dnl ****************************************************
dnl *** Warnings to show if using GCC                ***
dnl *** (do this last so -Werror won't mess up tests ***
dnl ****************************************************

AC_ARG_ENABLE(more-warnings,
	      AS_HELP_STRING([--disable-more-warnings], [Inhibit compiler warnings]),
	      set_more_warnings=no)

if test "$GCC" = "yes" -a "$set_more_warnings" != "no"; then
	CFLAGS="$CFLAGS \
		-Wall -Wstrict-prototypes -Werror=missing-prototypes \
		-Werror=implicit-function-declaration \
		-Werror=pointer-arith -Werror=init-self -Werror=format=2 \
		-Wno-format-zero-length \
		-Werror=missing-include-dirs -Werror=aggregate-return \
		-Werror=declaration-after-statement"
fi

##################################################
# Visibility handling
##################################################

SOUP_HIDDEN_VISIBILITY_CFLAGS=""
case "$host" in
    *-*-mingw*)
        dnl on mingw32 we do -fvisibility=hidden and __declspec(dllexport)
        AC_DEFINE([_SOUP_EXTERN], [__attribute__((visibility("default"))) __declspec(dllexport) extern],
                  [defines how to decorate public symbols while building])
        SOUP_HIDDEN_VISIBILITY_CFLAGS="-fvisibility=hidden"
        ;;
    *)
        dnl on other compilers, check if we can do -fvisibility=hidden
        SAVED_CFLAGS="${CFLAGS}"
        CFLAGS="-fvisibility=hidden"
        AC_MSG_CHECKING([for -fvisibility=hidden compiler flag])
        AC_TRY_COMPILE([], [int main (void) { return 0; }],
                       AC_MSG_RESULT(yes)
                       enable_fvisibility_hidden=yes,
                       AC_MSG_RESULT(no)
                       enable_fvisibility_hidden=no)
        CFLAGS="${SAVED_CFLAGS}"

        AS_IF([test "${enable_fvisibility_hidden}" = "yes"], [
            AC_DEFINE([_SOUP_EXTERN], [__attribute__((visibility("default"))) extern],
                      [defines how to decorate public symbols while building])
            SOUP_HIDDEN_VISIBILITY_CFLAGS="-fvisibility=hidden"
        ])
        ;;
esac
AC_SUBST(SOUP_HIDDEN_VISIBILITY_CFLAGS)

dnl *************************
dnl *** Output Everything ***
dnl *************************

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	libsoup-2.4.pc
	libsoup-gnome-2.4.pc
	Makefile
	libsoup-zip
	libsoup/Makefile
	po/Makefile.in
	po/Makefile
	tests/Makefile
	examples/Makefile
	docs/Makefile
	docs/reference/Makefile
	libsoup/soup-version.h
	config.h.win32
	build/win32/Makefile
	build/win32/vs9/Makefile
	build/win32/vs9/soup-gen-srcs.vsprops
	build/win32/vs10/Makefile
	build/win32/vs10/soup-gen-srcs.props
	build/win32/vs11/Makefile
	build/win32/vs12/Makefile
	build/win32/vs14/Makefile
	])
AC_OUTPUT
