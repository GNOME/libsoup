project('libsoup', 'c',
        version: '2.66.0',
        meson_version : '>=0.48',
        license : 'LGPL2',
        default_options : 'c_std=c89')

gnome = import('gnome')

soup_version = meson.project_version()
version_arr = soup_version.split('.')
soup_version_major = version_arr[0]
soup_version_minor = version_arr[1]
soup_version_micro = version_arr[2]

libversion = '1.8.0'
apiversion = '2.4'
soversion = '1'
libsoup_api_name = '@0@-@1@'.format(meson.project_name(), apiversion)
libversion_arr = libversion.split('.')
darwin_version_major = libversion_arr[0].to_int()
darwin_version_minor = libversion_arr[1].to_int()
darwin_version_micro = libversion_arr[2].to_int()
darwin_versions = [darwin_version_major + darwin_version_minor + 1, '@0@.@1@'.format(darwin_version_major + darwin_version_minor + 1, darwin_version_micro)]

host_system = host_machine.system()

# Needed for the gmtime_r check and for some system types availability.
default_source_flag = [
  '-D_DEFAULT_SOURCE'
]

add_project_arguments(default_source_flag, language: 'c')

common_flags = [
  '-DHAVE_CONFIG_H',
]

cc = meson.get_compiler('c')
# Enable extra warnings if compiler supports them.
if cc.get_id() == 'msvc'
  common_flags += ['/FImsvc_recommended_pragmas.h']
else
  test_cflags = [
      '-Wall',
      '-Wmissing-include-dirs',
      '-Wpointer-arith',
      '-Winit-self',
      '-Wdeclaration-after-statement',
      '-Werror=missing-prototypes',
      '-Werror=implicit-function-declaration',
      '-Werror=aggregate-return',
      '-Werror=format=2',
      '-Wstrict-prototypes',
      '-Wno-format-zero-length',
  ]

  common_flags += cc.get_supported_arguments(test_cflags)
endif

if cc.get_id() != 'msvc' and host_system == 'windows'
  # For "%2hhx" sscanf format and the like
  add_project_arguments('-D__USE_MINGW_ANSI_STDIO=1', language : 'c')
endif

add_project_arguments(common_flags, language : 'c')

glib_required_version = '>= 2.38'
glib_dep = [dependency('glib-2.0', version : glib_required_version,
                       fallback: ['glib', 'libglib_dep']),
            dependency('gobject-2.0', version : glib_required_version,
                       fallback: ['glib', 'libgobject_dep']),
            dependency('gio-2.0', version : glib_required_version,
                       fallback: ['glib', 'libgio_dep'])]

sqlite_dep = dependency('sqlite3', required: false)

# Fallback check for sqlite, not all platforms ship pkg-config file
if not sqlite_dep.found()
  cc.has_header('sqlite3.h')
  cc.has_header('sqlite3ext.h')
  sqlite_dep = cc.find_library('sqlite3')
endif

libxml_dep = dependency('libxml-2.0', required: false)

# Fallback check for libxml2, not all platforms ship pkg-config file
if not libxml_dep.found()
  # Note: The XML include dir needs to be within the INCLUDE envvar,
  # such as <INCLUDEDIR>\libxml2
  cc.has_header('libxml/tree.h')
  libxml2_libname = cc.get_id() == 'msvc' ? 'libxml2' : 'xml2'
  libxml_dep = cc.find_library(libxml2_libname)
endif

cdata = configuration_data()

platform_deps = []
hidden_visibility_flag = []
is_static_library = get_option('default_library') == 'static'
if not is_static_library
  if host_machine.system() == 'windows'
    platform_deps = [cc.find_library('ws2_32')]
    cdata.set('DLL_EXPORT', true)
    cdata.set('_SOUP_EXTERN', '__declspec(dllexport) extern')
    if cc.get_id() != 'msvc'
      hidden_visibility_flag += ['-fvisibility=hidden']
    endif
  else
    cdata.set('_SOUP_EXTERN', '__attribute__((visibility("default"))) extern')
    hidden_visibility_flag += ['-fvisibility=hidden']
  endif
endif

libpsl_required_version = '>= 0.20'
libpsl_dep = dependency('libpsl', version : libpsl_required_version,
  fallback : ['libpsl', 'libpsl_dep'])

if cc.has_function('gmtime_r', prefix : '#include <time.h>', args : default_source_flag)
    cdata.set('HAVE_GMTIME_R', '1')
endif

###################
# GIO TLS support #
###################
enable_tls_check = get_option('tls_check')
if enable_tls_check
  check_gio_tls_src = '''#include <gio/gio.h>
  int main(void) {
    return !g_tls_backend_supports_tls (g_tls_backend_get_default ());
  }
  '''

  assert(cc.compiles(check_gio_tls_src, name : 'GIO has real TLS support', dependencies : glib_dep),
         'libsoup requires glib-networking or glib-openssl for TLS support')
endif

#################################
# Regression tests dependencies #
#################################

# The situation here is a little bit complicated. For running some of the tests
# we need the Apache's httpd binary. As we want to know more about its
# configuration we have to run it and parse the output. But here is the first
# problem, because on Debian we can't run the binary unless the
# /etc/apache2/envvars file is sourced, otherwise it ends with failure. The
# recommended way to communicate with the Apache is the apachectl that passes
# the arguments to httpd and also sources the envvars file. In the ideal world
# we could use the apachectl to run the tests as well, but on Fedora any non
# trivial call to it ends with the following error:
#     Passing arguments to httpd using apachectl is no longer supported.
#
# The summary is that for the configuration parsing we will use the apachectl,
# but for running the tests we will use the httpd binary.
apachectl = find_program('apachectl', '/sbin/apachectl', '/usr/sbin/apachectl', required : false)
# This abomination is a result of https://github.com/mesonbuild/meson/issues/1576
apache_httpd2 = find_program('httpd2', 'httpd', 'apache2', 'apache',
             '/sbin/httpd2', '/sbin/httpd', '/sbin/apache2', '/sbin/apache',
             '/usr/sbin/httpd2', '/usr/sbin/httpd', '/usr/sbin/apache2', '/usr/sbin/apache',
             required : false)
have_apache=false
apache_httpd2_version = ''
if apache_httpd2.found() and apachectl.found()
  apache_httpd2_version_raw = run_command(apachectl.path(), '-v')
  if apache_httpd2_version_raw.returncode() == 0
    apache_httpd2_version = apache_httpd2_version_raw.stdout().split('\n')[0]
    apache_httpd2_version = apache_httpd2_version.split('/')[1].split(' ')[0]
    if apache_httpd2_version.version_compare('>=2.4')
      have_apache = true
      cdata.set_quoted('APACHE_HTTPD', apache_httpd2.path())
    else
      message('Found ' + apache_httpd2_version + ', but at least 2.4 is needed - ignoring')
    endif
  endif
endif

if have_apache
  apache_modules_dirs_out = run_command('get_apache_modules_dirs.py', apachectl.path())
  have_apache = (apache_modules_dirs_out.returncode() == 0)
  if have_apache
    apache_modules_dirs = apache_modules_dirs_out.stdout().split(':')
    message('Apache modules directory: ' + apache_modules_dirs[0])
    cdata.set('APACHE_MODULE_DIR', apache_modules_dirs[0])
    cdata.set('APACHE_SSL_MODULE_DIR', apache_modules_dirs[1])
    cdata.set('APACHE_PHP_MODULE_FILE', apache_modules_dirs[2])
    cdata.set('IF_HAVE_MOD_UNIXD', apache_modules_dirs[3] != '' ? '' : '#')
    cdata.set('HAVE_APACHE', have_apache)
  endif
endif

have_php = false
have_php_xmlrpc = false
if have_apache
  php = find_program('php', required : false)
  message(cdata.get('APACHE_PHP_MODULE_FILE'))
  if php.found() and cdata.get('APACHE_PHP_MODULE_FILE') != ''
    have_php = true
    php_xmlrpc = run_command(php, '-d', 'extension=xmlrpc', '-r', 'exit(function_exists("xmlrpc_server_create")?0:1);')
    if php_xmlrpc.returncode() == 0
      message('php-xmlrpc found')
      have_php_xmlrpc = true
      cdata.set('HAVE_PHP_XMLRPC', '1')
    else
      message('php-xmlrpc not found')
    endif
  endif
  cdata.set('IF_HAVE_PHP', have_php ? '' : '#')
  cdata.set('IF_HAVE_PHP_XMLRPC', have_php_xmlrpc ? '' : ';')
endif

tests_ready = have_apache and have_php and have_php_xmlrpc
if not tests_ready
  warning('Some regression tests will not be compiled due to missing libraries or modules. Please check the logs for more details.')
endif

cdata.set('HAVE_CURL', find_program('curl', required : false).found())

##################
# GSSAPI support #
##################
enable_gssapi = get_option('gssapi')
if enable_gssapi
  if cc.get_id() == 'msvc'
    if host_machine.cpu_family() == 'x86'
      gssapi_lib_type = '32'
    else
      gssapi_lib_type = '64'
    endif
    if cc.has_header('gssapi/gssapi.h', required: false)
      gssapi_lib = cc.find_library('gssapi' + gssapi_lib_type, required: false)
      assert(gssapi_lib.found(), 'GSSAPI support requested, but the MIT Kerberos 5 headers and libraries are not found')
      add_project_link_arguments('gssapi@0@.lib'.format(gssapi_lib_type), language : 'c')
    endif
  else
    krb5_config_option = get_option('krb5_config')

    krb5_config_path = krb5_config_option != '' ? krb5_config_option : 'krb5-config'
    krb5_config = find_program(krb5_config_path, required : false)

    assert(krb5_config.found(), 'GSSAPI support requested, but krb5-config not found. Please specify its path with -Dkrb5-config=PATH')

    krb5_config_output = run_command (krb5_config, '--libs', 'gssapi')
    assert(krb5_config_output.returncode() == 0, 'Failed to obtain cflags for GSSAPI from krb5-config')
    add_project_link_arguments(krb5_config_output.stdout().split(), language : 'c')

    krb5_config_output = run_command (krb5_config, '--cflags', 'gssapi')
    assert(krb5_config_output.returncode() == 0, 'Failed to obtain cflags for GSSAPI from krb5-config')
    add_project_arguments(krb5_config_output.stdout().split(), language : 'c')
  endif

  if enable_gssapi
    add_project_arguments('-DLIBSOUP_HAVE_GSSAPI=1', language : 'c')
  endif
endif

################
# NTLM support #
################
# NTLM not supported on Windows
if host_machine.system() != 'windows'
  enable_ntlm = get_option('ntlm')
  if enable_ntlm
    ntlm_auth = find_program(get_option('ntlm_auth'), required: false)

    if ntlm_auth.found()
      add_project_arguments('-DUSE_NTLM_AUTH=1', language : 'c')
      add_project_arguments('-DNTLM_AUTH=' + ntlm_auth.path(), language : 'c')
    endif
  endif
endif

#################
# GNOME support #
#################
enable_gnome = get_option('gnome') and host_machine.system() != 'windows'

#########################
# GObject introspection #
#########################
# FIXME: once we start to require meson 0.49.0+ and gnome-introspection 1.58.1+
# the we can enable the introspection even for the static build. See
# https://github.com/mesonbuild/meson/pull/4478.
enable_introspection = get_option('introspection') and find_program('g-ir-scanner', required: false).found() and not meson.is_cross_build() and not is_static_library

############
# Vala API #
############
enable_vapi = get_option('vapi')
if enable_vapi
  assert(enable_introspection, 'vapi support was requested, but introspection support is mandatory.')
  assert(add_languages('vala', required: false), 'vapi support was requested, but vala not found.')
endif

configinc = include_directories('.')

prefix = get_option('prefix')

cdata.set_quoted('PACKAGE_VERSION', soup_version)
cdata.set_quoted('LOCALEDIR', join_paths(prefix, get_option('localedir')))
cdata.set_quoted('GETTEXT_PACKAGE', libsoup_api_name)
configure_file(output : 'config.h', configuration : cdata)

subdir('libsoup')
subdir('po')
subdir('examples')

if get_option('tests')
  subdir('tests')
 endif

if get_option('doc')
  subdir('docs/reference')
endif
