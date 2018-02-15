project('libsoup', 'c',
        version: '2.61.90',
        meson_version : '>=0.40.1',
        license : 'LGPL2',
        default_options : 'c_std=c89')

gnome = import('gnome')
cc = meson.get_compiler('c')

soup_version = meson.project_version()
version_arr = soup_version.split('.')
soup_version_major = version_arr[0]
soup_version_minor = version_arr[1]
soup_version_micro = version_arr[2]

libversion = '1.8.0'
apiversion = '2.4'
soversion = '0'
libsoup_api_name = '@0@-@1@'.format(meson.project_name(), apiversion)

host_system = host_machine.system()

# Enable extra warnings if compiler supports them.
if cc.get_id() == 'msvc'
  common_flags = ['/FImsvc_recommended_pragmas.h']
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

  common_flags = cc.get_supported_arguments(test_cflags)
endif

add_project_arguments(common_flags, language : 'c')

glib_required_version = '>= 2.38'
glib_dep = [dependency('glib-2.0', version : glib_required_version),
            dependency('gobject-2.0', version : glib_required_version),
            dependency('gio-2.0', version : glib_required_version)]

sqlite_dep = dependency('sqlite3', required: cc.get_id() != 'msvc')

# Fallback check for sqlite on Visual Studio, which normally does not
# generate a pkg-config file upon a successful build
if not sqlite_dep.found()
  cc.has_header('sqlite3.h')
  cc.has_header('sqlite3ext.h')
  sqlite_dep = cc.find_library('sqlite3')
endif

libxml_dep = dependency('libxml-2.0', required: cc.get_id() != 'msvc')

# Fallback check for libxml2 on Visual Studio, which normally does not
# generate a pkg-config file upon a successful build
if not libxml_dep.found()
  # Note: The XML include dir needs to be within the INCLUDE envvar,
  # such as <INCLUDEDIR>\libxml2
  cc.has_header('libxml/tree.h')
  libxml2_dep = cc.find_library('libxml2')
endif

cdata = configuration_data()

platform_deps = []
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32')]
  cdata.set('_SOUP_EXTERN', '__declspec(dllexport)')
  cdata.set('DLL_EXPORT', 1)
endif

###################
# GIO TLS support #
###################
check_gio_tls_src = '''#include <gio/gio.h>
int main(void) {
  return !g_tls_backend_supports_tls (g_tls_backend_get_default ());
}
'''

enable_tls_check = get_option('tls_check')
if enable_tls_check
  assert(cc.compiles(check_gio_tls_src, name : 'GIO has real TLS support', dependencies : glib_dep),
         'libsoup requires glib-networking or glib-openssl for TLS support')
endif

#################################
# Regression tests dependencies #
#################################
apache_httpd2 = find_program('httpd2', 'httpd', 'apache2', 'apache', required : false)
have_apache=false
apache_httpd2_version = ''
if apache_httpd2.found()
  apache_httpd2_version_raw = run_command(apache_httpd2.path(), '-v')
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
  apache_modules = run_command('get_apache_module_dirs.py', apache_httpd2.path())
  if apache_modules.returncode() == 0
    message('Apache module directory: ' + apache_modules.stdout().split(':')[0])
    apache_module_dir = apache_modules.stdout().split(':')[0]
    cdata.set('APACHE_MODULE_DIR', apache_module_dir)
    apache_ssl_module_dir = apache_modules.stdout().split(':')[1]
    cdata.set('APACHE_SSL_MODULE_DIR', apache_ssl_module_dir)
    if apache_module_dir != '' and apache_ssl_module_dir != ''
      have_apache = true
      cdata.set('HAVE_APACHE', '1')
    endif
    cdata.set('APACHE_PHP_MODULE_DIR', apache_modules.stdout().split(':')[2])
  endif
endif

have_php = false
if have_apache
  php = find_program('php', required : false)
  apache_php_module = run_command('test', '-d', cdata.get('APACHE_PHP_MODULE_DIR'))
  if apache_php_module.returncode() == 0
    have_php = true
    php_xmlrpc = run_command(php, '--rf', 'xmlrpc_server_create')
    if php_xmlrpc.returncode() == 0
      message('php-xmlrpc found')
      cdata.set('HAVE_PHP_XMLRPC', '1')
    else
      message('php-xmlrpc not found')
    endif
  endif
  cdata.set('IF_HAVE_PHP', have_php ? '' : '#')
  apache_mod_unixd = run_command('test', '-f', cdata.get('APACHE_MODULE_DIR') + '/mod_unixd.so')
  cdata.set('IF_HAVE_MOD_UNIXD', apache_mod_unixd.returncode() == 0 ? '' : '#')
endif

if find_program('curl', required : false).found()
  cdata.set('HAVE_CURL', '1')
endif

##################
# GSSAPI support #
##################
enable_gssapi = get_option('gssapi')
krb5_config_option = get_option('krb5_config')
if enable_gssapi
  if cc.get_id() == 'msvc'
    if host_machine.cpu_family() == 'x86'
      gssapi_lib_type = '32'
    else
      gssapi_lib_type = '64'
    endif
    if cc.has_header('gssapi/gssapi.h', required: false)
      gssapi_lib = cc.find_library('gssapi' + gssapi_lib_type, required: false)
      assert(gssapi_lib.found(), 'GSSAPI support requested, but the MIT Keberos 5 headers and libraries are not found')
      add_project_link_arguments('gssapi@0@.lib'.format(gssapi_lib_type), language : 'c')
    endif
  else
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
enable_gnome = get_option('gnome')
if host_machine.system() == 'windows'
  enable_gnome = false
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
