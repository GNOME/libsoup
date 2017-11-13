project('libsoup', 'c',
        version: '2.60.2',
        meson_version : '>=0.40.1',
        license : 'LGPL')

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

host_system = host_machine.system()

glib_dep = [dependency('glib-2.0', version : '>=2.38'),
            dependency('gobject-2.0', version : '>=2.38'),
            dependency('gio-2.0', version : '>=2.38')]

sqlite_dep = [dependency('sqlite3')]

libxml_dep = [dependency('libxml-2.0')]

cdata = configuration_data()

platform_deps = []
if host_machine.system() == 'windows'
  platform_deps = [cc.find_library('ws2_32')]
  cdata.set('_SOUP_EXTERN', '__declspec(dllexport)')
  cdata.set('DLL_EXPORT', 1)
endif

###################
# glib-networking #
###################
check_glib_networking_src = '''#include <gio/gio.h>
int main(void) {
  return !g_tls_backend_supports_tls (g_tls_backend_get_default ());
}
'''

enable_tls_check = get_option('enable-tls-check')
if enable_tls_check
  if not cc.compiles(check_glib_networking_src, name : 'glib-networking supports TLS', dependencies : glib_dep)
    error('libsoup requires glib-networking for TLS support')
  endif
endif

################################
# Regresion tests dependencies #
################################
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
      cdata.set('APACHE_HTTPD', '"@0@"'.format(apache_httpd2.path()))
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
      add_project_arguments('-DHAVE_APACHE=1', language : 'c')
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
      add_project_arguments('-DHAVE_PHP_XMLRPC=1', language : 'c')
    else
      message('php-xmlrpc not found')
    endif
  endif
  cdata.set('IF_HAVE_PHP', have_php ? '' : '#')
  apache_mod_unixd = run_command('test', '-f', cdata.get('APACHE_MODULE_DIR') + '/mod_unixd.so')
  cdata.set('IF_HAVE_MOD_UNIXD', apache_mod_unixd.returncode() == 0 ? '' : '#')
endif

if find_program('curl', required : false).found()
  add_project_arguments('-DHAVE_CURL=1', language : 'c')
endif

##################
# GSSAPI support #
##################
enable_gssapi = get_option('enable-gssapi')
krb5_config_option = get_option('krb5-config')
if enable_gssapi
  krb5_config_path = krb5_config_option != '' ? krb5_config_option : 'krb5-config'
  krb5_config = find_program(krb5_config_path, required : false)

  if krb5_config.found()
    krb5_config_output = run_command (krb5_config, '--libs', 'gssapi')
    if krb5_config_output.returncode() == 0
      add_project_link_arguments(krb5_config_output.stdout().split(), language : 'c')
    else
      error('Failed to obtain cflags for GSSAPI from krb5-config')
      enable_gssapi = false
    endif

    krb5_config_output = run_command (krb5_config, '--cflags', 'gssapi')
    if krb5_config_output.returncode() == 0
      add_project_arguments(krb5_config_output.stdout().split(), language : 'c')
    else
      error('Failed to obtain cflags for GSSAPI from krb5-config')
      enable_gssapi = false
    endif
  else
    error('GSSAPI support requested, but krb5-config not found. Please specify its path with -Dkrb5-config=PATH')
    enable_gssapi = false
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
  enable_ntlm = get_option('enable-ntlm')
  if enable_ntlm
    ntlm_auth_option = get_option('ntlm-auth')
    ntlm_auth_path = ntlm_auth_option != '' ? ntlm_auth_option : 'ntlm_auth'
    ntlm_auth = find_program(ntlm_auth_path, required : false)

    if ntlm_auth.found()
        add_project_arguments('-DUSE_NTLM_AUTH=1', language : 'c')
        add_project_arguments('-DNTLM_AUTH=' + ntlm_auth.path(), language : 'c')
    endif
  endif
endif

#################
# GNOME support #
#################
enable_gnome = get_option('enable-gnome')
if host_machine.system() == 'windows'
  enable_gnome = false
endif
cdata.set('BUILD_LIBSOUP_GNOME', enable_gnome)

configinc = include_directories('.')

prefix = get_option('prefix')

cdata.set('PACKAGE_VERSION', '"@0@"'.format(soup_version))
cdata.set('LOCALEDIR', '"@0@/@1@"'.format(prefix, get_option('localedir')))
cdata.set('GETTEXT_PACKAGE', '"libsoup-2.4"')
configure_file(output : 'config.h', configuration : cdata)

pkgconf = configuration_data()

pkgconf.set('prefix', get_option('prefix'))
pkgconf.set('exec_prefix', '${prefix}')
pkgconf.set('libdir', '${prefix}/@0@'.format(get_option('libdir')))
pkgconf.set('includedir', '${prefix}/@0@'.format(get_option('includedir')))
pkgconf.set('VERSION', soup_version)

pkg_install_dir = '@0@/pkgconfig'.format(get_option('libdir'))

configure_file(output : 'libsoup-2.4.pc',
    input : 'libsoup-2.4.pc.in',
    configuration : pkgconf,
    install_dir : pkg_install_dir)

if enable_gnome
  configure_file(output : 'libsoup-gnome-2.4.pc',
      input : 'libsoup-gnome-2.4.pc.in',
      configuration : pkgconf,
      install_dir : pkg_install_dir)
endif

subdir('libsoup')
subdir('examples')
subdir('tests')

if get_option('enable-gtk-doc')
  subdir('docs/reference')
endif
