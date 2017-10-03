project('libsoup', 'c',
        version: '2.60.0',
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

subdir('libsoup')
subdir('examples')
