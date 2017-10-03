project('libsoup', 'c',
        version: '2.58.0',
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
