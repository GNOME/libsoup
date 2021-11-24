project('libsoup', 'c',
        version: '2.74.2',
        meson_version : '>=0.50',
        license : 'LGPL2',
        default_options : 'c_std=c99')

gnome = import('gnome')

soup_version = meson.project_version()
version_arr = soup_version.split('.')
soup_version_major = version_arr[0]
soup_version_minor = version_arr[1]
soup_version_micro = version_arr[2]

# Before making a release, the libversion string should be modified.
#
#  * Bump the first component if binary compatibility has been broken; or
#  * Bump the second component if new APIs are added; or
#  * Bump the third component otherwise.
#
# When bumping the first component version, set the second and third components
# to 0. When bumping the second version, set the third one to zero.
libversion = '1.11.2'
apiversion = '2.4'
soversion = libversion.split('.')[0]
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

if host_system == 'sunos'
      add_project_arguments('-D__EXTENSIONS__', language: 'c')
      add_project_link_arguments('-lsocket', language: 'c')
endif

common_flags = [
  '-DHAVE_CONFIG_H',
]

cc = meson.get_compiler('c')
# Enable extra warnings if compiler supports them.
if cc.get_id() == 'msvc'
  common_flags += ['/FImsvc_recommended_pragmas.h']

  # set the input encoding to utf-8
  add_project_arguments(cc.get_supported_arguments(['/utf-8']), language: 'c')
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

glib_required_version = '>= 2.58'
glib_dep = dependency('glib-2.0', version : glib_required_version,
                       fallback: ['glib', 'libglib_dep'])
gmodule_dep = dependency('gmodule-2.0', version : glib_required_version,
                         fallback: ['glib', 'libgmodule_dep'])
gobject_dep = dependency('gobject-2.0', version : glib_required_version,
                       fallback: ['glib', 'libgobject_dep'])
gio_dep = dependency('gio-2.0', version : glib_required_version,
                       fallback: ['glib', 'libgio_dep'])

glib_deps = [glib_dep, gmodule_dep, gobject_dep, gio_dep]

sqlite_dep = dependency('sqlite3', required: false)

# Fallback check for sqlite, not all platforms ship pkg-config file
if not sqlite_dep.found()
  sqlite_dep = cc.find_library('sqlite3',
    has_headers : ['sqlite3.h'],
    required: false)
endif

if not sqlite_dep.found()
  # Allows fallback to subproject
  sqlite_dep = dependency('sqlite3')
endif

libxml_dep = dependency('libxml-2.0', required: false)

# Fallback check for libxml2, not all platforms ship pkg-config file
if not libxml_dep.found()
  # Note: The XML include dir needs to be within the INCLUDE envvar,
  # such as <INCLUDEDIR>\libxml2
  libxml2_libname = cc.get_id() == 'msvc' ? 'libxml2' : 'xml2'
  libxml_dep = cc.find_library(libxml2_libname,
    has_headers : 'libxml/tree.h',
    required: false)
endif

if not libxml_dep.found()
  libxml_dep = subproject('libxml2').get_variable('xml2lib_dep')
endif

cdata = configuration_data()

brotlidec_dep = dependency('libbrotlidec', required : get_option('brotli'))
if brotlidec_dep.found()
  cdata.set('WITH_BROTLI', true)
endif

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

# sysprof support
libsysprof_capture_dep = dependency('sysprof-capture-4',
  required: get_option('sysprof'),
  default_options: [
    'enable_examples=false',
    'enable_gtk=false',
    'enable_tests=false',
    'enable_tools=false',
    'libsysprof=false',
    'with_sysprofd=none',
    'help=false',
  ],
  # sysprof doesn't support Windows, so don't fall back to the subproject which fails to build,
  # instead let it fail here so that sysprof gets skipped
  fallback: (host_system != 'windows') ? ['sysprof', 'libsysprof_capture_dep'] : [],
)
cdata.set('HAVE_SYSPROF', libsysprof_capture_dep.found())

###################
# GIO TLS support #
###################
enable_tls_check = get_option('tls_check')
if enable_tls_check
  if gio_dep.type_name() == 'internal'
    warning('TLS check was enabled but required dependency is internal')
  else
    check_gio_tls_src = '''#include <gio/gio.h>
    int main(void) {
      return !g_tls_backend_supports_tls (g_tls_backend_get_default ());
    }
    '''

    rres = cc.run(check_gio_tls_src, name : 'GIO has real TLS support', dependencies : glib_deps)
    assert(rres.compiled() and rres.returncode() == 0, 'libsoup requires glib-networking for TLS support')
  endif
endif

libz_dep = dependency('zlib', required : false)
if not libz_dep.found()
  if cc.get_id() != 'msvc'
    libz_dep = cc.find_library('z', required : false)
  else
    libz_dep = cc.find_library('zlib1', required : false)
    if not libz_dep.found()
      libz_dep = cc.find_library('zlib', required : false)
    endif
  endif
  if not libz_dep.found() or not cc.has_header('zlib.h')
    libz_dep = subproject('zlib').get_variable('zlib_dep')
  endif
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
  # It seems that from version 2.4.39 apachectl doesn't take arguments, fallback
  # to calling apache directly just in case.
  if apache_httpd2_version_raw.returncode() != 0
    apache_httpd2_version_raw = run_command(apache_httpd2.path(), '-v')
  endif
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
  # Same as above, using apachectl might fail, try apache directly.
  if not have_apache
    apache_modules_dirs_out = run_command('get_apache_modules_dirs.py', apache_httpd2.path())
    have_apache = (apache_modules_dirs_out.returncode() == 0)
  endif
  if have_apache
    apache_modules_dirs = apache_modules_dirs_out.stdout().split(':')
    message('Apache modules directory: ' + apache_modules_dirs[0])
    cdata.set('APACHE_MODULE_DIR', apache_modules_dirs[0])
    message('Apache SSL module directory: ' + apache_modules_dirs[1])
    cdata.set('APACHE_SSL_MODULE_DIR', apache_modules_dirs[1])
    message('Apache PHP module file: ' + apache_modules_dirs[2])
    cdata.set('APACHE_PHP_MODULE_FILE', apache_modules_dirs[2])
    message('Apache mod_unixd module directory: ' + (apache_modules_dirs[3] != '' ? apache_modules_dirs[3] : '(none)'))
    cdata.set('IF_HAVE_MOD_UNIXD', apache_modules_dirs[3] != '' ? '' : '#')
    cdata.set('HAVE_APACHE', have_apache)
  else
    message('Failed to locate necessary Apache modules for full test coverage')
    message('stdout: ' + apache_modules_dirs_out.stdout())
    message('stderr: ' + apache_modules_dirs_out.stderr())
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

##################
# GSSAPI support #
##################
gssapi_opt = get_option('gssapi')
enable_gssapi = false
if cc.get_id() == 'msvc'
  if host_machine.cpu_family() == 'x86'
    gssapi_lib_type = '32'
  else
    gssapi_lib_type = '64'
  endif
  gssapi_dep = cc.find_library('gssapi' + gssapi_lib_type,
    has_headers: 'gssapi/gssapi.h',
    required: gssapi_opt)
  if gssapi_dep.found()
      enable_gssapi = true
  endif
else
  krb5_config_path = get_option('krb5_config')
  if not meson.is_cross_build() and krb5_config_path == ''
    krb5_config_path = 'krb5-config'
  endif
  krb5_config = find_program(krb5_config_path, required : gssapi_opt)
  if krb5_config.found()
    libs_output = run_command (krb5_config, '--libs', 'gssapi', check: gssapi_opt.enabled())
    cflags_output = run_command (krb5_config, '--cflags', 'gssapi', check: gssapi_opt.enabled())
    if libs_output.returncode() == 0 and cflags_output.returncode() == 0
      enable_gssapi = true
      gssapi_dep = declare_dependency(
        link_args: libs_output.stdout().split(),
        compile_args: cflags_output.stdout().split())
    endif
  else
    gssapi_dep = dependency('', required: false)
  endif
endif

if enable_gssapi
  add_project_arguments('-DLIBSOUP_HAVE_GSSAPI=1', language : 'c')
endif

################
# NTLM support #
################
# NTLM not supported on Windows
if host_machine.system() != 'windows'
  ntlm_auth = find_program(get_option('ntlm_auth'), required: get_option('ntlm'))

  if ntlm_auth.found()
    add_project_arguments('-DUSE_NTLM_AUTH=1', language : 'c')
    add_project_arguments('-DNTLM_AUTH="' + ntlm_auth.path() + '"', language : 'c')
  endif
endif

#################
# GNOME support #
#################
enable_gnome = get_option('gnome')

#########################
# GObject introspection #
#########################
gir = find_program('g-ir-scanner', required: get_option('introspection'))
enable_introspection = gir.found()

############
# Vala API #
############
vapi_opt = get_option('vapi')
enable_vapi = add_languages('vala', required: vapi_opt)
if enable_vapi and not enable_introspection
  enable_vapi = false
  if vapi_opt.enabled()
    error('vapi support was requested, but introspection support is mandatory.')
  endif
endif

configinc = include_directories('.')

prefix = get_option('prefix')

cdata.set_quoted('PACKAGE_VERSION', soup_version)
cdata.set_quoted('LOCALEDIR', join_paths(prefix, get_option('localedir')))
cdata.set_quoted('GETTEXT_PACKAGE', libsoup_api_name)
configure_file(output : 'config.h', configuration : cdata)

subdir('libsoup')
# xgettext is optional (on Windows for instance)
if find_program('xgettext', required : false).found()
  subdir('po')
endif
subdir('examples')

if get_option('tests')
  subdir('tests')
 endif

if get_option('gtk_doc')
  srcdir = include_directories('libsoup')
  subdir('docs/reference')
endif
