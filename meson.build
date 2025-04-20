project('libsoup', 'c',
        version: '3.7.0',
        meson_version : '>= 0.54',
        license : 'LGPL-2.0-or-later',
        default_options : [
          'c_std=gnu99',
          'warning_level=2',
        ])

gnome = import('gnome')

soup_version = meson.project_version()

# Before making a release, the soversion string should be modified.
# The string is of the form [C, R, A].
# - If interfaces have been changed or added, but binary compatibility has
#   been preserved, change to [C+1, 0, A+1].
# - If binary compatibility has been broken (eg removed or changed interfaces)
#   change to [C+1, 0, 0]
# - If the interface is the same as the previous version, use [C, R+1, A].
soup_version_info = [7, 3, 7]

# Turn [C, R, A] into an actual usable *soversion*.
soup_soversion_major = soup_version_info[0] - soup_version_info[2] # Current-Age
soup_soversion_minor = soup_version_info[2] # Age
soup_soversion_micro = soup_version_info[1] # Revision
libversion = '@0@.@1@.@2@'.format(soup_soversion_major, soup_soversion_minor, soup_soversion_micro)

darwin_versions = [soup_soversion_major + soup_soversion_minor + 1, '@0@.@1@'.format(soup_soversion_major + soup_soversion_minor + 1, soup_soversion_micro)]

apiversion = '3.0'
libsoup_api_name = '@0@-@1@'.format(meson.project_name(), apiversion)

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

# define ssize_t as Microsoft's headers do not define it
if cc.get_argument_syntax() == 'msvc'
  add_project_arguments('-Dssize_t=gssize', language: 'c')
endif

# Enable extra warnings if compiler supports them.
if cc.get_id() == 'msvc'
  common_flags += ['/FImsvc_recommended_pragmas.h']

  # set the input encoding to utf-8
  add_project_arguments(cc.get_supported_arguments(['/utf-8']), language: 'c')
else
  test_cflags = [
      '-Wmissing-include-dirs',
      '-Wpointer-arith',
      '-Winit-self',
      '-Werror=missing-prototypes',
      '-Werror=implicit-function-declaration',
      '-Werror=aggregate-return',
      '-Werror=format=2',
      '-Werror=return-type',
      '-Wincompatible-pointer-types',
      '-Wstrict-prototypes',
      '-Wno-format-zero-length',
      '-Wno-missing-include-dirs',
      '-Wno-typedef-redefinition',
      '-Wno-unused-parameter',
      '-Wno-sign-compare',
      '-Wno-cast-function-type',
      '-Wno-missing-field-initializers',
  ]

  if get_option('b_sanitize') == 'address' or get_option('b_sanitize') == 'address,undefined' or \
     get_option('fuzzing').enabled()
    test_cflags += ['-fno-omit-frame-pointer', '-fno-optimize-sibling-calls']
  endif

  common_flags += cc.get_supported_arguments(test_cflags)
endif

if cc.get_id() != 'msvc' and host_system == 'windows'
  # For "%2hhx" sscanf format and the like
  add_project_arguments('-D__USE_MINGW_ANSI_STDIO=1', language : 'c')
endif

add_project_arguments(common_flags, language : 'c')

glib_required_version = '>= 2.70.0'
glib_dep = dependency('glib-2.0', version : glib_required_version,
                       fallback: ['glib', 'libglib_dep'])
gmodule_dep = dependency('gmodule-no-export-2.0', version : glib_required_version,
                         fallback: ['glib', 'libgmodule_dep'])
gobject_dep = dependency('gobject-2.0', version : glib_required_version,
                       fallback: ['glib', 'libgobject_dep'])
gio_dep = dependency('gio-2.0', version : glib_required_version,
                       fallback: ['glib', 'libgio_dep'])

glib_deps = [glib_dep, gmodule_dep, gobject_dep, gio_dep]

cdata = configuration_data()

cdata.set('GLIB_VERSION_MAX_ALLOWED', 'GLIB_VERSION_2_70')
cdata.set('GLIB_VERSION_MIN_REQUIRED', 'GLIB_VERSION_2_70')

libnghttp2_dep = dependency('libnghttp2')
if (libnghttp2_dep.version() == 'unknown' and (libnghttp2_dep.type_name() == 'internal' or cc.has_function('nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation', prefix : '#include <nghttp2/nghttp2.h>', dependencies : libnghttp2_dep))) or libnghttp2_dep.version().version_compare('>=1.50')
    cdata.set('HAVE_NGHTTP2_OPTION_SET_NO_RFC9113_LEADING_AND_TRAILING_WS_VALIDATION', '1')
endif

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

brotlidec_dep = dependency('libbrotlidec', required : get_option('brotli'))
if brotlidec_dep.found()
  cdata.set('WITH_BROTLI', true)
endif

unix_socket_dep = dependency('gio-unix-2.0',
                             version : glib_required_version,
                             fallback: (host_system != 'windows') ? ['glib', 'libgiounix_dep'] : [],
                             required : false)

platform_deps = []
is_static_library = get_option('default_library') == 'static'
if not is_static_library
  if host_machine.system() == 'windows'
    platform_deps = [cc.find_library('ws2_32')]
    cdata.set('DLL_EXPORT', true)
    cdata.set('_SOUP_EXTERN', '__declspec(dllexport) extern')
  else
    cdata.set('_SOUP_EXTERN', '__attribute__((visibility("default"))) extern')
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
  apache_httpd2_version_raw = run_command(apachectl.path(), '-v', check: false)
  # It seems that from version 2.4.39 apachectl doesn't take arguments, fallback
  # to calling apache directly just in case.
  if apache_httpd2_version_raw.returncode() != 0
    apache_httpd2_version_raw = run_command(apache_httpd2.path(), '-v', check: false)
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
  apache_modules_dirs_out = run_command('get_apache_modules_dirs.py', apachectl.path(), check: false)
  have_apache = (apache_modules_dirs_out.returncode() == 0)
  # Same as above, using apachectl might fail, try apache directly.
  if not have_apache
    apache_modules_dirs_out = run_command('get_apache_modules_dirs.py', apache_httpd2.path(), check: false)
    have_apache = (apache_modules_dirs_out.returncode() == 0)
  endif
  if have_apache
    apache_modules_dirs = apache_modules_dirs_out.stdout().split(':')
    message('Apache modules directory: ' + apache_modules_dirs[0])
    cdata.set('APACHE_MODULE_DIR', apache_modules_dirs[0])
    message('Apache SSL module directory: ' + apache_modules_dirs[1])
    cdata.set('APACHE_SSL_MODULE_DIR', apache_modules_dirs[1])
    message('Apache mod_unixd module directory: ' + (apache_modules_dirs[2] != '' ? apache_modules_dirs[2] : '(none)'))
    cdata.set('IF_HAVE_MOD_UNIXD', apache_modules_dirs[2] != '' ? '' : '#')
    message('Apache HTTP/2 module directory: ' + apache_modules_dirs[3])
    cdata.set('IF_HAVE_MOD_HTTP2', apache_modules_dirs[3] != '' ? '' : '#')
    cdata.set('APACHE_HTTP2_MODULE_DIR', apache_modules_dirs[3])
    cdata.set('HAVE_APACHE', have_apache)
  else
    message('Failed to locate necessary Apache modules for full test coverage')
    message('stdout: ' + apache_modules_dirs_out.stdout())
    message('stderr: ' + apache_modules_dirs_out.stderr())
  endif
endif

if get_option('autobahn').auto() and not get_option('tests')
  have_autobahn = false
else
  have_autobahn = find_program('wstest', required: get_option('autobahn')).found()
endif

gnutls_dep = dependency('gnutls', version: '>= 3.6.0', required : get_option('pkcs11_tests'))

if not have_apache or not have_autobahn or not gnutls_dep.found()
  warning('Some regression tests will not be compiled due to missing libraries or modules. Please check the logs for more details.')
endif

##################
# GSSAPI support #
##################
gssapi_opt = get_option('gssapi')
if cc.get_id() == 'msvc'
  if host_machine.cpu_family() == 'x86'
    gssapi_lib_type = '32'
  else
    gssapi_lib_type = '64'
  endif
  gssapi_dep = cc.find_library('gssapi' + gssapi_lib_type,
    has_headers: 'gssapi/gssapi.h',
    required: gssapi_opt)
else
  gssapi_dep = dependency('krb5-gssapi', required: gssapi_opt)
endif

if gssapi_dep.found()
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
else
  ntlm_auth = dependency('', required: false)
endif

#########################
# GObject introspection #
#########################
gir = find_program('g-ir-scanner', required: get_option('introspection'))
enable_introspection = gir.found()

############
# Vala API #
############
vapi_opt = get_option('vapi')
enable_vapi = add_languages('vala', required: vapi_opt, native: false)
if enable_vapi and not enable_introspection
  enable_vapi = false
  if vapi_opt.enabled()
    error('vapi support was requested, but introspection support is mandatory.')
  endif
endif

configinc = include_directories('.')

prefix = get_option('prefix')

if get_option('b_sanitize') != 'none'
  cdata.set_quoted('B_SANITIZE_OPTION', get_option('b_sanitize'))
endif

cdata.set_quoted('PACKAGE_VERSION', soup_version)
cdata.set_quoted('LOCALEDIR', join_paths(prefix, get_option('localedir')))
cdata.set_quoted('GETTEXT_PACKAGE', libsoup_api_name)
configure_file(output : 'config.h', configuration : cdata)

subdir('libsoup')
xgettext = find_program('xgettext', required : false)
# xgettext is optional (on Windows for instance)
if xgettext.found()
  subdir('po')
endif

subdir('examples')
subdir('fuzzing')
if get_option('tests')
  subdir('tests')
endif

srcdir = include_directories('libsoup')
subdir('docs/reference')

summary({
    'prefix' : get_option('prefix'),
    'libdir' : get_option('libdir'),
    'datadir' : get_option('datadir'),
  },
  section : 'Directories'
)

summary({
    'GSSAPI' : gssapi_dep.found(),
    'NTLM' : ntlm_auth.found(),
    'Brotli' : brotlidec_dep.found(),
    'Translations' : xgettext.found(),
    'GIR' : enable_introspection,
    'VAPI' : enable_vapi,
    'Documentation' : have_docs,
  },
  section : 'Features'
)

summary({
    'All tests' : get_option('tests'),
    'Tests requiring Apache' : have_apache,
    'Documentation tests' : get_option('doc_tests'),
    'Fuzzing tests' : get_option('fuzzing').enabled(),
    'Autobahn tests' : have_autobahn,
    'PKCS #11 tests' : gnutls_dep.found(),
    'Install tests': get_option('installed_tests'),
    'Unix sockets' : unix_socket_dep.found(),
  },
  section : 'Testing'
)
