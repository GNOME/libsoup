test_utils = library('test-utils', 'test-utils.c', 'test-utils.h',
  install : false,
  c_args : '-DAPACHE_HTTPD=' + cdata.get('APACHE_HTTPD'),
  dependencies : [glib_dep, libsoup_dep])

tests = [
  'auth',
  'cache',
  'chunk',
  'chunk-io',
  'coding',
  'connection',
  'context',
  'continue',
  'cookies',
  'date',
  'forms',
  'header-parsing',
  'misc',
  'multipart',
  'no-ssl',
  'ntlm',
  'proxy',
  'pull-api',
  'range',
  'redirect',
  'requester',
  'resource',
  'session',
  'server-auth',
  'server',
  'sniffing',
  'socket',
  'ssl',
  'streaming',
  'timeout',
  'tld',
  'uri-parsing',
  'websocket',
  'xmlrpc-old-server',
  'xmlrpc-old',
  'xmlrpc-server',
  'xmlrpc'
]

env = environment()
env.set('G_TEST_SRCDIR', meson.current_source_dir())
env.set('G_TEST_BUILDDIR', meson.current_build_dir())
env.set('G_DEBUG', 'gc-friendly')
env.set('MALLOC_CHECK_', '2')
# This is set by Meson if empty
env.set('MALLOC_PERTURB_', '')

foreach test: tests
  test_name = '@0@-test'.format(test)
  test_target = executable(test_name, test_name + '.c',
    link_with: test_utils,
    dependencies : [glib_dep, libsoup_dep])
  test(test_name, test_target, env : env)
endforeach

executable('ntlm-test-helper', 'ntlm-test-helper.c',
  dependencies : [glib_dep, libsoup_dep])

configure_file(output : 'httpd.conf',
  input : 'httpd.conf.in',
  configuration : cdata)

# There is not copy_file() in Meson and this is official workaroud as per
# https://github.com/mesonbuild/meson/issues/860
configure_file(input : 'test-cert.pem',
  output : 'test-cert.pem',
  configuration : configuration_data())
configure_file(input : 'test-key.pem',
  output : 'test-key.pem',
  configuration : configuration_data())

gnome.compile_resources('soup-tests',
  'soup-tests.gresource.xml',
  gresource_bundle : true,
  install : true,
  install_dir : meson.current_build_dir() + '/tests',
  source_dir : '.')
