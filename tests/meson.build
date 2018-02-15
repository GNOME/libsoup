test_utils_name = 'test-utils'

if cc.get_id() == 'msvc'
  test_utils = static_library(test_utils_name, test_utils_name + '.c',
    dependencies : [glib_dep, libsoup_dep])
else
  test_utils = library(test_utils_name, test_utils_name + '.c',
    dependencies : [glib_dep, libsoup_dep])
endif

# ['name', is_parallel]
tests = [
  ['auth', false],
  ['cache', true],
  ['chunk', true],
  ['chunk-io', true],
  ['coding', true],
  ['connection', false],
  ['context', true],
  ['continue', true],
  ['cookies', true],
  ['date', true],
  ['forms', true],
  ['header-parsing', true],
  ['misc', true],
  ['multipart', true],
  ['no-ssl', true],
  ['ntlm', true],
  ['proxy', true],
  ['pull-api', false],
  ['range', false],
  ['redirect', true],
  ['requester', true],
  ['resource', true],
  ['session', true],
  ['server-auth', true],
  ['server', true],
  ['sniffing', true],
  ['socket', true],
  ['ssl', true],
  ['streaming', true],
  ['timeout', true],
  ['tld', true],
  ['uri-parsing', true],
  ['websocket', true],
  ['xmlrpc-old-server', true],
  ['xmlrpc-old', false],
  ['xmlrpc-server', true],
  ['xmlrpc', false]
]

env = environment()
env.set('G_TEST_SRCDIR', meson.current_source_dir())
env.set('G_TEST_BUILDDIR', meson.current_build_dir())
env.set('G_DEBUG', 'gc-friendly')
env.set('MALLOC_CHECK_', '2')
# This is set by Meson if empty
env.set('MALLOC_PERTURB_', '')

foreach test: tests
  test_name = '@0@-test'.format(test[0])
  test_target = executable(test_name, test_name + '.c',
    link_with: test_utils,
    dependencies : [glib_dep, libsoup_dep, platform_deps])
  test(test_name, test_target, env : env, is_parallel : test[1])
endforeach

executable('ntlm-test-helper', 'ntlm-test-helper.c',
  dependencies : [glib_dep, libsoup_dep])

configure_file(output : 'httpd.conf',
  input : 'httpd.conf.in',
  configuration : cdata)

# There is not copy_file() in Meson and this is official workaround as per
# https://github.com/mesonbuild/meson/issues/860
configure_file(input : 'htdigest',
  output : 'htdigest',
  configuration : configuration_data())
configure_file(input : 'htpasswd',
  output : 'htpasswd',
  configuration : configuration_data())
configure_file(input : 'index.txt',
  output : 'index.txt',
  configuration : configuration_data())
configure_file(input : 'test-cert.pem',
  output : 'test-cert.pem',
  configuration : configuration_data())
configure_file(input : 'test-key.pem',
  output : 'test-key.pem',
  configuration : configuration_data())
configure_file(input : 'xmlrpc-server.php',
  output : 'xmlrpc-server.php',
  configuration : configuration_data())

gnome.compile_resources('soup-tests',
  'soup-tests.gresource.xml',
  gresource_bundle : true,
  install : true,
  install_dir : meson.current_build_dir() + '/tests')
