test_utils_name = 'test-utils'

if cc.get_id() == 'msvc'
  test_utils = static_library(test_utils_name, test_utils_name + '.c',
    dependencies : libsoup_dep)
else
  test_utils = library(test_utils_name, test_utils_name + '.c',
    dependencies : libsoup_dep)
endif

test_resources = gnome.compile_resources('soup-tests',
  'soup-tests.gresource.xml',
  gresource_bundle : true)

# ['name', is_parallel]
tests = [
  ['cache', true],
  ['chunk', true],
  ['chunk-io', true],
  ['coding', true],
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
  ['websocket', true]
]

if have_apache
  tests += [
    ['auth', false],
    ['connection', false],
    ['range', false],
    ['proxy', false],
    ['pull-api', false],
  ]

  configure_file(output : 'httpd.conf',
    input : 'httpd.conf.in',
    configuration : cdata)

  configure_file(input : 'htdigest',
    output : 'htdigest',
    copy : true)
  configure_file(input : 'htpasswd',
    output : 'htpasswd',
    copy : true)
  configure_file(input : 'index.txt',
    output : 'index.txt',
    copy : true)
  configure_file(input : 'test-cert.pem',
    output : 'test-cert.pem',
    copy : true)
  configure_file(input : 'test-key.pem',
    output : 'test-key.pem',
    copy : true)
endif

if have_php
  configure_file(output : 'php.ini',
    input : 'php.ini.in',
    configuration : cdata)
endif

if have_php_xmlrpc
  tests += [
    ['xmlrpc-old-server', true, have_php_xmlrpc],
    ['xmlrpc-old', false, have_php_xmlrpc],
    ['xmlrpc-server', true, have_php_xmlrpc],
    ['xmlrpc', false, have_php_xmlrpc]
  ]

  configure_file(input : 'xmlrpc-server.php',
    output : 'xmlrpc-server.php',
    copy : true)
endif

env = environment()
env.set('G_TEST_SRCDIR', meson.current_source_dir())
env.set('G_TEST_BUILDDIR', meson.current_build_dir())
env.set('G_DEBUG', 'gc-friendly')
# See https://github.com/mesonbuild/meson/issues/1383 for the workaround below
env.prepend('LD_LIBRARY_PATH', meson.build_root() + '/libsoup')
env.set('MALLOC_CHECK_', '2')
# This is set by Meson if empty
env.set('MALLOC_PERTURB_', '')

foreach test: tests
  test_name = '@0@-test'.format(test[0])
  test_target = executable(test_name,
    sources : [ test_name + '.c', test_resources ],
    link_with : test_utils,
    dependencies : libsoup_dep)
  # Increase the timeout as on some architectures the tests could be slower
  # than the default 30 seconds.
  test(test_name, test_target, env : env, is_parallel : test[1], timeout : 60)
endforeach

executable('ntlm-test-helper', 'ntlm-test-helper.c',
  dependencies : libsoup_dep)
