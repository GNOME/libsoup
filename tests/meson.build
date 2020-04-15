test_utils_name = 'test-utils'
installed_tests_metadir = join_paths(get_option('datadir'), 'installed-tests', libsoup_api_name)
installed_tests_execdir = join_paths(get_option('libexecdir'), 'installed-tests', libsoup_api_name)
installed_tests_enabled = get_option('installed_tests')
installed_tests_template_tap = files('template-tap.test.in')
abs_installed_tests_execdir = join_paths(prefix, installed_tests_execdir)

if cc.get_id() == 'msvc'
  test_utils = static_library(test_utils_name, test_utils_name + '.c',
    dependencies : libsoup_dep)
else
  test_utils = library(test_utils_name, test_utils_name + '.c',
    dependencies : libsoup_dep,
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
  )
endif

test_resources = gnome.compile_resources('soup-tests',
  'soup-tests.gresource.xml',
  gresource_bundle : true,
  install : installed_tests_enabled,
  install_dir : installed_tests_execdir,
)

if installed_tests_enabled
  install_data(
    'index.txt',
    'test-cert.pem',
    'test-key.pem',
    install_dir : installed_tests_execdir
  )
endif

# ['name', is_parallel, extra_deps]
tests = [
  ['cache', true, []],
  ['chunk', true, []],
  ['chunk-io', true, []],
  ['coding', true, []],
  ['context', true, []],
  ['continue', true, []],
  ['cookies', true, []],
  ['date', true, []],
  ['forms', true, []],
  ['header-parsing', true, []],
  ['hsts', true, []],
  ['hsts-db', true, []],
  ['misc', true, []],
  ['multipart', true, []],
  ['no-ssl', true, []],
  ['ntlm', true, []],
  ['redirect', true, []],
  ['requester', true, []],
  ['resource', true, []],
  ['samesite', true, []],
  ['session', true, []],
  ['server-auth', true, []],
  ['server', true, []],
  ['sniffing', true, []],
  ['socket', true, []],
  ['ssl', true, []],
  ['streaming', true, []],
  ['timeout', true, []],
  ['tld', true, []],
  ['uri-parsing', true, []],
  ['websocket', true, [libz_dep]]
]

if brotlidec_dep.found()
  tests += [
    ['brotli-decompressor', true, []],
  ]

  if installed_tests_enabled
    install_data(
      'brotli-data/compressed.br',
      'brotli-data/corrupt.br',
      'brotli-data/uncompressed.txt',
      install_dir : join_paths(installed_tests_execdir, 'brotli-data'),
    )
  endif
endif

if have_apache
  tests += [
    ['auth', false, []],
    ['connection', false, []],
    ['range', false, []],
    ['proxy', false, []],
    ['pull-api', false, []],
  ]

  configure_file(output : 'httpd.conf',
    input : 'httpd.conf.in',
    configuration : cdata,
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
  )

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

  if installed_tests_enabled
    install_data(
      'htdigest',
      'htpasswd',
      install_dir : installed_tests_execdir,
    )
  endif
endif

if have_php
  configure_file(output : 'php.ini',
    input : 'php.ini.in',
    configuration : cdata,
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
  )
endif

if have_php_xmlrpc
  tests += [
    ['xmlrpc-old-server', true, []],
    ['xmlrpc-old', false, []],
    ['xmlrpc-server', true, []],
    ['xmlrpc', false, []]
  ]

  configure_file(input : 'xmlrpc-server.php',
    output : 'xmlrpc-server.php',
    copy : true)

  if installed_tests_enabled
    install_data(
      'xmlrpc-server.php',
      install_dir : installed_tests_execdir,
    )
  endif
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

  if installed_tests_enabled
    test_conf = configuration_data()
    test_conf.set('installed_tests_dir', abs_installed_tests_execdir)
    test_conf.set('program', test_name)
    test_conf.set('env', '')
    test_conf.set('type', test[1] ? 'session' : 'session-exclusive')
    configure_file(
      input : installed_tests_template_tap,
      output : test_name + '.test',
      install_dir : installed_tests_metadir,
      configuration : test_conf,
    )
  endif

  test_deps = [ libsoup_dep ] + test[2]
  test_target = executable(test_name,
    sources : [ test_name + '.c', test_resources ],
    link_with : test_utils,
    dependencies : test_deps,
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
    install_rpath : abs_installed_tests_execdir,
  )
  # Increase the timeout as on some architectures the tests could be slower
  # than the default 30 seconds.
  test(test_name, test_target, env : env, is_parallel : test[1], timeout : 60)
endforeach

executable('ntlm-test-helper', 'ntlm-test-helper.c',
  dependencies : libsoup_dep,
  install : installed_tests_enabled,
  install_dir : installed_tests_execdir,
  install_rpath : abs_installed_tests_execdir,
)
