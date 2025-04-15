test_utils_name = 'test-utils'
installed_tests_metadir = join_paths(get_option('datadir'), 'installed-tests', libsoup_api_name)
installed_tests_execdir = join_paths(get_option('libexecdir'), 'installed-tests', libsoup_api_name)
installed_tests_enabled = get_option('installed_tests')
installed_tests_template_tap = files('template-tap.test.in')
abs_installed_tests_execdir = join_paths(prefix, installed_tests_execdir)

if get_option('pkcs11_tests').enabled()
  assert(gnutls_dep.found()) # Required earlier.
  enable_pkcs11_tests = true
elif get_option('pkcs11_tests').auto()
  enable_pkcs11_tests = gnutls_dep.found()
else
  enable_pkcs11_tests = false
endif

if cc.get_id() == 'msvc'
  test_utils = static_library(test_utils_name, test_utils_name + '.c',
    dependencies : [ libsoup_static_dep, unix_socket_dep ])
else
  test_utils = library(test_utils_name, test_utils_name + '.c',
    dependencies : [ libsoup_static_dep, unix_socket_dep ],
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

if enable_pkcs11_tests
  mock_pkcs11_module = shared_module('mock-pkcs11',
      sources: 'mock-pkcs11.c',
      name_prefix: '',
      gnu_symbol_visibility: 'hidden',
      include_directories: include_directories('pkcs11'),
      dependencies: [
        gio_dep,
        gnutls_dep,
      ],
      install: installed_tests_enabled,
      install_dir: installed_tests_execdir
    )
else
  mock_pkcs11_module = []
endif

configure_file(input : 'index.txt',
  output : 'index.txt',
  copy : true)
configure_file(input : 'test-cert.pem',
  output : 'test-cert.pem',
  copy : true)
configure_file(input : 'test-key.pem',
  output : 'test-key.pem',
  copy : true)
configure_file(input : 'test-cert-2.pem',
  output : 'test-cert-2.pem',
  copy : true)
configure_file(input : 'test-key-2.pem',
  output : 'test-key-2.pem',
  copy : true)

if installed_tests_enabled
  install_data(
    'index.txt',
    'test-cert.pem',
    'test-key.pem',
    'test-cert-2.pem',
    'test-key-2.pem',
    install_dir : installed_tests_execdir
  )
endif

# ['name', is_parallel, extra_deps]
tests = [
  {'name': 'cache'},
  {'name': 'chunk-io'},
  {'name': 'coding'},
  {'name': 'context'},
  {'name': 'continue'},
  {'name': 'cookies'},
  {'name': 'date'},
  {'name': 'forms'},
  {'name': 'header-parsing'},
  {'name': 'http2', 'slow': true},
  {'name': 'http2-body-stream', 'slow': true},
  {'name': 'hsts'},
  {'name': 'hsts-db'},
  {'name': 'logger'},
  {'name': 'misc'},
  {'name': 'multipart'},
  {'name': 'multithread'},
  {'name': 'no-ssl'},
  {'name': 'ntlm'},
  {'name': 'range', 'parallel': false},
  {'name': 'redirect'},
  {'name': 'request-body'},
  {'name': 'samesite'},
  {'name': 'session'},
  {'name': 'server-auth'},
  {'name': 'server-mem-limit'},
  {'name': 'server'},
  {'name': 'sniffing',
    'depends': [test_resources],
  },
  {'name': 'ssl',
   'dependencies': [gnutls_dep],
   'depends': mock_pkcs11_module,
   'c_args': [
      '-DHAVE_GNUTLS=@0@'.format(gnutls_dep.found() ? 1 : 0),
      '-DENABLE_PKCS11_TESTS=@0@'.format(enable_pkcs11_tests ? 1 : 0),
   ]
  },
  {'name': 'streaming'},
  {'name': 'timeout', 'slow': true},
  {'name': 'tld'},
  {'name': 'uri-parsing'},
  {'name': 'websocket',
   'dependencies': [libz_dep],
   'slow': true},
]

if brotlidec_dep.found()
  tests += [{'name': 'brotli-decompressor'}]

  if installed_tests_enabled
    install_data(
      'brotli-data/compressed.br',
      'brotli-data/corrupt.br',
      'brotli-data/uncompressed.txt',
      install_dir : join_paths(installed_tests_execdir, 'brotli-data'),
    )
  endif
endif

if unix_socket_dep.found()
  tests += [{
    'name': 'unix-socket',
    'dependencies': [unix_socket_dep],
  }]
endif

if have_apache
  tests += [
    {'name': 'auth', 'parallel': false},
    {'name': 'connection', 'parallel': false},
    {'name': 'proxy', 'parallel': false},
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

  if installed_tests_enabled
    install_data(
      'htdigest',
      'htpasswd',
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

if meson.version().version_compare('>= 0.58.0')
  meson.add_devenv(env)
endif

if have_autobahn
   subdir('autobahn')
endif

foreach test: tests
  test_name = '@0@-test'.format(test['name'])

  if installed_tests_enabled
    test_conf = configuration_data()
    test_conf.set('installed_tests_dir', abs_installed_tests_execdir)
    test_conf.set('program', test_name)
    test_conf.set('env', '')
    test_conf.set('type', test.get('parallel', true) ? 'session' : 'session-exclusive')
    configure_file(
      input : installed_tests_template_tap,
      output : test_name + '.test',
      install_dir : installed_tests_metadir,
      configuration : test_conf,
    )
  endif

  test_deps = [ libsoup_static_dep ] + test.get('dependencies', [])
  test_target = executable(test_name,
    sources : [ test_name + '.c', test_resources ],
    c_args : test.get('c_args', []),
    include_directories : test.get('includes', []),
    link_with : test_utils,
    dependencies : test_deps,
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
    install_rpath : abs_installed_tests_execdir,
  )

  test(test_name, test_target,
    args : ['--debug'],
    env : env,
    is_parallel : test.get('parallel', true),
    depends : test.get('depends', []),
    timeout : test.get('slow', false) ? 300 : 30,
    protocol : 'tap',
  )
endforeach

executable('ntlm-test-helper', 'ntlm-test-helper.c',
  dependencies : libsoup_dep,
  install : installed_tests_enabled,
  install_dir : installed_tests_execdir,
  install_rpath : abs_installed_tests_execdir,
)

if unix_socket_dep.found()
  executable('ws-test-helper', 'ws-test-helper.c',
    dependencies : [libsoup_dep, unix_socket_dep],
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
    install_rpath : abs_installed_tests_execdir,
  )
endif
