autobahn_conf = configuration_data()
autobahn_conf.set('MESON_BUILD_ROOT', meson.build_root())

configure_file(
  input : 'autobahn-server.json.in',
  output : 'autobahn-server.json',
  configuration : autobahn_conf,
)

client = executable('autobahn-test', 'autobahn-test.c',
    link_with : test_utils,
    dependencies : libsoup_static_dep,
    include_directories : include_directories('..'),
)

test('autobahn-test', client,
  suite : 'autobahn',
  env : env,
  timeout : 3600,
  protocol : 'tap',
)
