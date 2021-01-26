test_utils_name = 'test-utils'
installed_tests_execdir = join_paths(get_option('libexecdir'), 'installed-tests', libsoup_api_name)
installed_tests_enabled = get_option('installed_tests')
abs_installed_tests_execdir = join_paths(prefix, installed_tests_execdir)

if cc.get_id() == 'msvc'
  test_utils = static_library(test_utils_name, '../' + test_utils_name + '.c',
    dependencies : libsoup_static_dep)
else
  test_utils = library(test_utils_name, '../' + test_utils_name + '.c',
    dependencies : libsoup_static_dep,
    install : installed_tests_enabled,
    install_dir : installed_tests_execdir,
  )
endif

deps = [
  glib_deps,
  libsoup_dep
]

client = executable('soup-autobahn-test-client', 'soup-autobahn-test-client.c',
    dependencies: deps,
    link_with : test_utils
)
test('soup-autobahn-test-client', client, suite: 'autobahn', timeout: 3600)
