deps = [
  glib_deps,
  libsoup_dep
]

client = executable('soup-autobahn-test-client', 'soup-autobahn-test-client.c', dependencies: deps)

test('soup-autobahn-test-client', client, suite: 'autobahn', timeout: 3600)
