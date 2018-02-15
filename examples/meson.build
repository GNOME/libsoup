deps = [
  glib_dep,
  libsoup_dep
]

examples = [
  'get',
  'simple-httpd',
  'simple-proxy'
]

foreach example: examples
  executable(example, example + '.c', dependencies: deps)
endforeach
