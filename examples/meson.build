deps = [
  glib_deps,
  libsoup_dep
]

examples = [
  'get',
  'simple-httpd',
  'simple-proxy'
]

if unix_socket_dep.found()
  examples += [ 'unix-socket-client' ]
  examples += [ 'unix-socket-server' ]
  deps += [ unix_socket_dep ]
endif

foreach example: examples
  executable(example, example + '.c', dependencies: deps)
endforeach
