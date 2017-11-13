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

foreach test: tests
    auth_test = executable('@0@-test'.format(test), '@0@-test.c'.format(test),
      link_with: test_utils,
      dependencies : [glib_dep, libsoup_dep])
endforeach

executable('ntlm-test-helper', 'ntlm-test-helper.c',
  dependencies : [glib_dep, libsoup_dep])

configure_file(output : 'httpd.conf',
  input : 'httpd.conf.in',
  configuration : cdata)

gnome.compile_resources('soup-tests',
  'soup-tests.gresource.xml',
  gresource_bundle : true,
  install : true,
  install_dir : meson.current_build_dir() + '/tests',
  source_dir : '.')
