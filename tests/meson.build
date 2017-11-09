libtest = library('libtest', 'test-utils.c', 'test-utils.h',
  install : false,
  c_args : '-DAPACHE_HTTPD=' + cdata.get('APACHE_HTTPD'),
  dependencies : [glib_dep, libsoup_dep])

auth_test = executable('auth-test', 'auth-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

cache_test = executable('cache-test', 'cache-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

chunk_test = executable('chunk-test', 'chunk-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

chunk_io_test = executable('chunk-io-test', 'chunk-io-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

coding_test = executable('coding-test', 'coding-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

connection_test = executable('connection-test', 'connection-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

context_test = executable('context-test', 'context-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

continue_test = executable('continue-test', 'continue-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

cookies_test = executable('cookies-test', 'cookies-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

date_test = executable('date-test', 'date-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

forms_test = executable('forms-test', 'forms-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

header_parsing_test = executable('header-parsing-test', 'header-parsing-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

misc_test = executable('misc-test', 'misc-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

multipart_test = executable('multipart-test', 'multipart-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

no_ssl_test = executable('no-ssl-test', 'no-ssl-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

ntlm_test = executable('ntlm-test', 'ntlm-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

proxy_test = executable('proxy-test', 'proxy-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

pull_api_test = executable('pull-api-test', 'pull-api-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

range_test = executable('range-test', 'range-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

redirect_test = executable('redirect-test', 'redirect-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

requester_test = executable('requester-test', 'requester-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

resource_test = executable('resource-test', 'resource-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

session_test = executable('session-test', 'session-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

server_auth_test = executable('server-auth-test', 'server-auth-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

server_test = executable('server-test', 'server-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

sniffing_test = executable('sniffing-test', 'sniffing-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

socket_test = executable('socket-test', 'socket-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

ssl_test = executable('ssl-test', 'ssl-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

streaming_test = executable('streaming-test', 'streaming-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

timeout_test = executable('timeout-test', 'timeout-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

tld_test = executable('tld-test', 'tld-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

uri_parsing_test = executable('uri-parsing-test', 'uri-parsing-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

websocket_test = executable('websocket-test', 'websocket-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

xmlrpc_old_server_test = executable('xmlrpc-old-server-test', 'xmlrpc-old-server-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

xmlrpc_old_test = executable('xmlrpc-old-test', 'xmlrpc-old-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

xmlrpc_server_test = executable('xmlrpc-server-test', 'xmlrpc-server-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

xmlrpc_test = executable('xmlrpc-test', 'xmlrpc-test.c',
  link_with: libtest,
  dependencies : [glib_dep, libsoup_dep])

xmlrpc_test = executable('ntlm-test-helper', 'ntlm-test-helper.c',
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
