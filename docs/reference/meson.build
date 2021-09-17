ignore_headers = [
  'soup.h',
  'soup-autocleanups.h',
  'soup-enum-types.h',
  'soup-message-private.h',
  'soup-session-private.h',
  'soup-auth-basic.h',
  'soup-auth-digest.h',
  'soup-auth-ntlm.h',
  'soup-auth-negotiate.h',
  'soup-brotli-decompressor.h',
  'soup-connection.h',
  'soup-connection-auth.h',
  'soup-message-queue.h',
  'soup-path-map.h',
  'soup-gnome-features.h',
  'soup-proxy-resolver.h',
  'soup-proxy-resolver-gnome.h',
  'soup-proxy-resolver-static.h',
  'soup-directory-input-stream.h',
  'soup-http-input-stream.h',
  'soup-password-manager.h',
  'soup-password-manager-gnome.h',
  'soup-converter-wrapper.h',
  'soup-body-input-stream.h',
  'soup-body-output-stream.h',
  'soup-client-input-stream.h',
  'soup-content-processor.h',
  'soup-content-sniffer-stream.h',
  'soup-io-stream.h',
  'soup-cache-input-stream.h',
  'soup-filter-input-stream.h',
  'soup-cookie-jar-sqlite.h',
  'soup-requester.h',
  'soup-misc-private.h',
  'soup-proxy-uri-resolver.h',
  'soup-proxy-resolver-wrapper.h',
  'soup-proxy-uri-resolver.h',
  'soup-cache-private.h',
  'soup-cache-client-input-stream.h',
  'soup-socket-private.h',
  'soup-value-utils.h',
  'soup-websocket-extension-manager-private.h',
  'soup-xmlrpc-old.h'
]

mkdb_args = [
  '--sgml-mode',
  '--output-format=xml'
]

scan_args = [
  '--deprecated-guards=SOUP_DISABLE_DEPRECATED',
  '--rebuild-types',
  '--ignore-decorators="SOUP_DEPRECATED\w*\s*()|SOUP_DEPRECATED\w*|SOUP_AVAILABLE[\w_]*"'
]

gnome.gtkdoc('libsoup-2.4',
  main_sgml : 'libsoup-2.4-docs.sgml',
  src_dir : srcdir,
  ignore_headers : ignore_headers,
  namespace : 'soup',
  mkdb_args : mkdb_args,
  scan_args : scan_args,
  dependencies : libsoup_dep,
  install : true,
  content_files: [
    'build-howto.xml',
    'client-howto.xml',
    'request-howto.xml',
    'server-howto.xml',
    'session-porting.xml',
  ]
)
