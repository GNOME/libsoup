ignore_headers = [
  'gconstructor.h',
  'soup.h',
  'soup-enum-types.h',
  'soup-message-private.h',
  'soup-session-private.h',
  'soup-auth-digest-private.h',
  'soup-brotli-decompressor.h',
  'soup-connection.h',
  'soup-connection-auth.h',
  'soup-message-queue-item.h',
  'soup-path-map.h',
  'soup-http-input-stream.h',
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
  'soup-cache-private.h',
  'soup-cache-client-input-stream.h',
  'soup-socket.h',
  'soup-socket-properties.h',
  'soup-websocket-extension-manager-private.h',
  'soup-misc.h',
  'soup-date-utils-private.h',
  'soup-resources.h',
  'soup-private-enum-types.h',
  'soup-server-message-private.h',
  'soup-message-io-data.h',
  'soup-uri-utils-private.h',
  'soup-session-feature-private.h',
]

mkdb_args = [
  '--output-format=xml'
]

scan_args = [
  '--deprecated-guards=SOUP_DISABLE_DEPRECATED',
  '--rebuild-types',
  '--ignore-decorators="SOUP_DEPRECATED\w*\s*\([^)]*\)|SOUP_DEPRECATED\w*|SOUP_AVAILABLE\w*"'
]

glib_prefix = glib_dep.get_pkgconfig_variable('prefix')
glib_docpath = glib_prefix / 'share' / 'gtk-doc' / 'html'

gnome.gtkdoc('libsoup-3.0',
  main_xml : 'libsoup-3.0-docs.xml',
  src_dir : srcdir,
  ignore_headers : ignore_headers,
  namespace : 'soup',
  mkdb_args : mkdb_args,
  scan_args : scan_args,
  fixxref_args : [
    '--html-dir=@0@'.format(get_option('datadir') / 'gtk-doc', 'html'),
    '--extra-dir=@0@'.format(glib_docpath / 'glib'),
    '--extra-dir=@0@'.format(glib_docpath /'gobject'),
    '--extra-dir=@0@'.format(glib_docpath /'gio'),
  ],
  dependencies : libsoup_dep,
  install : true,
  content_files: [
    'build-howto.xml',
    'client-basic.xml',
    'client-advanced.xml',
    'client-tls.xml',
    'server-howto.xml',
    'migrating-from-libsoup-2.xml',
  ],
)
