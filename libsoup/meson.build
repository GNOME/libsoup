soup_sources = [
  'soup-address.c',
  'soup-auth.c',
  'soup-auth-basic.c',
  'soup-auth-digest.c',
  'soup-auth-ntlm.c',
  'soup-auth-negotiate.c',
  'soup-auth-domain.c',
  'soup-auth-domain-basic.c',
  'soup-auth-domain-digest.c',
  'soup-auth-manager.c',
  'soup-body-input-stream.c',
  'soup-body-output-stream.c',
  'soup-cache.c',
  'soup-cache-client-input-stream.c',
  'soup-cache-input-stream.c',
  'soup-client-input-stream.c',
  'soup-connection.c',
  'soup-connection-auth.c',
  'soup-content-decoder.c',
  'soup-content-processor.c',
  'soup-content-sniffer.c',
  'soup-content-sniffer-stream.c',
  'soup-converter-wrapper.c',
  'soup-cookie.c',
  'soup-cookie-jar.c',
  'soup-cookie-jar-db.c',
  'soup-cookie-jar-text.c',
  'soup-date.c',
  'soup-directory-input-stream.c',
  'soup-filter-input-stream.c',
  'soup-form.c',
  'soup-headers.c',
  'soup-init.c',
  'soup-io-stream.c',
  'soup-logger.c',
  'soup-message.c',
  'soup-message-body.c',
  'soup-message-client-io.c',
  'soup-message-headers.c',
  'soup-message-io.c',
  'soup-message-queue.c',
  'soup-message-server-io.c',
  'soup-method.c',
  'soup-misc.c',
  'soup-multipart.c',
  'soup-multipart-input-stream.c',
  'soup-password-manager.c',
  'soup-path-map.c',
  'soup-proxy-resolver.c',
  'soup-proxy-resolver-default.c',
  'soup-proxy-resolver-wrapper.c',
  'soup-proxy-uri-resolver.c',
  'soup-request.c',
  'soup-request-data.c',
  'soup-request-file.c',
  'soup-request-http.c',
  'soup-requester.c',
  'soup-server.c',
  'soup-session.c',
  'soup-session-async.c',
  'soup-session-feature.c',
  'soup-session-sync.c',
  'soup-socket.c',
  'soup-socket-properties.c',
  'soup-status.c',
  'soup-tld.c',
  'soup-uri.c',
  'soup-value-utils.c',
  'soup-version.c',
  'soup-websocket.c',
  'soup-websocket-connection.c',
  'soup-xmlrpc.c',
  'soup-xmlrpc-old.c',
]

soup_headers = [
  'soup.h',
  'soup-address.h',
  'soup-auth.h',
  'soup-auth-domain.h',
  'soup-auth-domain-basic.h',
  'soup-auth-domain-digest.h',
  'soup-auth-manager.h',
  'soup-autocleanups.h',
  'soup-cache.h',
  'soup-content-decoder.h',
  'soup-content-sniffer.h',
  'soup-cookie.h',
  'soup-cookie-jar.h',
  'soup-cookie-jar-db.h',
  'soup-cookie-jar-text.h',
  'soup-date.h',
  'soup-form.h',
  'soup-headers.h',
  'soup-logger.h',
  'soup-message.h',
  'soup-message-body.h',
  'soup-message-headers.h',
  'soup-method.h',
  'soup-misc.h',
  'soup-multipart.h',
  'soup-multipart-input-stream.h',
  'soup-password-manager.h',
  'soup-portability.h',
  'soup-proxy-resolver.h',
  'soup-proxy-resolver-default.h',
  'soup-proxy-uri-resolver.h',
  'soup-request.h',
  'soup-request-data.h',
  'soup-request-file.h',
  'soup-request-http.h',
  'soup-requester.h',
  'soup-server.h',
  'soup-session.h',
  'soup-session-async.h',
  'soup-session-feature.h',
  'soup-session-sync.h',
  'soup-socket.h',
  'soup-status.h',
  'soup-tld.h',
  'soup-types.h',
  'soup-uri.h',
  'soup-value-utils.h',
  'soup-websocket.h',
  'soup-websocket-connection.h',
  'soup-xmlrpc.h',
  'soup-xmlrpc-old.h',
]

soup_gnome_sources = [
  'soup-cookie-jar-sqlite.c',
  'soup-gnome-features.c',
  'soup-proxy-resolver-gnome.c',
  'soup-password-manager-gnome.c'
]

soup_gnome_headers = [
  'soup-proxy-resolver-gnome.h',
  'soup-password-manager-gnome.h'
]

soup_gnome_include_headers = [
  'soup-cookie-jar-sqlite.h',
  'soup-gnome.h',
  'soup-gnome-features.h'
]

includedir = 'libsoup-@0@/libsoup'.format(apiversion)
install_headers(soup_headers, subdir : includedir)

version_cdata = configuration_data()
version_cdata.set('SOUP_MAJOR_VERSION', soup_version_major)
version_cdata.set('SOUP_MINOR_VERSION', soup_version_minor)
version_cdata.set('SOUP_MICRO_VERSION', soup_version_micro)

configure_file(input : 'soup-version.h.in',
  output : 'soup-version.h',
  install_dir : join_paths(get_option('includedir'), includedir),
  configuration : version_cdata)

soup_enums = gnome.mkenums('soup-enum-types',
  sources : soup_headers,
  h_template : 'soup-enum-types.h.template',
  c_template : 'soup-enum-types.c.template',
  install_header : true,
  install_dir : join_paths(get_option('includedir'), includedir))

soupenum_h = soup_enums[1]
soupenum_c = soup_enums[0]

tldparser = find_program(join_paths(meson.current_source_dir(), 'tld-parser.py'))
tlddata = custom_target('tlddata',
  output : 'tld_data.inc',
  input : join_paths(meson.source_root(), 'data', 'effective_tld_names.dat'),
  install : false,
  command : [tldparser, '@INPUT@', '@OUTPUT@'])

libsoup_c_args  = ['-DHAVE_CONFIG_H']
libsoup_c_args += ['-DG_LOG_DOMAIN="libsoup"']
libsoup_c_args += ['-DLIBSOUP_COMPILATION']

deps = [
  glib_dep,
  libxml_dep,
  sqlite_dep,
  platform_deps
]

libsoup = library('soup-@0@'.format(apiversion), soup_sources,
  soup_enums, tlddata,
  version : libversion,
  soversion : soversion,
  c_args : libsoup_c_args,
  include_directories : [configinc],
  install : true,
  dependencies : deps
)

libsoup_dep = declare_dependency(link_with : libsoup,
  include_directories : configinc,
  sources : soup_enums)

if cdata.get('BUILD_LIBSOUP_GNOME')
  includedir = 'libsoup-gnome-@0@/libsoup'.format(apiversion)
  install_headers(
    soup_gnome_headers + ['soup-gnome.h', 'soup-gnome-features.h'],
    subdir : includedir)

  libsoup_gnome = library('soup-gnome-@0@'.format(apiversion), soup_gnome_sources,
    version : libversion,
    soversion : soversion,
    c_args : libsoup_c_args,
    include_directories : [configinc],
    install : true,
    dependencies : [deps, libsoup_dep])
endif

if get_option('enable-introspection') or get_option('enable-vala')
  soup_introspection_sources = [
    'soup-address.c',
    'soup-address.h',
    'soup-auth-basic.c',
    'soup-auth.c',
    'soup-auth-digest.c',
    'soup-auth-domain-basic.c',
    'soup-auth-domain-basic.h',
    'soup-auth-domain.c',
    'soup-auth-domain-digest.c',
    'soup-auth-domain-digest.h',
    'soup-auth-domain.h',
    'soup-auth.h',
    'soup-auth-manager.c',
    'soup-auth-manager.h',
    'soup-auth-negotiate.c',
    'soup-auth-ntlm.c',
    'soup-autocleanups.h',
    'soup-body-input-stream.c',
    'soup-body-output-stream.c',
    'soup-cache.c',
    'soup-cache-client-input-stream.c',
    'soup-cache.h',
    'soup-cache-input-stream.c',
    'soup-client-input-stream.c',
    'soup-connection-auth.c',
    'soup-connection.c',
    'soup-content-decoder.c',
    'soup-content-decoder.h',
    'soup-content-processor.c',
    'soup-content-sniffer.c',
    'soup-content-sniffer.h',
    'soup-content-sniffer-stream.c',
    'soup-converter-wrapper.c',
    'soup-cookie.c',
    'soup-cookie.h',
    'soup-cookie-jar.c',
    'soup-cookie-jar-db.c',
    'soup-cookie-jar-db.h',
    'soup-cookie-jar.h',
    'soup-cookie-jar-text.c',
    'soup-cookie-jar-text.h',
    'soup-date.c',
    'soup-date.h',
    'soup-directory-input-stream.c',
    'soup-filter-input-stream.c',
    'soup-form.c',
    'soup-form.h',
    'soup-headers.c',
    'soup-headers.h',
    'soup-init.c',
    'soup-io-stream.c',
    'soup-logger.c',
    'soup-logger.h',
    'soup-message-body.c',
    'soup-message-body.h',
    'soup-message.c',
    'soup-message-client-io.c',
    'soup-message.h',
    'soup-message-headers.c',
    'soup-message-headers.h',
    'soup-message-io.c',
    'soup-message-queue.c',
    'soup-message-server-io.c',
    'soup-method.c',
    'soup-method.h',
    'soup-misc.c',
    'soup-misc.h',
    'soup-multipart.c',
    'soup-multipart.h',
    'soup-multipart-input-stream.c',
    'soup-multipart-input-stream.h',
    'soup-password-manager.c',
    'soup-password-manager.h',
    'soup-path-map.c',
    'soup-portability.h',
    'soup-proxy-resolver.c',
    'soup-proxy-resolver-default.c',
    'soup-proxy-resolver-default.h',
    'soup-proxy-resolver-wrapper.c',
    'soup-proxy-uri-resolver.c',
    'soup-proxy-uri-resolver.h',
    'soup-request.c',
    'soup-request-data.c',
    'soup-request-data.h',
    'soup-requester.c',
    'soup-requester.h',
    'soup-request-file.c',
    'soup-request-file.h',
    'soup-request.h',
    'soup-request-http.c',
    'soup-request-http.h',
    'soup-server.c',
    'soup-server.h',
    'soup-session-async.c',
    'soup-session-async.h',
    'soup-session.c',
    'soup-session-feature.c',
    'soup-session-feature.h',
    'soup-session.h',
    'soup-session-sync.c',
    'soup-session-sync.h',
    'soup-socket.c',
    'soup-socket.h',
    'soup-socket-properties.c',
    'soup-status.c',
    'soup-status.h',
    'soup-tld.c',
    'soup-tld.h',
    'soup-types.h',
    'soup-uri.c',
    'soup-uri.h',
    'soup-value-utils.c',
    'soup-value-utils.h',
    'soup-version.c',
    'soup-websocket.c',
    'soup-websocket-connection.c',
    'soup-websocket-connection.h',
    'soup-websocket.h',
    'soup-xmlrpc.c',
    'soup-xmlrpc.h',
    'soup-xmlrpc-old.c',
    'soup-xmlrpc-old.h',
  ]

  gir_args = libsoup_c_args + [
    '-DLIBSOUP_USE_UNSTABLE_REQUEST_API',
    '--c-include=libsoup/soup.h'
  ]

  soup_gir_gen_sources = [gnome.generate_gir(libsoup,
    sources : soup_introspection_sources + [soupenum_h, soupenum_c],
    nsversion : '2.4',
    namespace : 'Soup',
    symbol_prefix : 'soup_',
    identifier_prefix : 'Soup',
    export_packages : 'libsoup-2.4',
    extra_args : gir_args,
    dependencies : [deps, libsoup],
    includes : ['Gio-2.0'],
    install : true,
  )]

  soup_gir_gen_dep = declare_dependency(link_with : libsoup,
    include_directories : [configinc],
    dependencies : deps,
    sources : soup_gir_gen_sources)

  if get_option('enable-vala')
    gnome.generate_vapi('libsoup-2.4',
      sources : [soup_gir_gen_sources[0][0]],
      packages : ['gio-2.0'],
      install : true,
    )
  endif

  if get_option('enable-gnome')
    gir_gnome_args = libsoup_c_args + [
      '--identifier-prefix=Soup',
      '--symbol-prefix=soup',
      '--c-include=libsoup/soup-gnome.h',
      '--include-uninstalled=@0@/Soup-2.4.gir'.format(meson.current_build_dir())
    ]

    gnome.generate_gir(libsoup_gnome,
      sources : [
        soup_gnome_sources,
        soupenum_c,
        soupenum_h,
        'soup-cookie-jar-sqlite.h',
        'soup-gnome-features.h'
      ],
      nsversion : '2.4',
      namespace : 'SoupGNOME',
      symbol_prefix : 'soup_',
      identifier_prefix : 'Soup',
      export_packages : 'libsoup-gnome-2.4',
      extra_args : gir_gnome_args,
      dependencies : [deps, libsoup, libsoup_gnome, soup_gir_gen_dep],
      includes : ['Gio-2.0'],
      install : true,
    )
  endif
endif
