includedir = join_paths(libsoup_api_name, meson.project_name())
subdir('include')

pkg = import('pkgconfig')

soup_sources = [
  'auth/soup-auth.c',
  'auth/soup-auth-basic.c',
  'auth/soup-auth-digest.c',
  'auth/soup-auth-ntlm.c',
  'auth/soup-auth-negotiate.c',
  'auth/soup-auth-manager.c',
  'auth/soup-connection-auth.c',
  'auth/soup-tls-interaction.c',

  'cache/soup-cache.c',
  'cache/soup-cache-client-input-stream.c',
  'cache/soup-cache-input-stream.c',

  'content-decoder/soup-content-decoder.c',
  'content-decoder/soup-content-processor.c',
  'content-decoder/soup-converter-wrapper.c',

  'content-sniffer/soup-content-sniffer.c',
  'content-sniffer/soup-content-sniffer-stream.c',

  'cookies/soup-cookie.c',
  'cookies/soup-cookie-jar.c',
  'cookies/soup-cookie-jar-db.c',
  'cookies/soup-cookie-jar-text.c',

  'hsts/soup-hsts-enforcer.c',
  'hsts/soup-hsts-enforcer-db.c',
  'hsts/soup-hsts-policy.c',

  'http1/soup-client-message-io-http1.c',
  'http1/soup-body-input-stream.c',
  'http1/soup-body-output-stream.c',
  'http1/soup-message-io-data.c',
  'http1/soup-message-io-source.c',

  'http2/soup-client-message-io-http2.c',
  'http2/soup-body-input-stream-http2.c',

  'server/http1/soup-server-message-io-http1.c',
  'server/http2/soup-server-message-io-http2.c',
  'server/soup-auth-domain.c',
  'server/soup-auth-domain-basic.c',
  'server/soup-auth-domain-digest.c',
  'server/soup-listener.c',
  'server/soup-message-body.c',
  'server/soup-path-map.c',
  'server/soup-server.c',
  'server/soup-server-connection.c',
  'server/soup-server-message.c',
  'server/soup-server-message-io.c',

  'websocket/soup-websocket.c',
  'websocket/soup-websocket-connection.c',
  'websocket/soup-websocket-extension.c',
  'websocket/soup-websocket-extension-deflate.c',
  'websocket/soup-websocket-extension-manager.c',

  'soup-client-input-stream.c',
  'soup-client-message-io.c',
  'soup-connection.c',
  'soup-connection-manager.c',
  'soup-date-utils.c',
  'soup-filter-input-stream.c',
  'soup-form.c',
  'soup-headers.c',
  'soup-header-names.c',
  'soup-http2-utils.c',
  'soup-init.c',
  'soup-io-stream.c',
  'soup-logger.c',
  'soup-logger-input-stream.c',
  'soup-message.c',
  'soup-message-headers.c',
  'soup-message-metrics.c',
  'soup-message-queue-item.c',
  'soup-method.c',
  'soup-misc.c',
  'soup-multipart.c',
  'soup-multipart-input-stream.c',
  'soup-session.c',
  'soup-session-feature.c',
  'soup-socket-properties.c',
  'soup-status.c',
  'soup-tld.c',
  'soup-uri-utils.c',
  'soup-version.c',
]

soup_private_enum_headers = [
  'soup-connection.h',
]

soup_introspection_headers = [
  'auth/soup-auth.h',
  'auth/soup-auth-manager.h',

  'cache/soup-cache.h',

  'content-decoder/soup-content-decoder.h',

  'content-sniffer/soup-content-sniffer.h',

  'cookies/soup-cookie.h',
  'cookies/soup-cookie-jar.h',
  'cookies/soup-cookie-jar-db.h',
  'cookies/soup-cookie-jar-text.h',

  'hsts/soup-hsts-enforcer.h',
  'hsts/soup-hsts-enforcer-db.h',
  'hsts/soup-hsts-policy.h',

  'server/soup-auth-domain.h',
  'server/soup-auth-domain-basic.h',
  'server/soup-auth-domain-digest.h',
  'server/soup-message-body.h',
  'server/soup-server.h',
  'server/soup-server-message.h',

  'websocket/soup-websocket.h',
  'websocket/soup-websocket-connection.h',
  'websocket/soup-websocket-extension.h',
  'websocket/soup-websocket-extension-deflate.h',
  'websocket/soup-websocket-extension-manager.h',

  'soup-date-utils.h',
  'soup-form.h',
  'soup-headers.h',
  'soup-logger.h',
  'soup-message.h',
  'soup-message-headers.h',
  'soup-message-metrics.h',
  'soup-method.h',
  'soup-multipart.h',
  'soup-multipart-input-stream.h',
  'soup-session.h',
  'soup-session-feature.h',
  'soup-status.h',
  'soup-tld.h',
  'soup-types.h',
  'soup-uri-utils.h',
]

soup_installed_headers = soup_introspection_headers

if brotlidec_dep.found()
  soup_sources += 'content-decoder/soup-brotli-decompressor.c'
endif


install_headers(soup_installed_headers, subdir : includedir)

soup_version_h = configure_file(
  input : 'soup-version.h.in',
  output : 'soup-version.h',
  install_dir : join_paths(get_option('includedir'), includedir),
  command : [find_program('generate-version-header.py'), '@INPUT@', '@OUTPUT@', meson.project_version()]
)

enum_types = 'soup-enum-types'
soup_enums = gnome.mkenums('soup-enum-types',
  sources : soup_installed_headers,
  h_template : enum_types + '.h.template',
  c_template : enum_types + '.c.template',
  install_header : true,
  install_dir : join_paths(get_option('includedir'), includedir))

soup_enum_h = soup_enums[1]
soup_enum_c = soup_enums[0]

soup_private_enums = gnome.mkenums_simple('soup-private-enum-types',
  sources : soup_private_enum_headers,
)

libsoup_c_args  = [
  '-DG_LOG_DOMAIN="@0@"'.format(meson.project_name()),
  '-DLIBSOUP_COMPILATION'
]

deps = [
  libsysprof_capture_dep,
  glib_deps,
  sqlite_dep,
  libpsl_dep,
  brotlidec_dep,
  platform_deps,
  gssapi_dep,
  libz_dep,
  libnghttp2_dep,
]

libsoup_includes = [
  configinc,
  include_directories([
    'auth',
    'cookies',
    'content-decoder',
    'hsts',
    'http1',
    'http2',
    'server',
    'server/http1',
    'server/http2',
    'websocket',
    '.'
  ]),
]

libsoup = library('soup-@0@'.format(apiversion),
  sources : [
    soup_sources,
    soup_private_enums,
    soup_enums,
  ],
  version : libversion,
  darwin_versions: darwin_versions,
  c_args : libsoup_c_args,
  include_directories : libsoup_includes,
  gnu_symbol_visibility: 'hidden',
  install : true,
  dependencies : deps)

libsoup_static = static_library('soup-@0@-static'.format(apiversion),
  sources : [
    soup_sources,
    soup_private_enums,
    soup_enums,
  ],
  c_args : libsoup_c_args,
  include_directories : libsoup_includes,
  dependencies : deps,
)

pkg.generate(libsoup,
  libraries : glib_deps,
  name : meson.project_name(),
  description : 'A glib-based HTTP library',
  filebase : libsoup_api_name,
  subdirs: libsoup_api_name,
  variables: 'exec_prefix=${prefix}')

libsoup_dep = declare_dependency(link_with : libsoup,
  include_directories : libsoup_includes,
  sources : soup_enum_h,
  dependencies : [ platform_deps, gssapi_dep, glib_deps ]
)

meson.override_dependency('libsoup-3.0', libsoup_dep)

libsoup_static_dep = declare_dependency(link_with : libsoup_static,
  include_directories : libsoup_includes,
  sources : soup_enum_h,
  dependencies : [ platform_deps, gssapi_dep, glib_deps ]
)

if enable_introspection or enable_vapi
  soup_ns = 'Soup'

  soup_gir_gen_sources = gnome.generate_gir(libsoup,
    sources : [
      soup_sources,
      soup_introspection_headers,
      soup_enum_h,
      soup_version_h
    ],
    dependencies : libsoup_dep,
    nsversion : apiversion,
    namespace : soup_ns,
    symbol_prefix : soup_ns.to_lower(),
    identifier_prefix : soup_ns,
    export_packages : libsoup_api_name,
    extra_args : libsoup_c_args,
    includes : 'Gio-2.0',
    install : true,
    header: join_paths(meson.project_name(), 'soup.h'),
  )

  soup_gir_gen_dep = declare_dependency(
    dependencies : libsoup_dep,
    sources : soup_gir_gen_sources)

  if enable_vapi
    soup_ns_version = '@0@-@1@'.format(soup_ns, apiversion)

    gnome.generate_vapi(libsoup_api_name,
      sources : [
        soup_gir_gen_sources[0],
        soup_ns_version + '-custom.vala'
      ],
      packages : 'gio-2.0',
      install : true,
    )
  endif
endif
