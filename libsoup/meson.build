pkg = import('pkgconfig')

resources = gnome.compile_resources('soup-resources',
    'soup.gresource.xml',
    c_name: 'soup',
    source_dir: '.'
)

soup_sources = [
  resources,
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
  'soup-hsts-enforcer.c',
  'soup-hsts-enforcer-db.c',
  'soup-hsts-policy.c',
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
  'soup-websocket-extension.c',
  'soup-websocket-extension-deflate.c',
  'soup-websocket-extension-manager.c',
  'soup-xmlrpc.c',
  'soup-xmlrpc-old.c',
]

soup_headers = [
  'gconstructor.h',
  'soup-auth-basic.h',
  'soup-auth-digest.h',
  'soup-auth-ntlm.h',
  'soup-auth-negotiate.h',
  'soup-body-input-stream.h',
  'soup-body-output-stream.h',
  'soup-cache-client-input-stream.h',
  'soup-cache-input-stream.h',
  'soup-cache-private.h',
  'soup-client-input-stream.h',
  'soup-connection.h',
  'soup-connection-auth.h',
  'soup-content-processor.h',
  'soup-content-sniffer-stream.h',
  'soup-converter-wrapper.h',
  'soup-directory-input-stream.h',
  'soup-filter-input-stream.h',
  'soup-io-stream.h',
  'soup-message-private.h',
  'soup-message-queue.h',
  'soup-misc-private.h',
  'soup-path-map.h',
  'soup-proxy-resolver-wrapper.h',
  'soup-session-private.h',
  'soup-socket-private.h',
  'soup-websocket-extension-manager-private.h',
]

soup_introspection_headers = [
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
  'soup-hsts-enforcer.h',
  'soup-hsts-enforcer-db.h',
  'soup-hsts-policy.h',
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
  'soup-websocket-extension.h',
  'soup-websocket-extension-deflate.h',
  'soup-websocket-extension-manager.h',
  'soup-xmlrpc.h',
  'soup-xmlrpc-old.h',
]

soup_installed_headers = soup_introspection_headers + [
  'soup.h'
]

soup_gnome_sources = [
  'soup-cookie-jar-sqlite.c',
  'soup-gnome-features.c',
  'soup-password-manager-gnome.c',
  'soup-proxy-resolver-gnome.c'
]

soup_gnome_headers = [
  'soup-proxy-resolver-gnome.h',
  'soup-password-manager-gnome.h'
]

soup_gnome_introspection_headers = [
  'soup-cookie-jar-sqlite.h',
  'soup-gnome-features.h'
]

soup_gnome_installed_headers = soup_gnome_introspection_headers + [
  'soup-gnome.h'
]

if brotlidec_dep.found()
  soup_sources += 'soup-brotli-decompressor.c'
  soup_headers += 'soup-brotli-decompressor.h'
endif


includedir = join_paths(libsoup_api_name, meson.project_name())
install_headers(soup_installed_headers, subdir : includedir)

version_cdata = configuration_data()
version_cdata.set('SOUP_MAJOR_VERSION', soup_version_major)
version_cdata.set('SOUP_MINOR_VERSION', soup_version_minor)
version_cdata.set('SOUP_MICRO_VERSION', soup_version_micro)

soup_version_h = configure_file(input : 'soup-version.h.in',
  output : 'soup-version.h',
  install_dir : join_paths(get_option('includedir'), includedir),
  configuration : version_cdata)

enum_types = 'soup-enum-types'
soup_enums = gnome.mkenums('soup-enum-types',
  sources : [
    soup_installed_headers,
    soup_gnome_installed_headers
  ],
  h_template : enum_types + '.h.template',
  c_template : enum_types + '.c.template',
  install_header : true,
  install_dir : join_paths(get_option('includedir'), includedir))

soup_enum_h = soup_enums[1]
soup_enum_c = soup_enums[0]

libsoup_c_args  = [
  '-DG_LOG_DOMAIN="@0@"'.format(meson.project_name()),
  '-DLIBSOUP_COMPILATION'
]

deps = [
  libsysprof_capture_dep,
  glib_deps,
  libxml_dep,
  sqlite_dep,
  libpsl_dep,
  brotlidec_dep,
  platform_deps,
  gssapi_dep,
  libz_dep,
]

libsoup = library('soup-@0@'.format(apiversion),
  soup_sources,
  soup_headers,
  soup_enums,
  version : libversion,
  soversion : soversion,
  darwin_versions: darwin_versions,
  c_args : libsoup_c_args + hidden_visibility_flag,
  include_directories : configinc,
  install : true,
  dependencies : deps)

pkg.generate(libsoup,
  libraries : glib_deps,
  name : meson.project_name(),
  description : 'A glib-based HTTP library',
  filebase : libsoup_api_name,
  subdirs: libsoup_api_name,
  variables: 'exec_prefix=${prefix}')

libsoup_dep = declare_dependency(link_with : libsoup,
  include_directories : configinc,
  sources : soup_enum_h,
  dependencies : [ platform_deps, gssapi_dep, glib_deps ])

if meson.version().version_compare('>=0.54.0')
  meson.override_dependency('libsoup-2.4', libsoup_dep)
endif

if enable_gnome
  soup_gnome_api_name = 'soup-gnome-' + apiversion
  libsoup_gnome_api_name = 'lib' + soup_gnome_api_name

  includedir = join_paths(libsoup_gnome_api_name, meson.project_name())
  install_headers(
    soup_gnome_installed_headers,
    subdir : includedir)

  libsoup_gnome = library(soup_gnome_api_name,
    soup_gnome_sources + soup_gnome_headers,
    version : libversion,
    soversion : soversion,
    darwin_versions: darwin_versions,
    c_args : libsoup_c_args + hidden_visibility_flag,
    include_directories : configinc,
    install : true,
    dependencies : deps + [libsoup_dep])

  libsoup_gnome_dep = declare_dependency(link_with : libsoup_gnome,
    include_directories : configinc,
    dependencies : deps + [libsoup_dep])

  if meson.version().version_compare('>=0.54.0')
    meson.override_dependency('libsoup-gnome-2.4', libsoup_gnome_dep)
  endif

  pkg.generate(
    libraries : libsoup_gnome,
    version : soup_version,
    name : meson.project_name(),
    description : 'A glib-based HTTP library',
    filebase : libsoup_gnome_api_name,
    requires : libsoup_api_name,
    subdirs: libsoup_gnome_api_name,
    variables: 'exec_prefix=${prefix}')
endif

if enable_introspection or enable_vapi
  soup_gir_args = libsoup_c_args + ['-DLIBSOUP_USE_UNSTABLE_REQUEST_API']

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
    extra_args : soup_gir_args,
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

  if enable_gnome
    soup_gnome_gir_args = libsoup_c_args + [
      '--include-uninstalled=' + soup_gir_gen_sources[0].full_path()
    ]

    gnome.generate_gir(libsoup_gnome,
      sources : [
        soup_gnome_sources,
        soup_gnome_introspection_headers
      ],
      nsversion : apiversion,
      namespace : 'SoupGNOME',
      symbol_prefix : soup_ns.to_lower(),
      identifier_prefix : soup_ns,
      export_packages : libsoup_gnome_api_name,
      extra_args : soup_gnome_gir_args,
      dependencies : soup_gir_gen_dep,
      install : true,
      header: join_paths(meson.project_name(), 'soup-gnome.h'),
    )
  endif
endif
