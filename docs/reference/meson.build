expand_content_md_files = [
    'build-howto.md',
    'client-basic.md',
    'client-advanced.md',
    'client-thread-safety.md',
    'client-tls.md',
    'server-howto.md',
    'migrating-from-libsoup-2.md',
]

toml_data = configuration_data()
toml_data.set('VERSION', meson.project_version())

gidocgen_dep = dependency('gi-docgen', version: '>= 2021.1',
  fallback: ['gi-docgen', 'dummy_dep'],
  native: true,
  required: get_option('docs')
)

have_docs = gidocgen_dep.found()
if not enable_introspection and get_option('docs').auto()
  have_docs = false
  warning('Documentation will not be built as introspection was disabled')
elif not enable_introspection and get_option('docs').enabled()
  error('Documentation cannot be built without introspection being enabled')
endif

if have_docs
  libsoup_toml = configure_file(
    input: 'libsoup.toml.in',
    output: 'libsoup.toml',
    configuration: toml_data
  )

  gidocgen = find_program('gi-docgen')

  docs_dir = get_option('datadir') / 'doc'

  custom_target('libsoup-doc',
    input: [ libsoup_toml, soup_gir_gen_sources[0] ],
    output: 'libsoup-@0@'.format(apiversion),
    command: [
      gidocgen,
      'generate',
      '--quiet',
      '--add-include-path=@0@'.format(meson.current_build_dir() / '../../libsoup'),
      '--config=@INPUT0@',
      '--output-dir=@OUTPUT@',
      '--no-namespace-dir',
      '--content-dir=@0@'.format(meson.current_source_dir()),
      '@INPUT1@',
    ],
    depend_files: [ expand_content_md_files ],
    build_by_default: true,
    install: true,
    install_dir: docs_dir,
  )

  if get_option('doc_tests')
    test('docs', gidocgen,
      args: [
        'check',
        '--add-include-path=@0@'.format(meson.current_build_dir() / '../../libsoup'),
        '--config=@0@'.format(libsoup_toml),
        soup_gir_gen_sources[0],
      ]
    )
  endif
endif