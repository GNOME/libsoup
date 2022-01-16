expand_content_md_files = [
    'build-howto.md',
    'client-basic.md',
    'client-advanced.md',
    'client-tls.md',
    'server-howto.md',
    'migrating-from-libsoup-2.md',
]

toml_data = configuration_data()
toml_data.set('VERSION', meson.project_version())

libsoup_toml = configure_file(
  input: 'libsoup.toml.in',
  output: 'libsoup.toml',
  configuration: toml_data
)

dependency('gi-docgen', version: '>= 2021.1',
           fallback: ['gi-docgen', 'dummy_dep'],
           native: true,
           required: get_option('gtk_doc'))

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
