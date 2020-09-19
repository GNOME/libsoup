# This is in a random subdir simply to avoid the built version being accidentally included.
configure_file (
  input: 'soup-installed.h',
  output: 'soup.h',
  copy: true,
  install: true,
  install_dir: get_option('includedir') / includedir,
)