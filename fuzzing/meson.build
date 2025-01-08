fs = import('fs')

fuzz_targets = [
  'fuzz_decode_data_uri',
  'fuzz_cookie_parse',
  'fuzz_content_sniffer',
  'fuzz_date_time',
  'fuzz_header_parsing',
]

fuzzing_args = '-fsanitize=fuzzer'
have_fuzzing = cc.has_argument(fuzzing_args)
fuzzing_feature = get_option('fuzzing')

if not have_fuzzing and fuzzing_feature.enabled()
  error('clang and libfuzzer are required for fuzzing')
endif

if have_fuzzing and (fuzzing_feature.enabled() or fuzzing_feature.auto())
  foreach target : fuzz_targets
    exe = executable(target, [target + '.c'],
      c_args : [fuzzing_args, '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'],
      link_args : fuzzing_args,
      dependencies : libsoup_dep,
    )

    extra_args = []
    dict_file = join_paths(meson.current_source_dir(), target + '.dict')
    if fs.exists(dict_file)
      extra_args += '-dict=' + dict_file
    endif

    test(target, exe,
      args: [
        '-runs=200000',
        '-artifact_prefix=meson-logs/' + target + '-',
        '-print_final_stats=1',
        '-max_len=4096',
      ] + extra_args,
      env: [
        'ASAN_OPTIONS=fast_unwind_on_malloc=0',
        'UBSAN_OPTIONS=print_stacktrace=1',
      ],
      suite: 'fuzzing',
      timeout: 360,
      priority: -1,
    )
  endforeach
endif