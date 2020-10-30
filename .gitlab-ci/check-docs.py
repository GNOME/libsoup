#!/usr/bin/env python3

import sys

with open('_build/docs/reference/libsoup-3.0-unused.txt') as f:
    unused_docs = f.read()

if unused_docs:
    print('There is documentation not listed in libsoup-3.0-sections.txt:')
    print(unused_docs)
    sys.exit(1)

with open('_build/docs/reference/libsoup-3.0-undocumented.txt') as f:
    # The file starts with a summary
    # undocumented_summary = ''.join(f.readline() for i in range(6)).strip()
    print(f.readline()) # e.g. 95% symbol docs coverage.
    for i in range(4):
        f.readline()
    undocumented_list = f.read().strip()

if undocumented_list:
    print('There is missing documentation for these symbols:')
    print(undocumented_list)
    # sys.exit(1)
