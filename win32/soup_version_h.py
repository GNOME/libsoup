#!/usr/bin/python
#
# Simple utility script to generate soup-version.h

import os
import sys
import argparse

from replace import replace_multi

def gen_version_h(argv):
    top_srcdir = os.path.dirname(__file__) + "\\.."
    parser = argparse.ArgumentParser(description='Generate soup-version.h')
    parser.add_argument('--version', help='Version of the package',
                        required=True)
    args = parser.parse_args()
    version_info = args.version.split('.')

    version_h_replace_items = {'@SOUP_MAJOR_VERSION@': version_info[0],
                               '@SOUP_MINOR_VERSION@': version_info[1],
                               '@SOUP_MICRO_VERSION@': version_info[2]}

    # Generate soup-version.h
    replace_multi(top_srcdir + '/libsoup/soup-version.h.in',
                  top_srcdir + '/libsoup/soup-version.h',
                  version_h_replace_items)

if __name__ == '__main__':
    sys.exit(gen_version_h(sys.argv))