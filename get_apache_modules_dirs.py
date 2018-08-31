#!/usr/bin/env python3
#
# Copyright 2017, 2018 Tomas Popela <tpopela@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import re
import subprocess
import sys
import os
import glob

def check_php_module(modules_path):
    php_modules = glob.glob(os.path.join(modules_path, 'libphp7*.so'));
    if len(php_modules):
        # The last one in the sorted output will be the desired php module.
        return sorted(php_modules)[-1];


def check_module(modules_path, module):
     module_path = os.path.join(modules_path, module)
     return os.path.isfile(module_path)


def check_required_basic_modules(modules_path):

    apache_required_modules = [
        'mod_alias',
        'mod_auth_basic',
        'mod_auth_digest',
        'mod_authn_core',
        'mod_authn_file',
        'mod_authz_core',
        'mod_authz_host',
        'mod_authz_user',
        'mod_dir',
        'mod_mime',
        'mod_mpm_prefork',
        'mod_proxy',
        'mod_proxy_http',
        'mod_proxy_connect'
    ]

    found = 0
    not_found = []
    for module_name in apache_required_modules:
        if not check_module(modules_path, module_name + '.so'):
            if found == 0:
                return False
            # If we found at least one module, continue and later report all the
            # modules that we didn't find.
            not_found.append(module_name)
        else:
            found += 1

    if found < len(apache_required_modules):
        print('Failed to find required Apache modules for running tests: ' + ', '.join(not_found), file=sys.stderr)
        return False

    return True


def main():
    """Checks whether the required Apache modules are available and prints their
       paths to stdout (values are separated by colons).

       Only one argument is required - path to the Apache's apachectl executable"""

    if len(sys.argv) != 2:
        print('Only one argument with path to the Apache apachectl executable expected!', file=sys.stderr)
        sys.exit(1)

    apachectl_executable = sys.argv[1]

    if not os.path.isfile(apachectl_executable):
        print('The passed Apache apachectl executable does not exist!', file=sys.stderr)
        sys.exit(1)

    apache_prefix = os.path.dirname(os.path.dirname(apachectl_executable))
    apachectl_output = subprocess.run(
        [apachectl_executable, '-V', '-C', 'ServerName localhost'], stdout=subprocess.PIPE)
    if apachectl_output.returncode != 0:
        print('Something went wrong when calling ' + apachectl_executable + '!', file=sys.stderr)
        sys.exit(1)

    mpm_regex = re.compile(r'\nServer MPM:[\s]+([\w]+)\n')
    mpm = mpm_regex.search(apachectl_output.stdout.decode('utf-8')).group(1).lower()

    apache_modules_dir = ''
    apache_ssl_module_dir = ''
    apache_php_module_file = ''
    apache_mod_unixd_module_file = ''

    for lib_dir in ['lib', 'lib64']:
        for httpd_dir in ['apache', 'apache2', 'http', 'http2', 'httpd']:
            for mpm_suffix in ['', '-' + mpm]:
                for modules_dir in ['', 'modules']:
                    modules_path = os.path.join(apache_prefix, lib_dir, httpd_dir + mpm_suffix, modules_dir)
                    if check_required_basic_modules(modules_path):
                        apache_modules_dir = modules_path
                    if check_module(modules_path, 'mod_ssl.so'):
                        apache_ssl_module_dir = modules_path
                    php_module = check_php_module(modules_path)
                    if (php_module):
                        apache_php_module_file = php_module
                    if check_module(modules_path, 'mod_unixd.so'):
                        apache_mod_unixd_module_file = modules_path

    # These two are mandatory for having properly configured Apache
    if apache_modules_dir == '' or apache_ssl_module_dir == '':
        sys.exit(1)

    print(apache_modules_dir + ":" +
          apache_ssl_module_dir + ":" +
          apache_php_module_file + ":" +
          apache_mod_unixd_module_file, end='')

if __name__ == "__main__":
    main()
