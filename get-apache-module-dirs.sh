#!/bin/sh
#
# Checks whether the required Apache modules are available and prints their path
# to stdout - where values are separated by colons.
#
# Only one argument is required - path to the Apache httpd2 binary

if [ -z $1 ]; then
    exit 1
fi

apache_httpd=$1

apache_prefix=$(dirname $(dirname $apache_httpd))
mpm=$($apache_httpd -V -C "ServerName localhost" | sed -ne 's/^Server MPM: */-/p' | tr 'A-Z' 'a-z')
# This only works with bash, but should fail harmlessly in sh
apache_module_dirs=$(echo $apache_prefix/lib{64,}/{apache,apache2,http,http2,httpd}{$mpm,}{/modules,})

for dir in $apache_module_dirs; do
    if test -f $dir/mod_auth_digest.so; then
        APACHE_MODULE_DIR="$dir"
    fi
    if test -f $dir/mod_ssl.so; then
        APACHE_SSL_MODULE_DIR="$dir"
    fi
    if test -f $dir/libphp7.so; then
        APACHE_PHP_MODULE_DIR="$dir"
    fi
done

echo -n "$APACHE_MODULE_DIR:$APACHE_SSL_MODULE_DIR:$APACHE_PHP_MODULE_DIR"
