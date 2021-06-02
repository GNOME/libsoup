#!/usr/bin/env python3

import sys
import subprocess

http_header_name_to_id = { }
http_header_names = []
with open('soup-header-names.in') as i:
    for line in i.readlines():
        name = line.strip();
        if not name or name[0] == '#':
            continue

        http_header_name_to_id[name] = 'SOUP_HEADER_' + name.upper().replace('-', '_')
        http_header_names.append (name)

http_header_names.sort()

gperf_file = '''%{
/* This file has been generated with generate-header-names.py script, do not edit */
#include "soup-header-names.h"
#include <string.h>

static const char * const soup_headr_name_strings[] = {
'''

for name in http_header_names:
    gperf_file += '  "%s",\n' % name

gperf_file += '''};
%}
%language=ANSI-C
%struct-type
struct SoupHeaderHashEntry {
    int name;
    SoupHeaderName header_name;
};
%define hash-function-name soup_header_name_hash_function
%define lookup-function-name soup_header_name_find
%readonly-tables
%global-table
%compare-strncmp
%ignore-case
%pic
%%
'''

for name in http_header_names:
    gperf_file += '%s, %s\n' % (name, http_header_name_to_id[name])

gperf_file += '''%%
SoupHeaderName soup_header_name_from_string (const char *str)
{
        const struct SoupHeaderHashEntry *entry;

        entry = soup_header_name_find (str, strlen (str));
        return entry ? entry->header_name : SOUP_HEADER_UNKNOWN;
}

const char *soup_header_name_to_string (SoupHeaderName name)
{
        if (name == SOUP_HEADER_UNKNOWN)
                return NULL;

        return soup_headr_name_strings[name];
}
'''

command = ['gperf', '-k', '*', '-D', '-n', '-s', '2']
p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
output, error = p.communicate(gperf_file)

if p.returncode != 0:
    print (error)
    sys.exit(p.returncode)

with open('soup-header-names.c', 'w+') as o:
    o.write(output.replace('const struct SoupHeaderHashEntry *', 'static const struct SoupHeaderHashEntry *', 1))


output = '''/* This file has been generated with generate-header-names.py script, do not edit */

#pragma once

typedef enum {
'''

for name in http_header_names:
    output += '        %s,\n' % http_header_name_to_id[name]

output +='''
        SOUP_HEADER_UNKNOWN
} SoupHeaderName;

SoupHeaderName soup_header_name_from_string (const char    *str);
const char    *soup_header_name_to_string   (SoupHeaderName name);
'''

with open('soup-header-names.h', 'w+') as o:
    o.write(output)
