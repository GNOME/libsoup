#!/usr/bin/env python

# Generate tld rules
# Copyright (C) 2012 Red Hat, Inc.
# Based on tld-parser.c Copyright (C) 2012 Igalia S.L.

import sys
import codecs

SOUP_TLD_RULE_NORMAL = 0
SOUP_TLD_RULE_MATCH_ALL = 1 << 0
SOUP_TLD_RULE_EXCEPTION = 1 << 1

tlds_file = codecs.open(sys.argv[1], encoding='utf-8')
inc_file = codecs.open(sys.argv[2], 'w', encoding='utf-8')

first = True
for rule in tlds_file:
    rule = rule.strip()
    if rule == '' or rule.startswith('//'):
        continue
    domain = rule
    flags = 0
    if rule[0] == '!':
        domain = domain[1:]
        flags |= SOUP_TLD_RULE_EXCEPTION

    if domain.startswith('*.'):
        domain = domain[2:]
        flags |= SOUP_TLD_RULE_MATCH_ALL
    
    if domain.startswith('.'):
        domain = domain[1:]

    if not first:
        inc_file.write(',\n')
    else:
        first = False
    inc_file.write('{ "%s", %d }' % (domain.strip(), flags))

inc_file.write('\n')

tlds_file.close()
inc_file.close()
        
