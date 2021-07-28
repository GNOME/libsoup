#!/usr/bin/env python3

import collections.abc
import gi

gi.require_version('Soup', '3.0')

from gi.repository import Soup

# MessageHeaders overrides
headers = Soup.MessageHeaders.new(Soup.MessageHeadersType.REQUEST)

assert isinstance(headers, collections.abc.Mapping)
assert isinstance(headers, collections.abc.MutableMapping)

headers['one'] = 'one-value'
headers['two'] = 'two-value'

assert headers['one'] == 'one-value'
assert headers['two'] == 'two-value'

assert len(headers) == 2

assert headers.keys() == ['one', 'two']
assert headers.values() == ['one-value', 'two-value']
assert headers.items() == {'one': 'one-value', 'two': 'two-value'}
assert 'one' in headers
assert headers.get('one') == 'one-value'

del headers['one']
assert 'one' not in headers

assert headers.pop('two') == 'two-value'
assert not headers
headers['one'] = 'one-value'
assert headers
headers.clear()
assert not headers
