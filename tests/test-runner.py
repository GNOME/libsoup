#!/usr/bin/env python3

import json
import os
import signal
import sys

import gi
gi.require_version('GIRepository', '2.0')
from gi.repository import GLib, Gio, GIRepository
libpath = os.path.join(os.environ.get('MESON_BUILD_ROOT', 'meson-build'), 'libsoup')
GIRepository.Repository.prepend_search_path(libpath)
GIRepository.Repository.prepend_library_path(libpath)

gi.require_version('Soup', '2.4')
from gi.repository import Soup


verbose_logging = False


def setup_server(server_params, expected_response):
    def on_request(server, msg, path, query, client, user_data=None):
        if verbose_logging:
            print('# -> ', msg.props.method, path, query)
        if 'body' in expected_response:
            msg.set_response(expected_response['content-type'], Soup.MemoryUse.COPY, expected_response['body'].encode())
        msg.set_status(expected_response['status'])

    server = Soup.Server()
    server.add_handler(None, on_request, None)
    if not server.listen_local(0, Soup.ServerListenOptions.IPV4_ONLY):
        print('not ok: Failed to listen')
        return None

    if verbose_logging:
        print('# Listening on', server.get_uris()[0].to_string(False))

    return server


def setup_client(description, client_params, request, response, server):
    def on_completed(session, msg, user_data=None):
        nonlocal server  # Keep object alive
    
        if msg.props.status_code == response['status']:
            print('ok:', description)
        else:
            print('not ok: {} ({})'.format(description, msg.props.status_code))

    session = Soup.Session.new()
    uri = server.get_uris()[0]
    msg = Soup.Message.new(request['method'], uri.to_string(False))
    headers = msg.props.request_headers
    for header, value in request.get('headers', {}).items():
        headers.append(header, value)
    session.queue_message(msg, on_completed, None)


def run_tests():
    print('TAP version 13')
    base_path = os.path.join(os.environ.get('MESON_SOURCE_ROOT', '.'), 'tests', 'data')
    test_cases = os.listdir(base_path)
    print('1..{}'.format(len(test_cases)))
    for test_case in sorted(test_cases):
        with open(os.path.join(base_path, test_case)) as f:
            test = json.load(f)
            server = setup_server(test['server'], test['response'])
            if not server:
                continue
            setup_client(test['description'], test['client'], test['request'], test['response'], server)


class Application(Gio.Application):
    def __init__(self, **kwargs):
        super().__init__(application_id='org.gnome.libsoup.test-runner',
                         flags=Gio.ApplicationFlags.NON_UNIQUE,
                         **kwargs)
        self.add_main_option('verbose', ord('v'), GLib.OptionFlags.NONE, GLib.OptionArg.NONE, 'Verbose output', None)

    def do_activate(self):
        app.hold()  # FIXME: Release when done
        run_tests()

    def do_handle_local_options(self, options):
        global verbose_logging
        verbose_logging = options.contains('verbose')
        return Gio.Application.do_handle_local_options(self, options)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)  # Handle ctrl+c
    app = Application()
    sys.exit(app.run(sys.argv))
