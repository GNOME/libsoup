Title: Migrating from libsoup 2
Slug: migrating-from-libsoup-2

# Migrating from libsoup 2

## Removed APIs

This is a list of APIs that have been removed:

 - XML-RPC support.
 - Handling of `file://` and `data://` URIs You should use [iface@Gio.File] for
   the former and [func@uri_decode_data_uri] for the latter.
 - Define aliases for property names You must use the string name of properties
   directly which works in libsoup 2 already.
 - `SoupSession:add-feature` and `SoupSession:add-feature-by-type` You must call
   [method@Session.add_feature] and [method@Session.add_feature_by_type]
   directly.
 - `SoupRequest`: You should use [method@Session.send] or
   [method@Session.send_async] methods.
 - `SoupAddress` has been replaced with [class@Gio.InetAddress] and
   [class@Gio.NetworkAddress].
 - `SoupSocket` has been removed.
 - `SoupProxyResolverDefault` is replaced by
   [func@Gio.ProxyResolver.get_default].
 - `SoupBuffer` has been replaced by [struct@GLib.Bytes] and
   [struct@GLib.ByteArray].
 - `SoupDate` has been replaced by `GDateTime`.
 - `SoupSession:ssl-strict` has been removed in favor of using the
   [signal@Message::accept-certificate] signal.
 - `soup_session_cancel_message()` has been removed instead you
   pass a [class@Gio.Cancellable] to APIs and call [method@Gio.Cancellable.cancel].

## Moved authenticate signal

The `SoupSession::authenticate` signal has been replaced by
[signal@Message::authenticate]. It now allows returning `TRUE` to signify if
you will handle authentication which allows for asynchronous handling.

## Structs are private

You can no longer directly access various structs such as [class@Message]. These are
now accessed by getters and setters. See below for direct
conversions:

<!-- TODO add links -->
<table>
    <tr>
        <th>Struct field</th>
        <th>Getter/Setter function</th>
    </tr>
    <tr>
        <td>SoupMessage.method</td>
        <td>soup_message_get_method()</td>
    </tr>
    <tr>
        <td>SoupMessage.status_code</td>
        <td>soup_message_get_status()</td>
    </tr>
    <tr>
        <td>SoupMessage.reason_phrase</td>
        <td>soup_message_get_reason_phrase()</td>
    </tr>
    <tr>
        <td>SoupMessage.uri</td>
        <td>soup_message_get_uri(), soup_message_set_uri()</td>
    </tr>
    <tr>
        <td>SoupMessage.request_headers</td>
        <td>soup_message_get_request_headers()</td>
    </tr>
    <tr>
        <td>SoupMessage.response_headers</td>
        <td>soup_message_get_response_headers()</td>
    </tr>
    <tr>
        <td>SoupMessage.request_body</td>
        <td>soup_message_set_request_body(), soup_message_set_request_body_from_bytes()</td>
    </tr>
    <tr>
        <td>SoupMessage.response_body</td>
        <td>See section on IO</td>
    </tr>
</table>

Similar struct changes exist for [struct@Cookie] but have very straightforward
replacements.

## URI type changed

The `SoupURI` type has been replaced with the [struct@GLib.Uri] type which has
some implications.

Creating a [struct@GLib.Uri] is generally as simple as `g_uri_parse (uri,
 SOUP_HTTP_URI_FLAGS, NULL)`. You may want to add

`G_URI_FLAGS_PARSE_RELAXED` to accept input that used to be considered valid.

Note that unlike `SoupURI`, `GUri` is an immutable type so you cannot change the
contents of one after it has been constructed. We provide [func@uri_copy] to aid
in modifying them.

The equivalent behavior to `soup_uri_to_string (uri, FALSE)`
is `g_uri_to_string_partial (uri, G_URI_HIDE_PASSWORD)`.

Since `GUri` does not provide any function to check for equality
[func@uri_equal] still exists.

Sending a `OPTIONS` message with a path of `*` is no longer a valid URI and has
been replaced with [property@Message:is-options-ping].

## Status codes no longer used for internal errors

Previously [enum@Status] was used to hold libsoup errors
(`SOUP_STATUS_IS_TRANSPORT_ERROR()`). Now all of these errors are propagated up
through the normal [struct@GLib.Error] method on the various APIs to send
messages. Here is a mapping chart between the status codes and new errors:

<table>
    <tr>
        <th>Old Status Codes</th>
        <th>New <code>GError</code></th>
    </tr>
    <tr>
        <td><code>SOUP_STATUS_CANCELLED</code></td>
        <td><code>G_IO_ERROR_CANCELLED</code></td>
    </tr>
    <tr>
        <td><code>SOUP_STATUS_MALFORMED</code></td>
        <td><code>SOUP_SESSION_ERROR_PARSING</code>, <code>SOUP_SESSION_ERROR_ENCODING</code></td>
    </tr>
    <tr>
        <td><code>SOUP_STATUS_TOO_MANY_REDIRECTS</code></td>
        <td><code>SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS</code></td>
    </tr>
</table>

## All IO is now GIOStream-based

Previously there were ways to allow libsoup to read data into buffers and for
you to read from those buffers such as `SoupMessage:response-body`
`SoupMessage:response-body-data`, and `SoupServerMessage::got-chunk`.

libsoup no longer stores a buffer of data for you to read from and instead it
returns a [class@Gio.InputStream] which you read from using normal GIO APIs.

If you want to simply request a buffer and nothing more you can use the
[method@Session.send_and_read] or [method@Session.send_and_read_async] APIs.

This also applies to writing data where you can set a [class@Gio.InputStream]
using [method@Message.set_request_body] or use the convenience API
[method@Message.set_request_body_from_bytes] to use a [struct@GLib.Bytes]
buffer.

## Clarification on thread-safety

In libsoup 2 there was an attempt at making various APIs of the library
thread-safe. However this was never well tested, maintained, or documented.


libsoup 3 was initially designed to behave in line with other GObject libraries. Once you
create a [class@Session] all usage of that session must happen on the same
thread. However, in version 3.2 thread safety support was introduced
again, with the same approach as libsoup2.
