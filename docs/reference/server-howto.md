Title: Server Basics
Slug: server-howto

# Server Basics

## Creating a SoupServer

As with the client API, there is a single object that will encapsulate
most of your interactions with libsoup. In this case, [class@Server].

You create the server with [ctor@Server.new], and as with the [class@Session]
constructor, you can specify a few additional options:

<table>
    <tr>
        <td>[property@Server:tls-certificate]</td>
        <td>
            A [class@Gio.TlsCertificate]
            (containing a private key) that will be used when handling
            HTTPS requests on the server.
        </td>
    </tr>
    <tr>
        <td>[property@Server:raw-paths]</literal></td>
        <td>
            Set this to <tt>TRUE</tt> if you don't want
            libsoup to decode %-encoding
            in the Request-URI. (e.g. because you need to treat
            <tt>"/foo/bar"</tt> and
            <tt>"/foo%2Fbar"</tt> as different paths.
    </td>
    </tr>
    <tr>
        <td>[property@Server:server-header]</td>
        <td>
            Allows you to set a Server header string that will be sent
            on all responses.
        </td>
    </tr>
</table>

## Adding Listening Sockets

To tell the server where to listen, call [method@Server.listen] (to listen on a
specific [class@Gio.SocketAddress]), [method@Server.listen_all] (to listen on a
given port on all network interfaces), or [method@Server.listen_local] (to
listen to a given port on the `loopback` interface only). You can call any of
these functions multiple times, to set up multiple listening sockets.

To set up an HTTPS server, you must first either set the
[property@Server:tls-certificate] property, or else call
[method@Server.set_tls_certificate]. After that you can pass the
`SOUP_SERVER_LISTEN_HTTPS` option to [method@Server.listen], etc.

By default, servers listen for both IPv4 and IPv6 connections; if you don't want
this, use the `SOUP_SERVER_LISTEN_IPV4_ONLY` or `SOUP_SERVER_LISTEN_IPV6_ONLY`
options.

The server runs asynchronously, in the thread-default [struct@GLib.MainContext]
of the thread in which the `listen` calls were made.

## Adding Handlers

By default, [class@Server] returns "404 Not Found" in response to all requests
(except ones that it can't parse, which get "400 Bad Request"). To override this
behavior, call [method@Server.add_handler] to set a callback to handle certain
URI paths.

```c
soup_server_add_handler (server, "/foo", server_callback,
                         data, destroy_notify);
```

The `"/foo"` indicates the base path for this handler. When a request comes in,
if there is a handler registered for exactly the path in the request's
`Request-URI`, then that handler will be called. Otherwise libsoup will strip
path components one by one until it finds a matching handler. So for example, a
request of the form `GET /foo/bar/baz.html?a=1&b=2 HTTP/1.1` would look for
handlers for `/foo/bar/baz.html`, `/foo/bar`, and `/foo`. If a handler has been
registered with a `NULL` base path, then it is used as the default handler for
any request that doesn't match any other handler.

## Responding to Requests

A handler callback looks something like this:

```c
static void
server_callback (SoupServer        *server,
                 SoupServerMessage *msg, 
                 const char        *path,
                 GHashTable        *query,
                 gpointer           user_data)
{
    // ...
}
```

`msg` is the request that has been received and `user_data` is the data that was
passed to [method@Server.add_handler]. `path` is the path (from `msg`'s URI),
and `query` contains the result of parsing the URI query field. (It is `NULL` if
there was no query.)

By default, libsoup assumes that you have completely finished processing the
message when you return from the callback, and that it can therefore begin
sending the response. If you are not ready to send a response immediately (e.g.
you have to contact another server, or wait for data from a database), you must
call [method@Server.pause_message] on the message before returning from the
callback. This will delay sending a response until you call
[method@Server.unpause_message]. (You must also connect to the
[signal@ServerMessage::finished] signal on the message in this case, so that you
can break off processing if the client unexpectedly disconnects before you start
sending the data.)

To set the response status, call [method@ServerMessage.set_status]. If the
response requires a body, you must decide whether to use `Content-Length`
encoding (the default), or `chunked` encoding.

## Responding with `Content-Length` Encoding

This is the simpler way to set a response body, if you have all of the data
available at once.

```c
static void
server_callback (SoupServer        *server,
                 SoupServerMessage *msg, 
                 const char        *path,
                 GHashTable        *query,
                 gpointer           user_data)
{
    MyServerData *server_data = user_data;
    const char *mime_type;
    GByteArray *body;

    if (soup_server_message_get_method (msg) != SOUP_METHOD_GET) {
        soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
        return;
    }

    /* This is somewhat silly. Presumably your server will do
     * something more interesting.
     */
    body = g_hash_table_lookup (server_data->bodies, path);
    mime_type = g_hash_table_lookup (server_data->mime_types, path);
    if (!body || !mime_type) {
        soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
        return;
    }

    soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
    soup_server_message_set_response (msg, mime_type, SOUP_MEMORY_COPY,
                                      body->data, body->len);
}
```

# Responding with `chunked` Encoding

If you want to supply the response body in chunks as it becomes available, use
`chunked` encoding instead. In this case, first call
`soup_message_headers_set_encoding (msg->response_headers,
SOUP_ENCODING_CHUNKED)` to tell libsoup that you'll be using `chunked` encoding.
Then call [method@MessageBody.append] (or [method@MessageBody.append_bytes]) on
`msg->response_body` with each chunk of the response body as it becomes
available, and call [method@MessageBody.complete] when the response is complete.
After each of these calls, you must also call [method@Server.unpause_message] to
cause the chunk to be sent. (You do not normally need to call
[method@Server.pause_message], because I/O is automatically paused when doing a
`chunked` transfer if no chunks are available.)

When using chunked encoding, you must also connect to the
[signal@ServerMessage::finished] signal on the message, so that you will be
notified if the client disconnects between two chunks; [class@Server] will unref
the message if that happens, so you must stop adding new chunks to the response
at that point. (An alternate possibility is to write each new chunk only when
the [signal@ServerMessage::wrote_chunk] signal is emitted indicating that the
previous one was written successfully.)

The **`simple-proxy`** example in the `examples/` directory gives an example of
using `chunked` encoding.

## Handling Authentication

To have [class@Server] handle HTTP authentication for you, create a
[class@AuthDomainBasic] or [class@AuthDomainDigest], and pass it to
[method@Server.add_auth_domain]:

```c
SoupAuthDomain *domain;

domain = soup_auth_domain_basic_new (
    "realm", "My Realm",
    "auth-callback", auth_callback,
    "auth-data", auth_data,
    "add-path", "/foo",
    "add-path", "/bar/private",
    NULL);
soup_server_add_auth_domain (server, domain);
g_object_unref (domain);
```

Then, every request under one of the auth domain's paths will be passed to the
`auth_callback` first before being passed to the `server_callback`:

```c
static gboolean
auth_callback (SoupAuthDomain *domain, SoupServerMessage *msg,
               const char *username, const char *password,
               gpointer user_data)
{
    MyServerData *server_data = user_data;
    MyUserData *user;

    user = my_server_data_lookup_user (server_data, username);
    if (!user)
        return FALSE;

    /* FIXME: Don't do this. Keeping a cleartext password database
     * is bad.
     */
    return strcmp (password, user->password) == 0;
}
```


The [callback@AuthDomainBasicAuthCallback] is given the username and password
from the `Authorization` header and must determine, in some server-specific
manner, whether or not to accept them. (In this example we compare the password
against a cleartext password database, but it would be better to store the
password somehow encoded, as in the UNIX password database. Alternatively, you
may need to delegate the password check to PAM or some other service.)

If you are using Digest authentication, note that
[callback@AuthDomainDigestAuthCallback] works completely differently (since the
server doesn't receive the cleartext password from the client in that case, so
there's no way to compare it directly). See the documentation for
[class@AuthDomainDigest] for more details.

You can have multiple [class@AuthDomain]s attached to a [class@Server], either
in separate parts of the path hierarchy, or overlapping. (e.g. you might want to
accept either Basic or Digest authentication for a given path.) When more than
one auth domain covers a given path, the request will be accepted if the user
authenticates successfully against *any* of the domains.

If you want to require authentication for some requests under a certain path,
but not all of them (e.g. you want to authenticate `PUT` requests, but not `GET`
requests), use a [callback@AuthDomainFilter].
