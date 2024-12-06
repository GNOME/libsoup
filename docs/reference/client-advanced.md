Title: Advanced Usage
Slug: client-advanced

# Advanced Usage

## Customizing Session Options

When you create the session with [ctor@Session.new_with_options], you can
specify various additional options. See the [class@Session] documentation for
more details but these may be interesting: [property@Session:max-conns] and
[property@Session:max-conns-per-host], [property@Session:user-agent],
[property@Session:timeout], [property@Session:accept-language] and
[property@Session:accept-language-auto].

## Adding Session Features

Additional session functionality is provided as [iface@SessionFeature]s, which
can be added to or removed from a session.

One such feature is [class@ContentDecoder] which is added by default. This
advertises to servers that the client supports compression, and automatically
decompresses compressed responses.

Some other available features that you can add include:

<table>
    <tr>
        <td>[class@Logger]</td>
        <td>
        A debugging aid, which logs all of libsoup's HTTP traffic
        to <code>stdout</code> (or another place you specify).
        </td>
    </tr>
    <tr>
    <td>
        [class@CookieJar], [class@CookieJarText],
        and [class@CookieJarDB].
    </td>
    <td>
        Support for HTTP cookies. [class@CookieJar]
        provides non-persistent cookie storage, while
        [class@CookieJarText] uses a text file to keep
        track of cookies between sessions, and
        [class@CookieJarDB] uses a
        <tt>SQLite</tt> database.
    </td>
    </tr>
    <tr>
    <td>[class@ContentSniffer]</td>
    <td>
        Uses the HTML5 sniffing rules to attempt to
        determine the Content-Type of a response when the
        server does not identify the Content-Type, or appears to
        have provided an incorrect one. 
    </td>
    </tr>
</table>

Use the [method@Session.add_feature_by_type] function to add features that don't
require any configuration (such as [class@ContentSniffer]), and the
[method@Session.add_feature]function to add features that must be constructed
first (such as [class@Logger]). For example, an application might do something
like the following:

```c
session = soup_session_new ();
soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

if (debug_level) {
    SoupLogger *logger = soup_logger_new (debug_level);
    soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
    g_object_unref (logger);
}
```

You can also remove features by calling [method@Session.remove_feature] or
[method@Session.remove_feature_by_type].
    
## Using a proxy

By default libsoup tries to respect the default proxy (as best as
[func@Gio.ProxyResolver.get_default] knows), however you can set a custom one or
disable it outright using the [property@Session:proxy-resolver] property. For
example:

```c
{
    GProxyResolver *resolver = g_simple_proxy_resolver_new ("https://my-proxy-example.org", NULL);
    SoupSession *session = soup_session_new_with_options ("proxy-resolver", resolver, NULL);
    g_object_unref (resolver);
}
```

## Using the SoupMessage API

The [class@Message] type contains all the state for a request and response pair
that you send and receive to a server. For many more complex tasks you will have
to create one of these and send it with the [method@Session.send] function. For
example this sends a request with the `HEAD` method:
    
```c
{
    SoupSession *session = soup_session_new ();
    SoupMessage *msg = soup_message_new (SOUP_METHOD_HEAD, "https://example.org");

    // This allows you to also customize the request headers:
    SoupMessageHeaders *request_headers = soup_message_get_request_headers (msg);
    soup_message_headers_replace (request_headers, "Foo", "Bar");

    GInputStream *in_stream = soup_session_send (session, msg, NULL, NULL);
    if (in_stream) {
        g_print ("Message was sent and recived a response of %u (%s)\n",
                 soup_message_get_status (msg), soup_message_get_reason_phrase (msg));
        // You can also inspect the response headers via soup_message_get_response_headers();
        g_object_unref (in_stream);
    }

    g_object_unref (msg);
    g_object_unref (session);
}
```

## Handling authentication

```c
static gboolean
authenticate_callback (SoupMessage *msg, SoupAuth *auth, gboolean retrying, gpointer user_data)
{
    if (retrying) {
        // Maybe don't try again if our password failed
        return FALSE;
    }

    soup_auth_authenticate (auth, "username", "password");

    // Returning TRUE means we have or *will* handle it.
    // soup_auth_authenticate() or soup_auth_cancel() can be called later
    // for example after showing a prompt to the user or loading the password
    // from a keyring.
    return TRUE;
}

int main (int argc, char **argv)
{
    SoupSession *session = soup_session_new ();
    SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://example.org");
    g_signal_connect (msg, "authenticate", G_CALLBACK (authenticate_callback), NULL);
    GInputStream *in_stream = soup_session_send (session, msg, NULL, NULL);

    if (in_stream) {
        g_object_unref (in_stream);
    }

    return 0;
}
```
