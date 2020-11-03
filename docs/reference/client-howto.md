# libsoup Client Basics {#libsoup-client-howto}

This section explains how to use libsoup as an HTTP client using several new APIs introduced in version 2.42.
If you want to be compatible with older versions of libsoup, consult the documentation for that version.


## Creating a SoupSession

The first step in using the client API is to create a #SoupSession.
The session object encapsulates all of the state that libsoup
is keeping on behalf of your program; cached HTTP connections,
authentication information, etc.

When you create the session with soup_session_new_with_options(),
you can specify various additional options:

- ["max-conns"](#SoupSession:max-conns)

    Allows you to set the maximum total number of connections
    the session will have open at one time. (Once it reaches
    this limit, it will either close idle connections, or
    wait for existing connections to free up before starting
    new requests.) The default value is `10`.

- ["max-conns-per-host"](#SoupSession:max-conns-per-host)

    Allows you to set the maximum total number of connections
    the session will have open *to a single host* at one time.
    The default value is `2`.

- ["user-agent"](#SoupSession:user-agent)

    Allows you to set a User-Agent string that will be sent
    on all outgoing requests.

Other properties are also available; see the #SoupSession documentation
for more details.

If you don't need to specify any options, you can just use soup_session_new(),
which takes no arguments.

## Session features

Additional session functionality is provided as #SoupSessionFeature<!-- -->s,
which can be added to a session...