Title: Everything TLS Related
Slug: client-tls

# Everything TLS Related

libsoup comes with TLS support provided by glib-networking. This has multiple backends
including gnutls (default on all platforms), SChannel on Windows, or OpenSSL.

## Accepting Invalid or Pinned Certificates

This makes use of the [signal@Message::accept-certificate] signal.

```c
static gboolean
accept_certificate_callback (SoupMessage *msg, GTlsCertificate *certificate,
                             GTlsCertificateFlags tls_errors, gpointer user_data)
{
    // Here you can inspect @certificate or compare it against a trusted one
    // and you can see what is considered invalid by @tls_errors.
    // Returning TRUE trusts it anyway.
    return TRUE;
}

int main (int argc, char **argv)
{
    SoupSession *session = soup_session_new ();
    SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://example.org");
    g_signal_connect (msg, "accept-certificate", G_CALLBACK (accept_certificate_callback), NULL);
    GInputStream *in_stream = soup_session_send (session, msg, NULL, NULL);

    if (in_stream) {
        g_object_unref (in_stream);
    }

    return 0;
}
```

## Setting a Custom CA

```c
{
    GError *error = NULL;
    // NOTE: This is blocking IO
    GTlsDatabase *tls_db = g_tls_file_database_new ("/foo/ca.pem", &error);

    if (error) {
        g_printerr ("Failed to load certificates: %s\n", error->message);
        g_error_free (error);
        return;
    }

    SoupSession *session = soup_session_new_with_options ("tls-database", tls_db, NULL);
    g_object_unref (tls_db);
}
```

## Using Client Certificates

```c
static gboolean
on_request_certificate (SoupMessage *msg, GTlsClientConnection *conn, gpointer user_data)
{
    GTlsCertificate *client_cert = user_data;

    /* We immediately set this however you can set this later in an async function. */
    soup_message_set_tls_client_certificate (msg, client_cert);

    return TRUE; /* We handled the request */
}

int main (int argc, char **argv)
{
    GError *error = NULL;
    GTlsCertificate *client_cert = g_tls_certificate_new_from_file ("/foo/cert.pem", &error);

    if (error) {
        g_printerr ("Failed to load certificate: %s\n", error->message);
        g_error_free (error);
        return 1;
    }

    SoupSession *session = soup_session_new ();
    SoupMessage *msg = soup_message_new ("GET", "https://example.org");

    /* We can set the certificate ahead of time if we already have one */
    // soup_message_set_tls_client_certificate (msg, client_cert)

    /* However we can also dynamically request one which is useful in
     * applications that show a graphical prompt for example. */
    g_signal_connect (msg, "request-certificate",
                      G_CALLBACK (on_request_certificate), client_cert);

    // Send the message...

    g_object_unref (msg);
    g_object_unref (session);
    g_object_unref (client_cert);
    return 0;
}
```
