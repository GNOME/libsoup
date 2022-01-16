Title: Creating a Basic Client
Slug: client-basic

# Creating a Basic Client

libsoup provides a feature rich and complete HTTP client feature-set however in this guide we will just be touching the basics.

## Creating a SoupSession
The core of libsoup is [class@Session]; It contains all of the state of a client
including managing connections, queuing messages, handling authentication and
redirects, and much more. For now lets assume the default set of options and
features it provides are acceptable for most usage in which case you simply need
to create one with [ctor@Session.new].

## Downloading Into Memory

A common use case is that you simply want to request an HTTP resource and store
it for later use. There are a few methods of doing this but libsoup provides a high
level API to accomplish this:

```c
#include <libsoup/soup.h>

int main (int argc, char **argv)
{
    SoupSession *session = soup_session_new ();
    SoupMessageHeaders *response_headers;
    const char *content_type;
    SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://upload.wikimedia.org/wikipedia/commons/5/5f/BBB-Bunny.png");
    GError *error = NULL;
    GBytes *bytes = soup_session_send_and_read (
        session,
        msg,
        NULL, // Pass a GCancellable here if you want to cancel a download
        &error);

    if (error) {
        g_printerr ("Failed to download: %s\n", error->message);
        g_error_free (error);
        g_object_unref (msg);
        g_object_unref (session);
        return 1;
    }

    response_headers = soup_message_get_response_headers (msg);
    content_type = soup_message_headers_get_content_type (response_headers);

    // content_type = "image/png"
    // bytes contains the raw data that can be used elsewhere
    g_print ("Downloaded %zu bytes of type %s\n",
             g_bytes_get_size (bytes), content_type);

    g_bytes_unref (bytes);
    g_object_unref (msg);
    g_object_unref (session);
    return 0;
}
```

## Efficiently Streaming Data

While sometimes you want to store an entire download in memory it is often more
efficient to stream the data in chunks. In this example we will write the output
to a file.
            
```c
#include <libsoup/soup.h>

int main (int argc, char **argv)
{
    SoupSession *session = soup_session_new ();
    SoupMessageHeaders *response_headers;
    const char *content_type;
    goffset content_length;
    SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://upload.wikimedia.org/wikipedia/commons/5/5f/BBB-Bunny.png");
    GError *error = NULL;
    GInputStream *in_stream = soup_session_send (
        session,
        msg,
        NULL,
        &error);

    if (error) {
        g_printerr ("Failed to download: %s\n", error->message);
        g_error_free (error);
        g_object_unref (msg);
        g_object_unref (session);
        return 1;
    }

    GFile *output_file = g_file_new_tmp ("BBB-Bunny-XXXXXX.png");
    GOutputStream *out_stream = g_file_create (output_file,
        G_FILE_CREATE_NONE, NULL, &error);

    if (error) {
        g_printerr ("Failed to create file \"%s\": %s\n",
                    g_file_peek_path (output_file), error->message);
        g_error_free (error);
        g_object_unref (output_file);
        g_object_unref (in_stream);
        g_object_unref (msg);
        g_object_unref (session);
        return 1;
    }

    response_headers = soup_message_get_response_headers (msg);
    content_type = soup_message_headers_get_content_type (response_headers);
    content_length = soup_message_headers_get_content_length (response_headers);

    // content_type = "image/png"
    g_print ("Downloading %zu bytes of type %s to %s\n",
             content_length, content_type,
             g_file_peek_path (output_file));

    g_output_stream_splice (out_stream, in_stream,
        G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
        NULL, &error);

    if (error) {
        g_print ("Download failed: %s\n", error->message);
        g_error_free (error);
    } else {
        g_print ("Download completed\n");
    }

    g_object_unref (output_file);
    g_object_unref (in_stream);
    g_object_unref (out_stream);
    g_object_unref (msg);
    g_object_unref (session);
    return error ? 1 : 0;
}
```

## Using Asynchronously

If you are using libsoup in an application with a [struct@GLib.MainLoop] such as
a GTK application you do not want to block the mainloop by doing IO. To
accomplish this libsoup provides an asynchronous version of each of the APIs:
[method@Session.send_and_read_async] and [method@Session.send_async]. These
behave the same as all async GLib APIs, for example:

```c
#include <libsoup/soup.h>

static void on_load_callback (GObject *source, GAsyncResult *result, gpointer user_data)
{
    GMainLoop *loop = user_data;
    GError *error = NULL;
    GBytes *bytes = soup_session_send_and_read_finish (SOUP_SESSION (source), result, &error);

    // Usage here is the same as before
    if (error) {
        g_error_free (error);
    } else {
        g_bytes_unref (bytes);
    }

    g_main_loop_quit (loop);
}

int main (int argc, char **argv)
{
    SoupSession *session = soup_session_new ();
    GMainLoop *loop = g_main_loop_new (NULL, FALSE);
    SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://upload.wikimedia.org/wikipedia/commons/5/5f/BBB-Bunny.png");

    soup_session_send_and_read_async (
        session,
        msg,
        G_PRIORITY_DEFAULT,
        NULL,
        on_load_callback,
        loop);

    g_main_loop_run (loop);

    g_main_loop_unref (loop);
    g_object_unref (msg);
    g_object_unref (session);
    return 0;
}
```
