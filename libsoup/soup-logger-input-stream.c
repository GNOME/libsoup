/* soup-logger-stream.c
 *
 * Copyright (C) 2021 Igalia S.L.
 */

#include <string.h>

#include "soup-logger-input-stream.h"
#include "soup.h"

enum {
        PROP_0,

        PROP_LOGGER,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

enum {
        READ_DATA,
        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _SoupLoggerInputStream {
        GFilterInputStream parent;
};

typedef struct {
        SoupLogger  *logger;
        GByteArray  *buffer; /* for skip; we still need to log it */
} SoupLoggerInputStreamPrivate;

static void soup_logger_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupLoggerInputStream, soup_logger_input_stream, G_TYPE_FILTER_INPUT_STREAM,
                               G_ADD_PRIVATE (SoupLoggerInputStream)
                               G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
                                                      soup_logger_input_stream_pollable_init))

static void
soup_logger_input_stream_init (SoupLoggerInputStream *logger)
{
}

static void
soup_logger_input_stream_finalize (GObject *object)
{
        SoupLoggerInputStream *stream = SOUP_LOGGER_INPUT_STREAM (object);
        SoupLoggerInputStreamPrivate *priv = soup_logger_input_stream_get_instance_private (stream);

        g_clear_object (&priv->logger);

        g_clear_pointer (&priv->buffer, g_byte_array_unref);

        G_OBJECT_CLASS (soup_logger_input_stream_parent_class)->finalize (object);
}

static void
soup_logger_input_stream_set_property (GObject *object, guint prop_id,
                                       const GValue *value, GParamSpec *pspec)
{
        SoupLoggerInputStream *stream = SOUP_LOGGER_INPUT_STREAM (object);
        SoupLoggerInputStreamPrivate *priv = soup_logger_input_stream_get_instance_private (stream);

        switch (prop_id) {
        case PROP_LOGGER:
                priv->logger = g_value_dup_object (value);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
soup_logger_input_stream_get_property (GObject *object, guint prop_id,
                                       GValue *value, GParamSpec *pspec)
{
        SoupLoggerInputStream *stream = SOUP_LOGGER_INPUT_STREAM (object);
        SoupLoggerInputStreamPrivate *priv = soup_logger_input_stream_get_instance_private (stream);

        switch (prop_id) {
        case PROP_LOGGER:
                g_value_set_object (value, priv->logger);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static gssize
read_internal (GInputStream  *stream,
               void          *buffer,
               gsize          count,
               gboolean       blocking,
               GCancellable  *cancellable,
               GError       **error)
{
        SoupLoggerInputStream *lstream = SOUP_LOGGER_INPUT_STREAM (stream);
        gssize nread;

        nread = g_pollable_stream_read (G_FILTER_INPUT_STREAM (stream)->base_stream,
                                        buffer, count, blocking, cancellable, error);

        if (nread > 0)
                g_signal_emit (lstream, signals[READ_DATA], 0, buffer, nread);

        return nread;
}

static gssize
soup_logger_input_stream_read (GInputStream  *stream,
                               void          *buffer,
                               gsize          count,
                               GCancellable  *cancellable,
                               GError       **error)
{
        return read_internal (stream, buffer, count, TRUE, cancellable, error);
}

static gssize
soup_logger_input_stream_skip (GInputStream  *stream,
                               gsize          count,
                               GCancellable  *cancellable,
                               GError       **error)
{
        SoupLoggerInputStream *lstream = SOUP_LOGGER_INPUT_STREAM (stream);
        SoupLoggerInputStreamPrivate *priv = soup_logger_input_stream_get_instance_private (lstream);

        if (!priv->buffer)
                priv->buffer = g_byte_array_sized_new (count);
        else
                g_byte_array_set_size (priv->buffer, count);

        return read_internal (stream, priv->buffer->data, count, TRUE, cancellable, error);
}

static gboolean
soup_logger_input_stream_can_poll (GPollableInputStream *stream)
{
        GInputStream *base_stream = G_FILTER_INPUT_STREAM (stream)->base_stream;

        return G_IS_POLLABLE_INPUT_STREAM (base_stream) &&
                g_pollable_input_stream_can_poll (G_POLLABLE_INPUT_STREAM (base_stream));
}

static gboolean
soup_logger_input_stream_is_readable (GPollableInputStream *stream)
{
        return g_pollable_input_stream_is_readable (G_POLLABLE_INPUT_STREAM (G_FILTER_INPUT_STREAM (stream)->base_stream));
}

static gssize
soup_logger_input_stream_read_nonblocking (GPollableInputStream  *stream,
                                           void                  *buffer,
                                           gsize                  count,
                                           GError               **error)
{
        return read_internal (G_INPUT_STREAM (stream),
                              buffer, count, FALSE, NULL, error);
}

static GSource *
soup_logger_input_stream_create_source (GPollableInputStream *stream,
                                        GCancellable         *cancellable)
{
        GSource *base_source, *pollable_source;

        base_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (G_FILTER_INPUT_STREAM (stream)->base_stream),
                                                             cancellable);

        g_source_set_dummy_callback (base_source);
        pollable_source = g_pollable_source_new (G_OBJECT (stream));
        g_source_add_child_source (pollable_source, base_source);
        g_source_unref (base_source);

        return pollable_source;
}

static void
soup_logger_input_stream_class_init (SoupLoggerInputStreamClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);
        GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (klass);

        object_class->finalize = soup_logger_input_stream_finalize;
        object_class->set_property = soup_logger_input_stream_set_property;
        object_class->get_property = soup_logger_input_stream_get_property;

        input_stream_class->read_fn = soup_logger_input_stream_read;
        input_stream_class->skip = soup_logger_input_stream_skip;

        signals[READ_DATA] =
                g_signal_new ("read-data",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE,
                              2,
                              G_TYPE_POINTER, G_TYPE_INT);

        properties[PROP_LOGGER] =
                g_param_spec_object ("logger",
                                     "Logger",
                                     "The stream's SoupLogger",
                                     SOUP_TYPE_LOGGER,
                                     G_PARAM_READWRITE |
                                     G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

static void
soup_logger_input_stream_pollable_init (GPollableInputStreamInterface *interface,
                                        gpointer                       interface_data)
{
        interface->can_poll = soup_logger_input_stream_can_poll;
        interface->is_readable = soup_logger_input_stream_is_readable;
        interface->read_nonblocking = soup_logger_input_stream_read_nonblocking;
        interface->create_source = soup_logger_input_stream_create_source;
}

SoupLogger *
soup_logger_input_stream_get_logger (SoupLoggerInputStream *stream)
{
        SoupLoggerInputStreamPrivate *priv = soup_logger_input_stream_get_instance_private (stream);

        return priv->logger;
}
