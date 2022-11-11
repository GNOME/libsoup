/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-message-metrics.c
 *
 * Copyright (C) 2021 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-message-metrics-private.h"

/**
 * SoupMessageMetrics:
 *
 * Contains metrics collected while loading a [class@Message] either from the
 * network or the disk cache.
 *
 * Metrics are not collected by default for a [class@Message], you need to add the
 * flag %SOUP_MESSAGE_COLLECT_METRICS to enable the feature.
 *
 * Temporal metrics are expressed as a monotonic time and always start with a
 * fetch start event and finish with response end. All other events are optional.
 * An event can be 0 because it hasn't happened yet, because it's optional or
 * because the load failed before the event reached.
 *
 * Size metrics are expressed in bytes and are updated while the [class@Message] is
 * being loaded. You can connect to different [class@Message] signals to get the
 * final result of every value.
 */

G_DEFINE_BOXED_TYPE (SoupMessageMetrics, soup_message_metrics, soup_message_metrics_copy, soup_message_metrics_free)

SoupMessageMetrics *
soup_message_metrics_new (void)
{
        return g_slice_new0 (SoupMessageMetrics);
}

/**
 * soup_message_metrics_copy:
 * @metrics: a #SoupMessageMetrics
 *
 * Copies @metrics.
 *
 * Returns: a copy of @metrics
 **/
SoupMessageMetrics *
soup_message_metrics_copy (SoupMessageMetrics *metrics)
{
        SoupMessageMetrics *copy;

        g_return_val_if_fail (metrics != NULL, NULL);

        copy = soup_message_metrics_new ();
        *copy = *metrics;

        return copy;
}

/**
 * soup_message_metrics_free:
 * @metrics: a #SoupMessageMetrics
 *
 * Frees @metrics.
 */
void
soup_message_metrics_free (SoupMessageMetrics *metrics)
{
        g_return_if_fail (metrics != NULL);

        g_slice_free (SoupMessageMetrics, metrics);
}

/**
 * soup_message_metrics_get_fetch_start:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately before the [class@Message] started to
 * fetch a resource either from a remote server or local disk cache.
 *
 * Returns: the fetch start time
 */
guint64
soup_message_metrics_get_fetch_start (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->fetch_start;
}

/**
 * soup_message_metrics_get_dns_start:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately before the [class@Message] started the
 * domain lookup name for the resource.
 *
 * It will be 0 if no domain lookup was required to fetch the resource (a
 * persistent connection was used or resource was loaded from the local disk
 * cache).
 *
 * Returns: the domain lookup start time
 */
guint64
soup_message_metrics_get_dns_start (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->dns_start;
}

/**
 * soup_message_metrics_get_dns_end:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately after the [class@Message] completed the
 * domain lookup name for the resource.
 *
 * It will be 0 if no domain lookup was required to fetch the resource (a
 * persistent connection was used or resource was loaded from the local disk
 * cache).
 *
 * Returns: the domain lookup end time
 */
guint64
soup_message_metrics_get_dns_end (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->dns_end;
}

/**
 * soup_message_metrics_get_connect_start:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately before the [class@Message] started to
 * establish the connection to the server.
 *
 * It will be 0 if no network connection was required to fetch the resource (a
 * persistent connection was used or resource was loaded from the local disk
 * cache).
 *
 * Returns: the connection start time
 */
guint64
soup_message_metrics_get_connect_start (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->connect_start;
}

/**
 * soup_message_metrics_get_connect_end:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately after the [class@Message] completed the
 * connection to the server. This includes the time for the proxy
 * negotiation and TLS handshake.
 *
 * It will be 0 if no network connection was required to fetch the resource (a
 * persistent connection was used or resource was loaded from the local disk
 * cache).
 *
 * Returns: the connection end time
 */
guint64
soup_message_metrics_get_connect_end (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->connect_end;
}

/**
 * soup_message_metrics_get_tls_start:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately before the [class@Message] started the
 * TLS handshake.
 *
 * It will be 0 if no TLS handshake was required to fetch the resource
 * (connection was not secure, a persistent connection was used or resource was
 * loaded from the local disk cache).
 *
 * Returns: the tls start time
 */
guint64
soup_message_metrics_get_tls_start (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->tls_start;
}

/**
 * soup_message_metrics_get_request_start:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately before the [class@Message] started the
 * request of the resource from the server or the local disk cache.
 *
 * Returns: the request start time
 */
guint64
soup_message_metrics_get_request_start (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->request_start;
}

/**
 * soup_message_metrics_get_response_start:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately after the [class@Message] received the first
 * bytes of the response from the server or the local disk cache.
 *
 * Returns: the response start time
 */
guint64
soup_message_metrics_get_response_start (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->response_start;
}

/**
 * soup_message_metrics_get_response_end:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the time immediately after the [class@Message] received the last
 * bytes of the response from the server or the local disk cache.
 *
 * In case of load failure, this returns the time immediately before the
 * fetch is aborted.
 *
 * Returns: the response end time
 */
guint64
soup_message_metrics_get_response_end (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->response_end;
}

/**
 * soup_message_metrics_get_request_header_bytes_sent:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the number of bytes sent to the network for the request headers.
 *
 * This value is available right before [signal@Message::wrote-headers] signal
 * is emitted, but you might get an intermediate value if called before.
 *
 * Returns: the request headers bytes sent
 */
guint64
soup_message_metrics_get_request_header_bytes_sent (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->request_header_bytes_sent;
}

/**
 * soup_message_metrics_get_request_body_size:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the request body size in bytes. This is the size of the original body
 * given to the request before any encoding is applied.
 *
 * This value is available right before [signal@Message::wrote-body] signal is
 * emitted, but you might get an intermediate value if called before.
 *
 * Returns: the request body size
 */
guint64
soup_message_metrics_get_request_body_size (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->request_body_size;
}

/**
 * soup_message_metrics_get_request_body_bytes_sent:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the number of bytes sent to the network for the request body.
 *
 * This is the size of the body sent, after encodings are applied, so it might
 * be greater than the value returned by
 * [method@MessageMetrics.get_request_body_size]. This value is available right
 * before [signal@Message::wrote-body] signal is emitted, but you might get an
 * intermediate value if called before.
 *
 * Returns: the request body bytes sent
 */
guint64
soup_message_metrics_get_request_body_bytes_sent (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->request_body_bytes_sent;
}

/**
 * soup_message_metrics_get_response_header_bytes_received:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the number of bytes received from the network for the response headers.
 *
 * This value is available right before [signal@Message::got-headers] signal
 * is emitted, but you might get an intermediate value if called before.
 * For resources loaded from the disk cache this value is always 0.
 *
 * Returns: the response headers bytes received
 */
guint64
soup_message_metrics_get_response_header_bytes_received (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->response_header_bytes_received;
}

/**
 * soup_message_metrics_get_response_body_size:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the response body size in bytes.
 *
 * This is the size of the body as given to the user after all encodings are
 * applied, so it might be greater than the value returned by
 * [method@MessageMetrics.get_response_body_bytes_received]. This value is
 * available right before [signal@Message::got-body] signal is emitted, but you
 * might get an intermediate value if called before.
 *
 * Returns: the response body size
 */
guint64
soup_message_metrics_get_response_body_size (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->response_body_size;
}

/**
 * soup_message_metrics_get_response_body_bytes_received:
 * @metrics: a #SoupMessageMetrics
 *
 * Get the number of bytes received from the network for the response body.
 *
 * This value is available right before [signal@Message::got-body] signal is
 * emitted, but you might get an intermediate value if called before. For
 * resources loaded from the disk cache this value is always 0.
 *
 * Returns: the response body bytes received
 */
guint64
soup_message_metrics_get_response_body_bytes_received (SoupMessageMetrics *metrics)
{
        g_return_val_if_fail (metrics != NULL, 0);

        return metrics->response_body_bytes_received;
}
