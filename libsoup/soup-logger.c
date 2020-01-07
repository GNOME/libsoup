/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-logger.c
 *
 * Copyright (C) 2001-2004 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2013 Igalia, S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "soup-logger.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup.h"

/**
 * SECTION:soup-logger
 * @short_description: Debug logging support
 *
 * #SoupLogger watches a #SoupSession and logs the HTTP traffic that
 * it generates, for debugging purposes. Many applications use an
 * environment variable to determine whether or not to use
 * #SoupLogger, and to determine the amount of debugging output.
 *
 * To use #SoupLogger, first create a logger with soup_logger_new(),
 * optionally configure it with soup_logger_set_request_filter(),
 * soup_logger_set_response_filter(), and soup_logger_set_printer(),
 * and then attach it to a session (or multiple sessions) with
 * soup_session_add_feature().
 *
 * By default, the debugging output is sent to
 * <literal>stdout</literal>, and looks something like:
 *
 * <informalexample><screen>
 * > POST /unauth HTTP/1.1
 * > Soup-Debug-Timestamp: 1200171744
 * > Soup-Debug: SoupSessionAsync 1 (0x612190), SoupMessage 1 (0x617000), SoupSocket 1 (0x612220)
 * > Host: localhost
 * > Content-Type: text/plain
 * > Connection: close
 * >
 * > This is a test.
 *
 * &lt; HTTP/1.1 201 Created
 * &lt; Soup-Debug-Timestamp: 1200171744
 * &lt; Soup-Debug: SoupMessage 1 (0x617000)
 * &lt; Date: Sun, 12 Jan 2008 21:02:24 GMT
 * &lt; Content-Length: 0
 * </screen></informalexample>
 *
 * The <literal>Soup-Debug-Timestamp</literal> line gives the time (as
 * a <type>time_t</type>) when the request was sent, or the response fully
 * received.
 *
 * The <literal>Soup-Debug</literal> line gives further debugging
 * information about the #SoupSession, #SoupMessage, and #SoupSocket
 * involved; the hex numbers are the addresses of the objects in
 * question (which may be useful if you are running in a debugger).
 * The decimal IDs are simply counters that uniquely identify objects
 * across the lifetime of the #SoupLogger. In particular, this can be
 * used to identify when multiple messages are sent across the same
 * connection.
 *
 * Currently, the request half of the message is logged just before
 * the first byte of the request gets written to the network (from the
 * #SoupMessage::starting signal), which means that if you have
 * not made the complete request body available at that point, it will
 * not be logged.
 *
 * The response is logged just after the last byte of the response
 * body is read from the network (from the #SoupMessage::got_body or
 * #SoupMessage::got_informational signal), which means that the
 * #SoupMessage::got_headers signal, and anything triggered off it
 * (such as #SoupSession::authenticate) will be emitted
 * <emphasis>before</emphasis> the response headers are actually
 * logged.
 *
 * If the response doesn't happen to trigger the
 * #SoupMessage::got_body nor #SoupMessage::got_informational signals
 * due to, for example, a cancellation before receiving the last byte
 * of the response body, the response will still be logged on the
 * event of the #SoupMessage::finished signal.
 **/

typedef struct {
	/* We use a mutex so that if requests are being run in
	 * multiple threads, we don't mix up the output.
	 */
	GMutex             lock;

	GQuark              tag;
	GHashTable         *ids;

	SoupSession        *session;
	SoupLoggerLogLevel  level;
	int                 max_body_size;

	SoupLoggerFilter    request_filter;
	gpointer            request_filter_data;
	GDestroyNotify      request_filter_dnotify;

	SoupLoggerFilter    response_filter;
	gpointer            response_filter_data;
	GDestroyNotify      response_filter_dnotify;

	SoupLoggerPrinter   printer;
	gpointer            printer_data;
	GDestroyNotify      printer_dnotify;
} SoupLoggerPrivate;

enum {
	PROP_0,

	PROP_LEVEL,
	PROP_MAX_BODY_SIZE,

	LAST_PROP
};

static SoupSessionFeatureInterface *soup_logger_default_feature_interface;
static void soup_logger_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupLogger, soup_logger, G_TYPE_OBJECT,
                         G_ADD_PRIVATE (SoupLogger)
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_logger_session_feature_init))

static void
soup_logger_init (SoupLogger *logger)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	g_mutex_init (&priv->lock);
	priv->tag = g_quark_from_static_string (g_strdup_printf ("SoupLogger-%p", logger));
	priv->ids = g_hash_table_new (NULL, NULL);
}

static void
soup_logger_finalize (GObject *object)
{
	SoupLogger *logger = SOUP_LOGGER (object);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	g_hash_table_destroy (priv->ids);

	if (priv->request_filter_dnotify)
		priv->request_filter_dnotify (priv->request_filter_data);
	if (priv->response_filter_dnotify)
		priv->response_filter_dnotify (priv->response_filter_data);
	if (priv->printer_dnotify)
		priv->printer_dnotify (priv->printer_data);

	g_mutex_clear (&priv->lock);

	G_OBJECT_CLASS (soup_logger_parent_class)->finalize (object);
}

static void
soup_logger_set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	SoupLogger *logger = SOUP_LOGGER (object);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	switch (prop_id) {
	case PROP_LEVEL:
		priv->level = g_value_get_enum (value);
		break;
	case PROP_MAX_BODY_SIZE:
		priv->max_body_size = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_logger_get_property (GObject *object, guint prop_id,
			   GValue *value, GParamSpec *pspec)
{
	SoupLogger *logger = SOUP_LOGGER (object);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	switch (prop_id) {
	case PROP_LEVEL:
		g_value_set_enum (value, priv->level);
		break;
	case PROP_MAX_BODY_SIZE:
		g_value_set_int (value, priv->max_body_size);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_logger_class_init (SoupLoggerClass *logger_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (logger_class);

	object_class->finalize = soup_logger_finalize;
	object_class->set_property = soup_logger_set_property;
	object_class->get_property = soup_logger_get_property;

	/* properties */
	/**
	 * SoupLogger:level:
	 *
	 * The level of logging output
	 *
	 * Since: 2.56
	 */
	/**
	 * SOUP_LOGGER_LEVEL:
	 *
	 * Alias for the #SoupLogger:level property, qv.
	 *
	 * Since: 2.56
	 **/
	g_object_class_install_property (
		object_class, PROP_LEVEL,
		g_param_spec_enum (SOUP_LOGGER_LEVEL,
				    "Level",
				    "The level of logging output",
				    SOUP_TYPE_LOGGER_LOG_LEVEL,
				    SOUP_LOGGER_LOG_MINIMAL,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));

	/**
	 * SoupLogger:max-body-size:
	 *
	 * If #SoupLogger:level is %SOUP_LOGGER_LOG_BODY, this gives
	 * the maximum number of bytes of the body that will be logged.
	 * (-1 means "no limit".)
	 *
	 * Since: 2.56
	 */
	/**
	 * SOUP_LOGGER_MAX_BODY_SIZE:
	 *
	 * Alias for the #SoupLogger:max-body-size property, qv.
	 *
	 * Since: 2.56
	 **/
	g_object_class_install_property (
		object_class, PROP_MAX_BODY_SIZE,
		g_param_spec_int (SOUP_LOGGER_MAX_BODY_SIZE,
				    "Max Body Size",
				    "The maximum body size to output",
				    -1,
				    G_MAXINT,
				    -1,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
}

/**
 * SoupLoggerLogLevel:
 * @SOUP_LOGGER_LOG_NONE: No logging
 * @SOUP_LOGGER_LOG_MINIMAL: Log the Request-Line or Status-Line and
 * the Soup-Debug pseudo-headers
 * @SOUP_LOGGER_LOG_HEADERS: Log the full request/response headers
 * @SOUP_LOGGER_LOG_BODY: Log the full headers and request/response
 * bodies.
 *
 * Describes the level of logging output to provide.
 **/

/**
 * soup_logger_new:
 * @level: the debug level
 * @max_body_size: the maximum body size to output, or -1
 *
 * Creates a new #SoupLogger with the given debug level. If @level is
 * %SOUP_LOGGER_LOG_BODY, @max_body_size gives the maximum number of
 * bytes of the body that will be logged. (-1 means "no limit".)
 *
 * If you need finer control over what message parts are and aren't
 * logged, use soup_logger_set_request_filter() and
 * soup_logger_set_response_filter().
 *
 * Returns: a new #SoupLogger
 **/
SoupLogger *
soup_logger_new (SoupLoggerLogLevel level, int max_body_size)
{
	return g_object_new (SOUP_TYPE_LOGGER,
			     SOUP_LOGGER_LEVEL, level,
			     SOUP_LOGGER_MAX_BODY_SIZE, max_body_size,
			     NULL);
}

/**
 * SoupLoggerFilter:
 * @logger: the #SoupLogger
 * @msg: the message being logged
 * @user_data: the data passed to soup_logger_set_request_filter()
 * or soup_logger_set_response_filter()
 *
 * The prototype for a logging filter. The filter callback will be
 * invoked for each request or response, and should analyze it and
 * return a #SoupLoggerLogLevel value indicating how much of the
 * message to log. Eg, it might choose between %SOUP_LOGGER_LOG_BODY
 * and %SOUP_LOGGER_LOG_HEADERS depending on the Content-Type.
 *
 * Return value: a #SoupLoggerLogLevel value indicating how much of
 * the message to log
 **/

/**
 * soup_logger_set_request_filter:
 * @logger: a #SoupLogger
 * @request_filter: the callback for request debugging
 * @filter_data: data to pass to the callback
 * @destroy: a #GDestroyNotify to free @filter_data
 *
 * Sets up a filter to determine the log level for a given request.
 * For each HTTP request @logger will invoke @request_filter to
 * determine how much (if any) of that request to log. (If you do not
 * set a request filter, @logger will just always log requests at the
 * level passed to soup_logger_new().)
 **/
void
soup_logger_set_request_filter (SoupLogger       *logger,
				SoupLoggerFilter  request_filter,
				gpointer          filter_data,
				GDestroyNotify    destroy)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	priv->request_filter         = request_filter;
	priv->request_filter_data    = filter_data;
	priv->request_filter_dnotify = destroy;
}

/**
 * soup_logger_set_response_filter:
 * @logger: a #SoupLogger
 * @response_filter: the callback for response debugging
 * @filter_data: data to pass to the callback
 * @destroy: a #GDestroyNotify to free @filter_data
 *
 * Sets up a filter to determine the log level for a given response.
 * For each HTTP response @logger will invoke @response_filter to
 * determine how much (if any) of that response to log. (If you do not
 * set a response filter, @logger will just always log responses at
 * the level passed to soup_logger_new().)
 **/
void
soup_logger_set_response_filter (SoupLogger       *logger,
				 SoupLoggerFilter  response_filter,
				 gpointer          filter_data,
				 GDestroyNotify    destroy)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	priv->response_filter         = response_filter;
	priv->response_filter_data    = filter_data;
	priv->response_filter_dnotify = destroy;
}

/**
 * SoupLoggerPrinter:
 * @logger: the #SoupLogger
 * @level: the level of the information being printed.
 * @direction: a single-character prefix to @data
 * @data: data to print
 * @user_data: the data passed to soup_logger_set_printer()
 *
 * The prototype for a custom printing callback.
 *
 * @level indicates what kind of information is being printed. Eg, it
 * will be %SOUP_LOGGER_LOG_HEADERS if @data is header data.
 *
 * @direction is either '<', '>', or ' ', and @data is the single line
 * to print; the printer is expected to add a terminating newline.
 *
 * To get the effect of the default printer, you would do:
 *
 * <informalexample><programlisting>
 *	printf ("%c %s\n", direction, data);
 * </programlisting></informalexample>
 **/

/**
 * soup_logger_set_printer:
 * @logger: a #SoupLogger
 * @printer: the callback for printing logging output
 * @printer_data: data to pass to the callback
 * @destroy: a #GDestroyNotify to free @printer_data
 *
 * Sets up an alternate log printing routine, if you don't want
 * the log to go to <literal>stdout</literal>.
 **/
void
soup_logger_set_printer (SoupLogger        *logger,
			 SoupLoggerPrinter  printer,
			 gpointer           printer_data,
			 GDestroyNotify     destroy)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	priv->printer         = printer;
	priv->printer_data    = printer_data;
	priv->printer_dnotify = destroy;
}

static guint
soup_logger_get_id (SoupLogger *logger, gpointer object)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	return GPOINTER_TO_UINT (g_object_get_qdata (object, priv->tag));
}

static guint
soup_logger_set_id (SoupLogger *logger, gpointer object)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	gpointer klass = G_OBJECT_GET_CLASS (object);
	gpointer id;

	id = g_hash_table_lookup (priv->ids, klass);
	id = (char *)id + 1;
	g_hash_table_insert (priv->ids, klass, id);

	g_object_set_qdata (object, priv->tag, id);
	return GPOINTER_TO_UINT (id);
}

/**
 * soup_logger_attach:
 * @logger: a #SoupLogger
 * @session: a #SoupSession
 *
 * Sets @logger to watch @session and print debug information for
 * its messages.
 *
 * (The session will take a reference on @logger, which will be
 * removed when you call soup_logger_detach(), or when the session is
 * destroyed.)
 *
 * Deprecated: Use soup_session_add_feature() instead.
 **/
void
soup_logger_attach (SoupLogger  *logger,
		    SoupSession *session)
{
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
}

/**
 * soup_logger_detach:
 * @logger: a #SoupLogger
 * @session: a #SoupSession
 *
 * Stops @logger from watching @session.
 *
 * Deprecated: Use soup_session_remove_feature() instead.
 **/
void
soup_logger_detach (SoupLogger  *logger,
		    SoupSession *session)
{
	soup_session_remove_feature (session, SOUP_SESSION_FEATURE (logger));
}

static void soup_logger_print (SoupLogger *logger, SoupLoggerLogLevel level,
			       char direction, const char *format, ...) G_GNUC_PRINTF (4, 5);

static void
soup_logger_print (SoupLogger *logger, SoupLoggerLogLevel level,
		   char direction, const char *format, ...)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	va_list args;
	char *data, *line, *end;

	va_start (args, format);
	data = g_strdup_vprintf (format, args);
	va_end (args);

	if (level == SOUP_LOGGER_LOG_BODY && priv->max_body_size > 0) {
		if (strlen (data) > priv->max_body_size + 6)
			strcpy (data + priv->max_body_size, "\n[...]");
	}

	line = data;
	do {
		end = strchr (line, '\n');
		if (end)
			*end = '\0';
		if (priv->printer) {
			priv->printer (logger, level, direction,
				       line, priv->printer_data);
		} else
			printf ("%c %s\n", direction, line);

		line = end + 1;
	} while (end && *line);

	g_free (data);
}

static void
soup_logger_print_basic_auth (SoupLogger *logger, const char *value)
{
	char *decoded, *decoded_utf8, *p;
	gsize len;

	decoded = (char *)g_base64_decode (value + 6, &len);
	if (decoded && !g_utf8_validate (decoded, -1, NULL)) {
		decoded_utf8 = g_convert_with_fallback (decoded, -1,
							"UTF-8", "ISO-8859-1",
							NULL, NULL, &len,
							NULL);
		if (decoded_utf8) {
			g_free (decoded);
			decoded = decoded_utf8;
		}
	}

	if (!decoded)
		decoded = g_strdup (value);
	p = strchr (decoded, ':');
	if (p) {
		while (++p < decoded + len)
			*p = '*';
	}
	soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '>',
			   "Authorization: Basic [%.*s]", (int)len, decoded);
	g_free (decoded);
}

static void
print_request (SoupLogger *logger, SoupMessage *msg,
	       SoupSocket *socket, gboolean restarted)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	SoupLoggerLogLevel log_level;
	SoupMessageHeadersIter iter;
	const char *name, *value;
	char *socket_dbg;
	SoupURI *uri;

	if (priv->request_filter) {
		log_level = priv->request_filter (logger, msg,
						  priv->request_filter_data);
	} else
		log_level = priv->level;

	if (log_level == SOUP_LOGGER_LOG_NONE)
		return;

	uri = soup_message_get_uri (msg);
	if (msg->method == SOUP_METHOD_CONNECT) {
		soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
				   "CONNECT %s:%u HTTP/1.%d",
				   uri->host, uri->port,
				   soup_message_get_http_version (msg));
	} else {
		soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
				   "%s %s%s%s HTTP/1.%d",
				   msg->method, uri->path,
				   uri->query ? "?" : "",
				   uri->query ? uri->query : "",
				   soup_message_get_http_version (msg));
	}

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
			   "Soup-Debug-Timestamp: %lu",
			   (unsigned long)time (0));

	socket_dbg = socket ?
		g_strdup_printf ("%s %u (%p)",
				 g_type_name_from_instance ((GTypeInstance *)socket),
				 soup_logger_get_id (logger, socket), socket)
		: NULL;

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
			   "Soup-Debug: %s %u (%p), %s %u (%p), %s%s",
			   g_type_name_from_instance ((GTypeInstance *)priv->session),
			   soup_logger_get_id (logger, priv->session), priv->session,
			   g_type_name_from_instance ((GTypeInstance *)msg),
			   soup_logger_get_id (logger, msg), msg,
			   socket_dbg ? socket_dbg : "cached",
			   restarted ? ", restarted" : "");
	g_free (socket_dbg);

	if (log_level == SOUP_LOGGER_LOG_MINIMAL)
		return;

	if (!soup_message_headers_get_one (msg->request_headers, "Host")) {
		char *uri_host;

		if (strchr (uri->host, ':'))
			uri_host = g_strdup_printf ("[%s]", uri->host);
		else if (g_hostname_is_non_ascii (uri->host))
			uri_host = g_hostname_to_ascii (uri->host);
		else
			uri_host = uri->host;

		soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '>',
				   "Host: %s%c%u", uri_host,
				   soup_uri_uses_default_port (uri) ? '\0' : ':',
				   uri->port);

		if (uri_host != uri->host)
			g_free (uri_host);
	}
	soup_message_headers_iter_init (&iter, msg->request_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		if (!g_ascii_strcasecmp (name, "Authorization") &&
		    !g_ascii_strncasecmp (value, "Basic ", 6))
			soup_logger_print_basic_auth (logger, value);
		else {
			soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '>',
					   "%s: %s", name, value);
		}
	}
	if (log_level == SOUP_LOGGER_LOG_HEADERS)
		return;

	if (msg->request_body->length &&
	    soup_message_body_get_accumulate (msg->request_body)) {
		SoupBuffer *request;

		request = soup_message_body_flatten (msg->request_body);
		g_return_if_fail (request != NULL);
		soup_buffer_free (request);

		if (soup_message_headers_get_expectations (msg->request_headers) != SOUP_EXPECTATION_CONTINUE) {
			soup_logger_print (logger, SOUP_LOGGER_LOG_BODY, '>',
					   "\n%s", msg->request_body->data);
		}
	}
}

static void
print_response (SoupLogger *logger, SoupMessage *msg)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	SoupLoggerLogLevel log_level;
	SoupMessageHeadersIter iter;
	const char *name, *value;

	if (priv->response_filter) {
		log_level = priv->response_filter (logger, msg,
						   priv->response_filter_data);
	} else
		log_level = priv->level;

	if (log_level == SOUP_LOGGER_LOG_NONE)
		return;

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '<',
			   "HTTP/1.%d %u %s\n",
			   soup_message_get_http_version (msg),
			   msg->status_code, msg->reason_phrase);

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '<',
			   "Soup-Debug-Timestamp: %lu",
			   (unsigned long)time (0));
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '<',
			   "Soup-Debug: %s %u (%p)",
			   g_type_name_from_instance ((GTypeInstance *)msg),
			   soup_logger_get_id (logger, msg), msg);

	if (log_level == SOUP_LOGGER_LOG_MINIMAL)
		return;

	soup_message_headers_iter_init (&iter, msg->response_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '<',
				   "%s: %s", name, value);
	}
	if (log_level == SOUP_LOGGER_LOG_HEADERS)
		return;

	if (msg->response_body->data) {
		soup_logger_print (logger, SOUP_LOGGER_LOG_BODY, '<',
				   "\n%s", msg->response_body->data);
	}
}

static void
finished (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = user_data;
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	g_mutex_lock (&priv->lock);

	print_response (logger, msg);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");

	g_mutex_unlock (&priv->lock);
}

static void
got_informational (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = user_data;
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	g_mutex_lock (&priv->lock);

	g_signal_handlers_disconnect_by_func (msg, finished, logger);
	print_response (logger, msg);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");

	if (msg->status_code == SOUP_STATUS_CONTINUE && msg->request_body->data) {
		SoupLoggerLogLevel log_level;

		soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
				   "[Now sending request body...]");

		if (priv->request_filter) {
			log_level = priv->request_filter (logger, msg,
							  priv->request_filter_data);
		} else
			log_level = priv->level;

		if (log_level == SOUP_LOGGER_LOG_BODY) {
			soup_logger_print (logger, SOUP_LOGGER_LOG_BODY, '>',
					   "%s", msg->request_body->data);
		}

		soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");
	}

	g_mutex_unlock (&priv->lock);
}

static void
got_body (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = user_data;
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	g_mutex_lock (&priv->lock);

	g_signal_handlers_disconnect_by_func (msg, finished, logger);
	print_response (logger, msg);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");

	g_mutex_unlock (&priv->lock);
}

static void
starting (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = SOUP_LOGGER (user_data);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	gboolean restarted;
	guint msg_id;
	SoupConnection *conn;
	SoupSocket *socket;

	msg_id = soup_logger_get_id (logger, msg);
	if (msg_id)
		restarted = TRUE;
	else {
		soup_logger_set_id (logger, msg);
		restarted = FALSE;
	}

	if (!soup_logger_get_id (logger, priv->session))
		soup_logger_set_id (logger, priv->session);

	conn = soup_message_get_connection (msg);
	socket = conn ? soup_connection_get_socket (conn) : NULL;
	if (socket && !soup_logger_get_id (logger, socket))
		soup_logger_set_id (logger, socket);

	print_request (logger, msg, socket, restarted);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");
}

static void
soup_logger_request_queued (SoupSessionFeature *logger,
			    SoupSession *session,
			    SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	g_signal_connect (msg, "starting",
			  G_CALLBACK (starting),
			  logger);
	g_signal_connect (msg, "got-informational",
			  G_CALLBACK (got_informational),
			  logger);
	g_signal_connect (msg, "got-body",
			  G_CALLBACK (got_body),
			  logger);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (finished),
			  logger);
}

static void
soup_logger_request_unqueued (SoupSessionFeature *logger,
			      SoupSession *session,
			      SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	g_signal_handlers_disconnect_by_func (msg, starting, logger);
	g_signal_handlers_disconnect_by_func (msg, got_informational, logger);
	g_signal_handlers_disconnect_by_func (msg, got_body, logger);
	g_signal_handlers_disconnect_by_func (msg, finished, logger);
}

static void
soup_logger_feature_attach (SoupSessionFeature *feature,
			    SoupSession *session)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (SOUP_LOGGER (feature));

	priv->session = session;

	soup_logger_default_feature_interface->attach (feature, session);
}

static void
soup_logger_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				  gpointer interface_data)
{
	soup_logger_default_feature_interface =
		g_type_default_interface_peek (SOUP_TYPE_SESSION_FEATURE);

	feature_interface->attach = soup_logger_feature_attach;
	feature_interface->request_queued = soup_logger_request_queued;
	feature_interface->request_unqueued = soup_logger_request_unqueued;
}
