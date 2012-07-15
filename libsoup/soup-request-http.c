/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-request-http.c: http: URI request object
 *
 * Copyright (C) 2009, 2010 Red Hat, Inc.
 * Copyright (C) 2010 Igalia, S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>

#include "soup-request-http.h"
#include "soup.h"
#include "soup-cache-private.h"
#include "soup-session-private.h"

G_DEFINE_TYPE (SoupRequestHTTP, soup_request_http, SOUP_TYPE_REQUEST)

enum {
	PROP_0,

	PROP_METHOD,
	PROP_REQUEST_URI,
	PROP_REQUEST_VERSION,
	PROP_REQUEST_HEADERS,
	PROP_STATUS_CODE,
	PROP_REASON_PHRASE,
	PROP_RESPONSE_VERSION,
	PROP_RESPONSE_HEADERS,

	PROP_FLAGS,
	PROP_FIRST_PARTY,
	PROP_TLS_CERTIFICATE,
	PROP_TLS_ERRORS,

	LAST_PROP
};

struct _SoupRequestHTTPPrivate {
	SoupMessage *msg;
	char *content_type;
	gboolean sent;
};

static void content_sniffed (SoupMessage *msg,
			     const char  *content_type,
			     GHashTable  *params,
			     gpointer     user_data);

static void
soup_request_http_init (SoupRequestHTTP *http)
{
	http->priv = G_TYPE_INSTANCE_GET_PRIVATE (http, SOUP_TYPE_REQUEST_HTTP, SoupRequestHTTPPrivate);
}

static void
soup_request_http_set_property (GObject *object, guint prop_id,
				const GValue *value, GParamSpec *pspec)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (object);

	switch (prop_id) {
	case PROP_METHOD:
		soup_request_http_set_method (http, g_value_get_string (value));
		break;
	case PROP_REQUEST_VERSION:
		soup_request_http_set_request_version (http, g_value_get_enum (value));
		break;
	case PROP_FLAGS:
		soup_request_http_set_flags (http, g_value_get_flags (value));
		break;
	case PROP_FIRST_PARTY:
		soup_request_http_set_first_party (http, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_request_http_get_property (GObject *object, guint prop_id,
				GValue *value, GParamSpec *pspec)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (object);
	GTlsCertificate *cert;
	GTlsCertificateFlags errors;

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, http->method);
		break;
	case PROP_REQUEST_URI:
		g_value_set_boxed (value, http->request_uri);
		break;
	case PROP_REQUEST_VERSION:
		g_value_set_enum (value, http->request_version);
		break;
	case PROP_REQUEST_HEADERS:
		g_value_set_boxed (value, http->request_headers);
		break;
	case PROP_STATUS_CODE:
		g_value_set_uint (value, http->status_code);
		break;
	case PROP_REASON_PHRASE:
		g_value_set_string (value, http->reason_phrase);
		break;
	case PROP_RESPONSE_VERSION:
		g_value_set_enum (value, http->response_version);
		break;
	case PROP_RESPONSE_HEADERS:
		g_value_set_boxed (value, http->request_headers);
		break;
	case PROP_FLAGS:
		g_value_set_flags (value, soup_message_get_flags (http->priv->msg));
		break;
	case PROP_FIRST_PARTY:
		g_value_set_boxed (value, soup_message_get_first_party (http->priv->msg));
		break;
	case PROP_TLS_CERTIFICATE:
		g_object_get (G_OBJECT (http->priv->msg),
			      "tls-certificate", &cert,
			      NULL);
		g_value_set_object (value, cert);
		break;
	case PROP_TLS_ERRORS:
		g_object_get (G_OBJECT (http->priv->msg),
			      "tls-errors", &errors,
			      NULL);
		g_value_set_flags (value, errors);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
message_property_changed (GObject    *object,
			  GParamSpec *pspec,
			  gpointer    user_data)
{
	SoupRequestHTTP *http = user_data;

	if (!strcmp (pspec->name, "method")) {
		http->method = http->priv->msg->method;
		g_object_notify (G_OBJECT (http), "method");
	} else if (!strcmp (pspec->name, "uri")) {
		http->request_uri = soup_message_get_uri (http->priv->msg);
		g_object_notify (G_OBJECT (http), "request-uri");
	} else if (!strcmp (pspec->name, "status-code")) {
		http->status_code = http->priv->msg->status_code;
		g_object_notify (G_OBJECT (http), "status-code");
	} else if (!strcmp (pspec->name, "reason-phrase")) {
		http->reason_phrase = http->priv->msg->reason_phrase;
		g_object_notify (G_OBJECT (http), "reason-phrase");
	} else if (!strcmp (pspec->name, "http-version")) {
		if (!http->priv->sent) {
			http->request_version = soup_message_get_http_version (http->priv->msg);
			g_object_notify (G_OBJECT (http), "request-version");
		} else {
			http->response_version = soup_message_get_http_version (http->priv->msg);
			g_object_notify (G_OBJECT (http), "response-version");
		}
	} else if (!strcmp (pspec->name, "flags"))
		g_object_notify (G_OBJECT (http), "flags");
	else if (!strcmp (pspec->name, "first-party"))
		g_object_notify (G_OBJECT (http), "first-party");
	else if (!strcmp (pspec->name, "tls-certificate"))
		g_object_notify (G_OBJECT (http), "tls-certificate");
	else if (!strcmp (pspec->name, "tls-errors"))
		g_object_notify (G_OBJECT (http), "tls-errors");
}

static gboolean
soup_request_http_check_uri (SoupRequest  *request,
			     SoupURI      *uri,
			     GError      **error)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (request);

	if (!SOUP_URI_VALID_FOR_HTTP (uri))
		return FALSE;

	http->priv->msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
	g_signal_connect (http->priv->msg, "content-sniffed",
			  G_CALLBACK (content_sniffed), http);

	g_signal_connect (http->priv->msg, "notify",
			  G_CALLBACK (message_property_changed), http);

	http->method = http->priv->msg->method;
	http->request_uri = soup_message_get_uri (http->priv->msg);
	http->request_version = SOUP_HTTP_1_1;
	http->request_headers = http->priv->msg->request_headers;
	http->response_version = SOUP_HTTP_1_1;
	http->response_headers = http->priv->msg->response_headers;

	return TRUE;
}

static void
soup_request_http_finalize (GObject *object)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (object);

	if (http->priv->msg) {
		g_signal_handlers_disconnect_by_func (http->priv->msg,
						      G_CALLBACK (content_sniffed),
						      http);
		g_signal_handlers_disconnect_by_func (http->priv->msg,
						      G_CALLBACK (message_property_changed),
						      http);
		g_object_unref (http->priv->msg);
	}

	g_free (http->priv->content_type);

	G_OBJECT_CLASS (soup_request_http_parent_class)->finalize (object);
}

static GInputStream *
soup_request_http_send (SoupRequest          *request,
			GCancellable         *cancellable,
			GError              **error)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (request);
	SoupSession *session = soup_request_get_session (request);

	g_return_val_if_fail (!SOUP_IS_SESSION_ASYNC (session), NULL);

	http->priv->sent = TRUE;
	return soup_session_send_request (session, http->priv->msg,
					  cancellable, error);
}


typedef struct {
	SoupMessage *original;
	GInputStream *stream;
} SendAsyncData;

static void
free_send_async_data (SendAsyncData *sadata)
{
       g_clear_object (&sadata->stream);
       g_clear_object (&sadata->original);

       g_slice_free (SendAsyncData, sadata);
}

static void
http_input_stream_ready_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GInputStream *stream;

	stream = soup_session_send_request_finish (SOUP_SESSION (source), result, &error);
	if (stream)
		g_task_return_pointer (task, stream, g_object_unref);
	else
		g_task_return_error (task, error);
	g_object_unref (task);
}

static void
conditional_get_ready_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	GTask *task = user_data;
	SoupRequestHTTP *http = g_task_get_source_object (task);
	SendAsyncData *sadata = g_task_get_task_data (task);
	GInputStream *stream;

	if (msg->status_code == SOUP_STATUS_NOT_MODIFIED) {
		SoupCache *cache = (SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE);

		stream = soup_cache_send_response (cache, sadata->original);
		if (stream) {
			soup_message_got_headers (sadata->original);
			soup_message_finished (sadata->original);

			http->priv->content_type = g_strdup (soup_message_headers_get_content_type (msg->response_headers, NULL));

			g_task_return_pointer (task, stream, g_object_unref);
			g_object_unref (task);
			return;
		}
	}

	/* The resource was modified or the server returned a 200
	 * OK. Either way we reload it. This is far from optimal as
	 * we're donwloading the resource twice, but we will change it
	 * once the cache is integrated in the streams stack.
	 */
	soup_session_send_request_async (session, sadata->original,
					 g_task_get_cancellable (task),
					 http_input_stream_ready_cb, task);
}

static gboolean
idle_return_from_cache_cb (gpointer data)
{
	GTask *task = data;
	SoupRequestHTTP *http = g_task_get_source_object (task);
	SendAsyncData *sadata = g_task_get_task_data (task);

	/* Issue signals  */
	soup_message_got_headers (http->priv->msg);
	soup_message_finished (http->priv->msg);

	http->priv->content_type = g_strdup (soup_message_headers_get_content_type (http->priv->msg->response_headers, NULL));

	g_task_return_pointer (task, g_object_ref (sadata->stream), g_object_unref);
	g_object_unref (task);

	return FALSE;
}

static void
soup_request_http_send_async (SoupRequest          *request,
			      GCancellable         *cancellable,
			      GAsyncReadyCallback   callback,
			      gpointer              user_data)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (request);
	SoupSession *session = soup_request_get_session (request);
	GTask *task;
	SendAsyncData *sadata;
	GInputStream *stream;
	SoupCache *cache;

	g_return_if_fail (!SOUP_IS_SESSION_SYNC (session));

	http->priv->sent = TRUE;

	task = g_task_new (request, cancellable, callback, user_data);
	sadata = g_slice_new0 (SendAsyncData);
	g_task_set_task_data (task, sadata, (GDestroyNotify)free_send_async_data);

	cache = (SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE);

	if (cache) {
		SoupCacheResponse response;

		response = soup_cache_has_response (cache, http->priv->msg);
		if (response == SOUP_CACHE_RESPONSE_FRESH) {
			stream = soup_cache_send_response (cache, http->priv->msg);

			/* Cached resource file could have been deleted outside */
			if (stream) {
				/* Do return the stream asynchronously as in
				 * the other cases. It's not enough to let
				 * GTask do the asynchrony for us, because
				 * the signals must be also emitted
				 * asynchronously
				 */
				sadata->stream = stream;
				soup_add_completion (soup_session_get_async_context (session),
						     idle_return_from_cache_cb, task);
				return;
			}
		} else if (response == SOUP_CACHE_RESPONSE_NEEDS_VALIDATION) {
			SoupMessage *conditional_msg;

			conditional_msg = soup_cache_generate_conditional_request (cache, http->priv->msg);

			if (conditional_msg) {
				sadata->original = g_object_ref (http->priv->msg);
				soup_session_queue_message (session, conditional_msg,
							    conditional_get_ready_cb,
							    task);
				return;
			}
		}
	}

	soup_session_send_request_async (session, http->priv->msg, cancellable,
					 http_input_stream_ready_cb, task);
}

static GInputStream *
soup_request_http_send_finish (SoupRequest   *request,
			       GAsyncResult  *result,
			       GError       **error)
{
	g_return_val_if_fail (g_task_is_valid (result, request), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static goffset
soup_request_http_get_content_length (SoupRequest *request)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (request);

	return soup_message_headers_get_content_length (http->priv->msg->response_headers);
}

static void
content_sniffed (SoupMessage *msg,
		 const char  *content_type,
		 GHashTable  *params,
		 gpointer     user_data)
{
	SoupRequestHTTP *http = user_data;
	GString *sniffed_type;

	sniffed_type = g_string_new (content_type);
	if (params) {
		GHashTableIter iter;
		gpointer key, value;

		g_hash_table_iter_init (&iter, params);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			g_string_append (sniffed_type, "; ");
			soup_header_g_string_append_param (sniffed_type, key, value);
		}
	}
	g_free (http->priv->content_type);
	http->priv->content_type = g_string_free (sniffed_type, FALSE);
}

static const char *
soup_request_http_get_content_type (SoupRequest *request)
{
	SoupRequestHTTP *http = SOUP_REQUEST_HTTP (request);

	return http->priv->content_type;
}

static const char *http_schemes[] = { "http", "https", NULL };

static void
soup_request_http_class_init (SoupRequestHTTPClass *request_http_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (request_http_class);
	SoupRequestClass *request_class =
		SOUP_REQUEST_CLASS (request_http_class);

	g_type_class_add_private (request_http_class, sizeof (SoupRequestHTTPPrivate));

	request_class->schemes = http_schemes;

	object_class->set_property = soup_request_http_set_property;
	object_class->get_property = soup_request_http_get_property;
	object_class->finalize = soup_request_http_finalize;

	request_class->check_uri = soup_request_http_check_uri;
	request_class->send = soup_request_http_send;
	request_class->send_async = soup_request_http_send_async;
	request_class->send_finish = soup_request_http_send_finish;
	request_class->get_content_length = soup_request_http_get_content_length;
	request_class->get_content_type = soup_request_http_get_content_type;

	/**
	 * SoupRequestHTTP:method:
	 *
	 * The request's HTTP method; "GET" by default. Note that in
	 * C you can simply read the <literal>method</literal> field
	 * of the #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_METHOD,
		g_param_spec_string ("method",
				     "Method",
				     "The HTTP method",
				     SOUP_METHOD_GET,
				     G_PARAM_READWRITE));
	/**
	 * SoupRequestHTTP:request-uri:
	 *
	 * The request's #SoupURI. Note that in C you can simply read
	 * the <literal>request_uri</literal> field of the
	 * #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_REQUEST_URI,
		g_param_spec_boxed ("request-uri",
				    "URI",
				    "The Request-URI",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE));
	/**
	 * SoupRequestHTTP:request-version:
	 *
	 * The #SoupHTTPVersion used when sending the request;
	 * %SOUP_HTTP_1_1 by default. Note that in C you can simply
	 * read the <literal>request_version</literal> field of the
	 * #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_REQUEST_VERSION,
		g_param_spec_enum ("request-version",
				   "Request HTTP Version",
				   "The SoupHTTPVersion used when sending the request",
				   SOUP_TYPE_HTTP_VERSION,
				   SOUP_HTTP_1_1,
				   G_PARAM_READWRITE));
	/**
	 * SoupRequestHTTP:request-headers:
	 *
	 * The request's HTTP request headers. Note that in C you can
	 * simply read the <literal>request_headers</literal> field of
	 * the #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_REQUEST_HEADERS,
		g_param_spec_boxed ("request-headers",
				    "Request Headers",
				    "The HTTP request headers",
				    SOUP_TYPE_MESSAGE_HEADERS,
				    G_PARAM_READABLE));

	/**
	 * SoupRequestHTTP:status-code:
	 *
	 * The request's HTTP response status code. Note that in C you
	 * can simply read the <literal>status_code</literal> field of
	 * the #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_STATUS_CODE,
		g_param_spec_uint ("status-code",
				   "Status code",
				   "The HTTP response status code",
				   0, 599, 0,
				   G_PARAM_READABLE));
	/**
	 * SoupRequestHTTP:reason-phrase:
	 *
	 * The request's HTTP response reason phrase. Note that in C
	 * you can simply read the <literal>reason_phrase</literal>
	 * field of the #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_REASON_PHRASE,
		g_param_spec_string ("reason-phrase",
				     "Reason phrase",
				     "The HTTP response reason phrase",
				     NULL,
				     G_PARAM_READABLE));
	/**
	 * SoupRequestHTTP:response-version:
	 *
	 * The #SoupHTTPVersion that the server replied with. Note
	 * that in C you can simply read the
	 * <literal>response_version</literal> field of the
	 * #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_RESPONSE_VERSION,
		g_param_spec_enum ("response-version",
				   "Response HTTP Version",
				   "The SoupHTTPVersion that the server replied with",
				   SOUP_TYPE_HTTP_VERSION,
				   SOUP_HTTP_1_1,
				   G_PARAM_READABLE));
	/**
	 * SoupRequestHTTP:response-headers:
	 *
	 * The request's HTTP response headers. Note that in C you can
	 * simply read the <literal>response_headers</literal> field
	 * of the #SoupRequestHTTP.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_RESPONSE_HEADERS,
		g_param_spec_boxed ("response-headers",
				    "Response Headers",
				    "The HTTP response headers",
				    SOUP_TYPE_MESSAGE_HEADERS,
				    G_PARAM_READABLE));

	/**
	 * SoupRequestHTTP:flags:
	 *
	 * The request's #SoupMessageFlags.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_FLAGS,
		g_param_spec_flags ("flags",
				    "Flags",
				    "Various request options",
				    SOUP_TYPE_MESSAGE_FLAGS,
				    0,
				    G_PARAM_READWRITE));
	/**
	 * SoupRequestHTTP:first-party:
	 *
	 * The #SoupURI loaded in the application when the request was
	 * queued.
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_FIRST_PARTY,
		g_param_spec_boxed ("first-party",
				    "First party",
				    "The URI loaded in the application when the request was queued.",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE));
	/**
	 * SoupRequestHTTP:tls-certificate:
	 *
	 * The #GTlsCertificate associated with the request
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_TLS_CERTIFICATE,
		g_param_spec_object ("tls-certificate",
				     "TLS Certificate",
				     "The TLS certificate associated with the request",
				     G_TYPE_TLS_CERTIFICATE,
				     G_PARAM_READABLE));
	/**
	 * SoupRequestHTTP:tls-errors:
	 *
	 * The verification errors on #SoupRequestHTTP:tls-certificate
	 *
	 * Since: 2.42
	 */
	g_object_class_install_property (
		object_class, PROP_TLS_ERRORS,
		g_param_spec_flags ("tls-errors",
				    "TLS Errors",
				    "The verification errors on the request's TLS certificate",
				    G_TYPE_TLS_CERTIFICATE_FLAGS, 0,
				    G_PARAM_READABLE));
}

/**
 * soup_request_http_get_message:
 * @http: a #SoupRequestHTTP object
 *
 * Gets a new reference to the #SoupMessage associated to this SoupRequest
 *
 * Returns: (transfer full): a new reference to the #SoupMessage
 *
 * Since: 2.42
 */
SoupMessage *
soup_request_http_get_message (SoupRequestHTTP *http)
{
	g_return_val_if_fail (SOUP_IS_REQUEST_HTTP (http), NULL);

	return g_object_ref (http->priv->msg);
}

void
soup_request_http_set_method (SoupRequestHTTP *http,
			      const char      *method)
{
	g_object_set (G_OBJECT (http->priv->msg),
		      "method", method,
		      NULL);
}

/**
 * soup_request_http_set_request_version:
 * @http: a #SoupRequestHTTP
 * @version: the version of HTTP to use
 *
 * Sets @http to use the version of HTTP specified by @version in its
 * request.
 *
 * Since: 2.42
 */
void
soup_request_http_set_request_version (SoupRequestHTTP *http,
				       SoupHTTPVersion  version)
{
	g_return_if_fail (!http->priv->sent);

	g_object_set (G_OBJECT (http->priv->msg),
		      "http-version", version,
		      NULL);
}

/**
 * soup_request_http_get_first_party:
 * @http: a #SoupRequestHTTP
 *
 * Gets @http's first-party #SoupURI; see the documentation
 * for #SoupCookieJarAcceptPolicy for more details.
 *
 * Returns: (transfer none): @http's first-party URI
 *
 * Since: 2.42
 */
SoupURI *
soup_request_http_get_first_party (SoupRequestHTTP *http)
{
	return soup_message_get_first_party (http->priv->msg);
}

/**
 * soup_request_http_set_first_party:
 * @http: a #SoupRequestHTTP
 * @first_party: the #SoupURI for the request's first party
 *
 * Sets @first_party as the main document #SoupURI for @http. For
 * details of when and how this is used refer to the documentation for
 * #SoupCookieJarAcceptPolicy.
 *
 * Since: 2.42
 */
void
soup_request_http_set_first_party (SoupRequestHTTP *http,
				   SoupURI         *first_party)
{
	soup_message_set_first_party (http->priv->msg,
				      first_party);
}

/**
 * soup_request_http_get_flags:
 * @http: a #SoupRequestHTTP
 *
 * Gets @http's message flags.
 *
 * Returns: @http's message flags
 *
 * Since: 2.42
 */
SoupMessageFlags
soup_request_http_get_flags (SoupRequestHTTP *http)
{
	return soup_message_get_flags (http->priv->msg);
}

/**
 * soup_request_http_set_flags:
 * @http: a #SoupRequestHTTP
 * @flags: a set of #SoupMessageFlags values
 *
 * Sets the specified flags on @msg. Note that some #SoupMessageFlags
 * (such as %SOUP_MESSAGE_CAN_REBUILD and
 * %SOUP_MESSAGE_OVERWRITE_CHUNKS) have no effect in the #SoupRequest
 * API.
 *
 * Since: 2.42
 */
void
soup_request_http_set_flags (SoupRequestHTTP  *http,
			     SoupMessageFlags  flags)
{
	soup_message_set_flags (http->priv->msg, flags);
}

/**
 * soup_request_http_get_https_status:
 * @http: a #SoupRequestHTTP
 * @certificate: (out) (transfer none): @http's TLS certificate
 * @errors: (out): the verification status of @certificate
 *
 * If @http is using https, this retrieves the #GTlsCertificate
 * associated with its connection, and the #GTlsCertificateFlags showing
 * what problems, if any, have been found with that certificate.
 *
 * Return value: %TRUE if @http uses https, %FALSE if not
 *
 * Since: 2.42
 */
gboolean
soup_request_http_get_https_status (SoupRequestHTTP       *http,
				    GTlsCertificate      **certificate,
				    GTlsCertificateFlags  *errors)
{
	return soup_message_get_https_status (http->priv->msg,
					      certificate, errors);
}
