/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-negotiate.c: HTTP Negotiate Authentication helper
 *
 * Copyright (C) 2009,2013 Guido Guenther <agx@sigxcpu.org>
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#ifdef LIBSOUP_HAVE_GSSAPI
#include <gssapi/gssapi.h>
#endif /* LIBSOUP_HAVE_GSSAPI */

#include "soup-auth-negotiate.h"
#include "soup-headers.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc-private.h"
#include "soup-uri.h"

/**
 * soup_auth_negotiate_supported:
 *
 * Indicates whether libsoup was built with GSSAPI support. If this is
 * %FALSE, %SOUP_TYPE_AUTH_NEGOTIATE will still be defined and can
 * still be added to a #SoupSession, but libsoup will never attempt to
 * actually use this auth type.
 *
 * Since: 2.54
 */
gboolean
soup_auth_negotiate_supported (void)
{
#ifdef LIBSOUP_HAVE_GSSAPI
	return TRUE;
#else
	return FALSE;
#endif
}

#define AUTH_GSS_ERROR      -1
#define AUTH_GSS_COMPLETE    1
#define AUTH_GSS_CONTINUE    0

typedef enum {
	SOUP_NEGOTIATE_NEW,
	SOUP_NEGOTIATE_RECEIVED_CHALLENGE, /* received initial negotiate header */
	SOUP_NEGOTIATE_SENT_RESPONSE,      /* sent response to server */
	SOUP_NEGOTIATE_FAILED
} SoupNegotiateState;

typedef struct {
	gboolean initialized;
	gchar *response_header;

#ifdef LIBSOUP_HAVE_GSSAPI
	gss_ctx_id_t context;
	gss_name_t   server_name;
#endif

	SoupNegotiateState state;
} SoupNegotiateConnectionState;

typedef struct {
	gboolean is_authenticated;
} SoupAuthNegotiatePrivate;

/**
 * SOUP_TYPE_AUTH_NEGOTIATE:
 *
 * A #GType corresponding to HTTP-based GSS-Negotiate authentication.
 * #SoupSessions do not support this type by default; if you want to
 * enable support for it, call soup_session_add_feature_by_type(),
 * passing %SOUP_TYPE_AUTH_NEGOTIATE.
 *
 * This auth type will only work if libsoup was compiled with GSSAPI
 * support; you can check soup_auth_negotiate_supported() to see if it
 * was.
 *
 * Since: 2.54
 */
G_DEFINE_TYPE_WITH_PRIVATE (SoupAuthNegotiate, soup_auth_negotiate, SOUP_TYPE_CONNECTION_AUTH)

#ifdef LIBSOUP_HAVE_GSSAPI
static gboolean check_auth_trusted_uri (SoupConnectionAuth *auth,
					SoupMessage *msg);
static gboolean soup_gss_build_response (SoupNegotiateConnectionState *conn,
					 SoupAuth *auth, GError **err);
static void soup_gss_client_cleanup (SoupNegotiateConnectionState *conn);
static gboolean soup_gss_client_init (SoupNegotiateConnectionState *conn,
				      const char *host, GError **err);
static int soup_gss_client_step (SoupNegotiateConnectionState *conn,
				 const char *host, GError **err);

static GSList *trusted_uris;
static GSList *blacklisted_uris;

static void parse_uris_from_env_variable (const gchar *env_variable, GSList **list);

static void check_server_response (SoupMessage *msg, gpointer auth);

static const char spnego_OID[] = "\x2b\x06\x01\x05\x05\x02";
static const gss_OID_desc gss_mech_spnego = { sizeof (spnego_OID) - 1, (void *) &spnego_OID };

static gpointer
soup_auth_negotiate_create_connection_state (SoupConnectionAuth *auth)
{
	SoupNegotiateConnectionState *conn;

	conn = g_slice_new0 (SoupNegotiateConnectionState);
	conn->state = SOUP_NEGOTIATE_NEW;

	return conn;
}

static void
free_connection_state_data (SoupNegotiateConnectionState *conn)
{
	soup_gss_client_cleanup (conn);
	g_free (conn->response_header);
}

static void
soup_auth_negotiate_free_connection_state (SoupConnectionAuth *auth,
					   gpointer state)
{
	SoupNegotiateConnectionState *conn = state;

	free_connection_state_data (conn);

	g_slice_free (SoupNegotiateConnectionState, conn);
}

static GSList *
soup_auth_negotiate_get_protection_space (SoupAuth *auth, SoupURI *source_uri)
{
	char *space, *p;

	space = g_strdup (source_uri->path);

	/* Strip filename component */
	p = strrchr (space, '/');
	if (p && p == space && p[1])
		p[1] = '\0';
	else if (p && p[1])
		*p = '\0';

	return g_slist_prepend (NULL, space);
}

static void
soup_auth_negotiate_authenticate (SoupAuth *auth, const char *username,
				  const char *password)
{
	SoupAuthNegotiate *negotiate = SOUP_AUTH_NEGOTIATE (auth);
	SoupAuthNegotiatePrivate *priv = soup_auth_negotiate_get_instance_private (negotiate);

	/* It is not possible to authenticate with username and password. */
	priv->is_authenticated = FALSE;
}

static gboolean
soup_auth_negotiate_is_authenticated (SoupAuth *auth)
{
	SoupAuthNegotiate *negotiate = SOUP_AUTH_NEGOTIATE (auth);
	SoupAuthNegotiatePrivate *priv = soup_auth_negotiate_get_instance_private (negotiate);

	/* We are authenticated just in case we received the GSS_S_COMPLETE. */
	return priv->is_authenticated;
}

static gboolean
soup_auth_negotiate_can_authenticate (SoupAuth *auth)
{
	return FALSE;
}

static char *
soup_auth_negotiate_get_connection_authorization (SoupConnectionAuth *auth,
						  SoupMessage *msg,
						  gpointer state)
{
	SoupNegotiateConnectionState *conn = state;
	char *header = NULL;

	if (conn->state == SOUP_NEGOTIATE_NEW) {
		GError *err = NULL;

		if (!check_auth_trusted_uri (auth, msg)) {
			conn->state = SOUP_NEGOTIATE_FAILED;
			return NULL;
		}

		if (!soup_gss_build_response (conn, SOUP_AUTH (auth), &err)) {
			/* FIXME: report further upward via
			 * soup_message_get_error_message  */
			if (conn->initialized)
				g_warning ("gssapi step failed: %s", err->message);
			else
				g_warning ("gssapi init failed: %s", err->message);
			conn->state = SOUP_NEGOTIATE_FAILED;
			g_clear_error (&err);

			return NULL;
		}
	}

	if (conn->response_header) {
		header = conn->response_header;
		conn->response_header = NULL;
		conn->state = SOUP_NEGOTIATE_SENT_RESPONSE;
	}

	return header;
}

static gboolean
soup_auth_negotiate_is_connection_ready (SoupConnectionAuth *auth,
					 SoupMessage        *msg,
					 gpointer            state)
{
	SoupNegotiateConnectionState *conn = state;

	return conn->state != SOUP_NEGOTIATE_FAILED;
}
#endif /* LIBSOUP_HAVE_GSSAPI */

static gboolean
soup_auth_negotiate_update_connection (SoupConnectionAuth *auth, SoupMessage *msg,
				       const char *header, gpointer state)
{
#ifdef LIBSOUP_HAVE_GSSAPI
	gboolean success = TRUE;
	SoupNegotiateConnectionState *conn = state;
	GError *err = NULL;

	if (!check_auth_trusted_uri (auth, msg)) {
		conn->state = SOUP_NEGOTIATE_FAILED;
		goto out;
	}

	/* Found negotiate header with no token, start negotiate */
	if (strcmp (header, "Negotiate") == 0) {
		/* If we were already negotiating and we get a 401
		 * with no token, start again. */
		if (conn->state == SOUP_NEGOTIATE_SENT_RESPONSE) {
			free_connection_state_data (conn);
			conn->initialized = FALSE;
		}

		conn->state = SOUP_NEGOTIATE_RECEIVED_CHALLENGE;
		if (soup_gss_build_response (conn, SOUP_AUTH (auth), &err)) {
			/* Connect the signal only once per message */
			if (!g_object_get_data (G_OBJECT (msg), "negotiate-got-headers-connected")) {
				/* Wait for the 2xx response to verify server response */
				g_signal_connect_data (msg,
						       "got_headers",
						       G_CALLBACK (check_server_response),
						       g_object_ref (auth),
						       (GClosureNotify) g_object_unref,
						       0);
				/* Mark that the signal was connected */
				g_object_set_data (G_OBJECT (msg),
						   "negotiate-got-headers-connected",
						   GINT_TO_POINTER (1));
			}
			goto out;
		} else {
			/* FIXME: report further upward via
			 * soup_message_get_error_message  */
			if (conn->initialized)
				g_warning ("gssapi step failed: %s", err->message);
			else
				g_warning ("gssapi init failed: %s", err->message);
			success = FALSE;
		}
	} else if (!strncmp (header, "Negotiate ", 10)) {
		if (soup_gss_client_step (conn, header + 10, &err) == AUTH_GSS_CONTINUE) {
			conn->state = SOUP_NEGOTIATE_RECEIVED_CHALLENGE;
			goto out;
		}
	}

	conn->state = SOUP_NEGOTIATE_FAILED;
 out:
	g_clear_error (&err);
	return success;
#else
	return FALSE;
#endif /* LIBSOUP_HAVE_GSSAPI */
}

static void
soup_auth_negotiate_init (SoupAuthNegotiate *negotiate)
{
	g_object_set (G_OBJECT (negotiate), SOUP_AUTH_REALM, "", NULL);
}

static void
soup_auth_negotiate_class_init (SoupAuthNegotiateClass *auth_negotiate_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (auth_negotiate_class);
	SoupConnectionAuthClass *conn_auth_class =
			SOUP_CONNECTION_AUTH_CLASS (auth_negotiate_class);

	auth_class->scheme_name = "Negotiate";
	auth_class->strength = 0;

	conn_auth_class->update_connection = soup_auth_negotiate_update_connection;
#ifdef LIBSOUP_HAVE_GSSAPI
	auth_class->strength = 7;

	conn_auth_class->create_connection_state = soup_auth_negotiate_create_connection_state;
	conn_auth_class->free_connection_state = soup_auth_negotiate_free_connection_state;
	conn_auth_class->get_connection_authorization = soup_auth_negotiate_get_connection_authorization;
	conn_auth_class->is_connection_ready = soup_auth_negotiate_is_connection_ready;

	auth_class->get_protection_space = soup_auth_negotiate_get_protection_space;
	auth_class->authenticate = soup_auth_negotiate_authenticate;
	auth_class->is_authenticated = soup_auth_negotiate_is_authenticated;
	auth_class->can_authenticate = soup_auth_negotiate_can_authenticate;

	parse_uris_from_env_variable ("SOUP_GSSAPI_TRUSTED_URIS", &trusted_uris);
	parse_uris_from_env_variable ("SOUP_GSSAPI_BLACKLISTED_URIS", &blacklisted_uris);
#endif /* LIBSOUP_HAVE_GSSAPI */
}

#ifdef LIBSOUP_HAVE_GSSAPI
static void
check_server_response (SoupMessage *msg, gpointer auth)
{
	gint ret;
	const char *auth_headers;
	GError *err = NULL;
	SoupAuthNegotiate *negotiate = auth;
	SoupAuthNegotiatePrivate *priv = soup_auth_negotiate_get_instance_private (negotiate);
	SoupNegotiateConnectionState *conn;

	conn = soup_connection_auth_get_connection_state_for_message (SOUP_CONNECTION_AUTH (auth), msg);
	if (!conn)
		return;

	if (auth != soup_message_get_auth (msg))
		return;

	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED)
		return;

	/* FIXME: need to check for proxy-auth too */
	auth_headers = soup_message_headers_get_one (msg->response_headers,
						     "WWW-Authenticate");
	if (!auth_headers || g_ascii_strncasecmp (auth_headers, "Negotiate ", 10) != 0) {
		g_warning ("Failed to parse auth header");
		conn->state = SOUP_NEGOTIATE_FAILED;
		goto out;
	}

	ret = soup_gss_client_step (conn, auth_headers + 10, &err);

	switch (ret) {
	case AUTH_GSS_COMPLETE:
		priv->is_authenticated = TRUE;
		break;
	case AUTH_GSS_CONTINUE:
		conn->state = SOUP_NEGOTIATE_RECEIVED_CHALLENGE;
		break;
	case AUTH_GSS_ERROR:
		if (err)
			g_warning ("%s", err->message);
		/* Unfortunately, so many programs (curl, Firefox, ..) ignore
		 * the return token that is included in the response, so it is
		 * possible that there are servers that send back broken stuff.
		 * Try to behave in the right way (pass the token to
		 * gss_init_sec_context()), show a warning, but don't fail
		 * if the server returned 200. */
		if (msg->status_code == SOUP_STATUS_OK)
			priv->is_authenticated = TRUE;
		else
			conn->state = SOUP_NEGOTIATE_FAILED;
		break;
	default:
		conn->state = SOUP_NEGOTIATE_FAILED;
	}
 out:
	g_clear_error (&err);
}

/* Check if scheme://host:port from message matches the given URI. */
static gint
match_base_uri (SoupURI *list_uri, SoupURI *msg_uri)
{
	if (msg_uri->scheme != list_uri->scheme)
		return 1;

	if (list_uri->port && (msg_uri->port != list_uri->port))
		return 1;

	if (list_uri->host)
		return !soup_host_matches_host (msg_uri->host, list_uri->host);

	return 0;
}

/* Parses a comma separated list of URIS from the environment. */
static void
parse_uris_from_env_variable (const gchar *env_variable, GSList **list)
{
	gchar **uris = NULL;
	const gchar *env;
	gint i;
	guint length;

	/* Initialize the list */
	*list = NULL;

	if (!(env = g_getenv (env_variable)))
		return;

	if (!(uris = g_strsplit (env, ",", -1)))
		return;

	length = g_strv_length (uris);
	for (i = 0; i < length; i++) {
		SoupURI *uri;

		/* If the supplied URI is valid, append it to the list */
		if ((uri = soup_uri_new (uris[i])))
			*list = g_slist_prepend (*list, uri);
	}

	g_strfreev (uris);
}

static gboolean
check_auth_trusted_uri (SoupConnectionAuth *auth, SoupMessage *msg)
{
	SoupURI *msg_uri;
	GSList *matched = NULL;

	g_return_val_if_fail (auth != NULL, FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);

	msg_uri = soup_message_get_uri (msg);

	/* First check if the URI is not on blacklist */
	if (blacklisted_uris &&
	    g_slist_find_custom (blacklisted_uris, msg_uri, (GCompareFunc) match_base_uri))
		return FALSE;

	/* If no trusted URIs are set, we allow all HTTPS URIs */
	if (!trusted_uris)
		return soup_uri_is_https (msg_uri, NULL);

	matched = g_slist_find_custom (trusted_uris,
				       msg_uri,
				       (GCompareFunc) match_base_uri);

	return matched ? TRUE : FALSE;
}

static gboolean
soup_gss_build_response (SoupNegotiateConnectionState *conn, SoupAuth *auth, GError **err)
{
	if (!conn->initialized)
		if (!soup_gss_client_init (conn, soup_auth_get_host (auth), err))
			return FALSE;

	if (soup_gss_client_step (conn, "", err) != AUTH_GSS_CONTINUE)
		return FALSE;

	return TRUE;
}

static void
soup_gss_error (OM_uint32 err_maj, OM_uint32 err_min, GError **err)
{
	OM_uint32 maj_stat, min_stat, msg_ctx = 0;
	gss_buffer_desc status;
	gchar *buf_maj = NULL, *buf_min = NULL;

	do {
		maj_stat = gss_display_status (&min_stat,
					       err_maj,
					       GSS_C_GSS_CODE,
					       (gss_OID) &gss_mech_spnego,
					       &msg_ctx,
					       &status);
		if (GSS_ERROR (maj_stat))
			break;

		buf_maj = g_strdup ((gchar *) status.value);
		gss_release_buffer (&min_stat, &status);

		maj_stat = gss_display_status (&min_stat,
					       err_min,
					       GSS_C_MECH_CODE,
					       GSS_C_NULL_OID,
					       &msg_ctx,
					       &status);
		if (!GSS_ERROR (maj_stat)) {
			buf_min = g_strdup ((gchar *) status.value);
			gss_release_buffer (&min_stat, &status);
		}

		if (err && *err == NULL) {
			g_set_error (err,
				     SOUP_HTTP_ERROR,
				     SOUP_STATUS_UNAUTHORIZED,
				     "%s: %s",
				     buf_maj,
				     buf_min ? buf_min : "");
		}
		g_free (buf_maj);
		g_free (buf_min);
		buf_min = buf_maj = NULL;
	} while (!GSS_ERROR (maj_stat) && msg_ctx != 0);
}

static gboolean
soup_gss_client_init (SoupNegotiateConnectionState *conn, const gchar *host, GError **err)
{
	OM_uint32 maj_stat, min_stat;
	gchar *service = NULL;
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	gboolean ret = FALSE;
	gchar *h;

	conn->server_name = GSS_C_NO_NAME;
	conn->context = GSS_C_NO_CONTEXT;

	h = g_ascii_strdown (host, -1);
	service = g_strconcat ("HTTP@", h, NULL);
	token.length = strlen (service);
	token.value = (gchar *) service;

	maj_stat = gss_import_name (&min_stat,
				    &token,
				    (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				    &conn->server_name);

	if (GSS_ERROR (maj_stat)) {
		soup_gss_error (maj_stat, min_stat, err);
		ret = FALSE;
		goto out;
	}

	conn->initialized = TRUE;
	ret = TRUE;
out:
	g_free (h);
	g_free (service);
	return ret;
}

static gint
soup_gss_client_step (SoupNegotiateConnectionState *conn, const gchar *challenge, GError **err)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc in = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc out = GSS_C_EMPTY_BUFFER;
	gint ret = AUTH_GSS_CONTINUE;

	g_clear_pointer (&conn->response_header, g_free);

	if (challenge && *challenge) {
		size_t len;
		in.value = g_base64_decode (challenge, &len);
		in.length = len;
	}

	maj_stat = gss_init_sec_context (&min_stat,
					 GSS_C_NO_CREDENTIAL,
					 &conn->context,
					 conn->server_name,
					 (gss_OID) &gss_mech_spnego,
					 GSS_C_MUTUAL_FLAG,
					 GSS_C_INDEFINITE,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 &in,
					 NULL,
					 &out,
					 NULL,
					 NULL);

	if ((maj_stat != GSS_S_COMPLETE) && (maj_stat != GSS_S_CONTINUE_NEEDED)) {
		soup_gss_error (maj_stat, min_stat, err);
		ret = AUTH_GSS_ERROR;
		goto out;
	}

	ret = (maj_stat == GSS_S_COMPLETE) ? AUTH_GSS_COMPLETE : AUTH_GSS_CONTINUE;
	if (out.length) {
		gchar *response = g_base64_encode ((const guchar *) out.value, out.length);
		conn->response_header = g_strconcat ("Negotiate ", response, NULL);
		g_free (response);
		maj_stat = gss_release_buffer (&min_stat, &out);
	}

out:
	if (out.value)
		gss_release_buffer (&min_stat, &out);
	if (in.value)
		g_free (in.value);
	return ret;
}

static void
soup_gss_client_cleanup (SoupNegotiateConnectionState *conn)
{
	OM_uint32 maj_stat, min_stat;

	gss_release_name (&min_stat, &conn->server_name);
	maj_stat = gss_delete_sec_context (&min_stat, &conn->context, GSS_C_NO_BUFFER);
	if (maj_stat != GSS_S_COMPLETE)
		maj_stat = gss_delete_sec_context (&min_stat, &conn->context, GSS_C_NO_BUFFER);
}
#endif /* LIBSOUP_HAVE_GSSAPI */
