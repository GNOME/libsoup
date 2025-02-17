/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
#include "soup-message-headers-private.h"
#include "soup-misc.h"
#include "soup-uri-utils-private.h"

/**
 * soup_auth_negotiate_supported:
 *
 * Indicates whether libsoup was built with GSSAPI support.
 *
 * If this is %FALSE, %SOUP_TYPE_AUTH_NEGOTIATE will still be defined and can
 * still be added to a [class@Session], but libsoup will never attempt to
 * actually use this auth type.
 *
 * Returns: %TRUE if supported otherwise %FALSE
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

#define AUTH_GSS_ERROR      (-1)
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


struct _SoupAuthNegotiate {
	SoupConnectionAuth parent;
};

typedef struct {
	gboolean is_authenticated;
} SoupAuthNegotiatePrivate;

/**
 * SoupAuthNegotiate:
 *
 * HTTP-based GSS-Negotiate authentication, as defined by
 * [RFC 4559](https://datatracker.ietf.org/doc/html/rfc4559).
 *
 * [class@Session]s do not support this type by default; if you want to
 * enable support for it, call [method@Session.add_feature_by_type],
 * passing %SOUP_TYPE_AUTH_NEGOTIATE.
 *
 * This auth type will only work if libsoup was compiled with GSSAPI
 * support; you can check [func@AuthNegotiate.supported] to see if it
 * was.
 */
G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupAuthNegotiate, soup_auth_negotiate, SOUP_TYPE_CONNECTION_AUTH)

#ifdef LIBSOUP_HAVE_GSSAPI
static gboolean check_auth_trusted_uri (SoupConnectionAuth *auth,
					SoupMessage *msg);
static gboolean soup_gss_build_response (SoupNegotiateConnectionState *conn,
					 SoupAuth *auth, char **error_message);
static void soup_gss_client_cleanup (SoupNegotiateConnectionState *conn);
static gboolean soup_gss_client_init (SoupNegotiateConnectionState *conn,
				      const char *authority, char **error_message);
static int soup_gss_client_step (SoupNegotiateConnectionState *conn,
				 const char *host, char **error_message);

static GSList *trusted_uris;
static GSList *blocklisted_uris;

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
soup_auth_negotiate_get_protection_space (SoupAuth *auth, GUri *source_uri)
{
	char *space, *p;

	space = g_strdup (g_uri_get_path (source_uri));

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
		char *error_message = NULL;

		if (!check_auth_trusted_uri (auth, msg)) {
			conn->state = SOUP_NEGOTIATE_FAILED;
			return NULL;
		}

		if (!soup_gss_build_response (conn, SOUP_AUTH (auth), &error_message)) {
			g_assert (error_message); /* Silence scan-build */
			/* FIXME: report further upward via
			 * soup_message_get_error_message  */
			if (conn->initialized)
				g_warning ("gssapi step failed: %s", error_message);
			else
				g_warning ("gssapi init failed: %s", error_message);
			conn->state = SOUP_NEGOTIATE_FAILED;
			g_clear_pointer (&error_message, g_free);

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
	char *error_message = NULL;

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
		if (soup_gss_build_response (conn, SOUP_AUTH (auth), &error_message)) {
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
                        g_assert (error_message); /* Silence scan-build */
			/* FIXME: report further upward via
			 * soup_message_get_error_message  */
			if (conn->initialized)
				g_warning ("gssapi step failed: %s", error_message);
			else
				g_warning ("gssapi init failed: %s", error_message);
			success = FALSE;
		}
	} else if (!strncmp (header, "Negotiate ", 10)) {
		if (soup_gss_client_step (conn, header + 10, &error_message) == AUTH_GSS_CONTINUE) {
			conn->state = SOUP_NEGOTIATE_RECEIVED_CHALLENGE;
			goto out;
		}
	}

	conn->state = SOUP_NEGOTIATE_FAILED;
 out:
	g_clear_pointer (&error_message, g_free);
	return success;
#else
	return FALSE;
#endif /* LIBSOUP_HAVE_GSSAPI */
}

static void
soup_auth_negotiate_init (SoupAuthNegotiate *negotiate)
{
	g_object_set (G_OBJECT (negotiate), "realm", "", NULL);
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
	parse_uris_from_env_variable ("SOUP_GSSAPI_BLOCKLISTED_URIS", &blocklisted_uris);
#endif /* LIBSOUP_HAVE_GSSAPI */
}

#ifdef LIBSOUP_HAVE_GSSAPI
static void
check_server_response (SoupMessage *msg, gpointer auth)
{
	gint ret;
	const char *auth_headers;
	char *error_message = NULL;
	SoupAuthNegotiate *negotiate = auth;
	SoupAuthNegotiatePrivate *priv = soup_auth_negotiate_get_instance_private (negotiate);
	SoupNegotiateConnectionState *conn;

	conn = soup_connection_auth_get_connection_state_for_message (SOUP_CONNECTION_AUTH (auth), msg);
	if (!conn)
		return;

	if (auth != soup_message_get_auth (msg))
		return;

	if (soup_message_get_status (msg) == SOUP_STATUS_UNAUTHORIZED)
		return;

	/* FIXME: need to check for proxy-auth too */
	auth_headers = soup_message_headers_get_one_common (soup_message_get_response_headers (msg),
                                                            SOUP_HEADER_WWW_AUTHENTICATE);
	if (!auth_headers || g_ascii_strncasecmp (auth_headers, "Negotiate ", 10) != 0) {
		if (soup_message_get_status (msg) == SOUP_STATUS_OK) {
			/* The server *may* supply final authentication data to
			 * the client, but doesn't have to. We are not
			 * authenticating the server, so just ignore missing
			 * auth data. In practice, this is required for web
			 * compat.
			 */
		        priv->is_authenticated = TRUE;
		        return;
		}

		g_warning ("Server bug: missing or invalid WWW-Authenticate header: %s", auth_headers);
		conn->state = SOUP_NEGOTIATE_FAILED;
		return;
	}

	ret = soup_gss_client_step (conn, auth_headers + 10, &error_message);

	switch (ret) {
	case AUTH_GSS_COMPLETE:
		priv->is_authenticated = TRUE;
		break;
	case AUTH_GSS_CONTINUE:
		conn->state = SOUP_NEGOTIATE_RECEIVED_CHALLENGE;
		break;
	case AUTH_GSS_ERROR:
		if (error_message)
			g_warning ("%s", error_message);

		/* Unfortunately, so many programs (curl, Firefox, ..) ignore
		 * the return token that is included in the response, so it is
		 * possible that there are servers that send back broken stuff.
		 * Try to behave in the right way (pass the token to
		 * gss_init_sec_context()), show a warning, but don't fail
		 * if the server returned 200. */
		if (soup_message_get_status (msg) == SOUP_STATUS_OK)
			priv->is_authenticated = TRUE;
		else
			conn->state = SOUP_NEGOTIATE_FAILED;
		break;
	default:
		conn->state = SOUP_NEGOTIATE_FAILED;
	}

	g_clear_pointer (&error_message, g_free);
}

/* Check if scheme://host:port from message matches the given URI. */
static gint
match_base_uri (GUri *list_uri, GUri *msg_uri)
{
        if (g_strcmp0 (g_uri_get_scheme (list_uri), g_uri_get_scheme (msg_uri)) != 0)
                return 1;

        if (g_uri_get_port (list_uri) != -1 && g_uri_get_port (list_uri) != g_uri_get_port (msg_uri))
                return 1;

        if (g_uri_get_host (list_uri))
                return !soup_host_matches_host (g_uri_get_host (msg_uri), g_uri_get_host (list_uri));

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
		GUri *uri;

		/* If the supplied URI is valid, append it to the list */
		if ((uri = g_uri_parse (uris[i], SOUP_HTTP_URI_FLAGS, NULL)))
			*list = g_slist_prepend (*list, uri);
	}

	g_strfreev (uris);
}

static gboolean
check_auth_trusted_uri (SoupConnectionAuth *auth, SoupMessage *msg)
{
	GUri *msg_uri;
	GSList *matched = NULL;

	g_return_val_if_fail (auth != NULL, FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);

	msg_uri = soup_message_get_uri (msg);

	/* First check if the URI is not on blocklist */
	if (blocklisted_uris &&
	    g_slist_find_custom (blocklisted_uris, msg_uri, (GCompareFunc) match_base_uri))
		return FALSE;

	/* If no trusted URIs are set, we allow all HTTPS URIs */
	if (!trusted_uris)
		return soup_uri_is_https (msg_uri);

	matched = g_slist_find_custom (trusted_uris,
				       msg_uri,
				       (GCompareFunc) match_base_uri);

	return matched ? TRUE : FALSE;
}

static gboolean
soup_gss_build_response (SoupNegotiateConnectionState *conn, SoupAuth *auth, char **error_message)
{
	if (!conn->initialized)
		if (!soup_gss_client_init (conn, soup_auth_get_authority (auth), error_message))
			return FALSE;

	if (soup_gss_client_step (conn, "", error_message) != AUTH_GSS_CONTINUE)
		return FALSE;

	return TRUE;
}

static void
soup_gss_error (OM_uint32 err_maj, OM_uint32 err_min, char **error_message)
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

		if (error_message && *error_message == NULL) {
			*error_message = g_strdup_printf ("%s: %s", buf_maj,
							  buf_min ? buf_min : "");
		}

		g_free (buf_maj);
		g_free (buf_min);
		buf_min = buf_maj = NULL;
	} while (!GSS_ERROR (maj_stat) && msg_ctx != 0);
}

static gboolean
soup_gss_client_init (SoupNegotiateConnectionState *conn, const gchar *authority, char **error_message)
{
	OM_uint32 maj_stat, min_stat;
	gchar *service = NULL;
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	gboolean ret = FALSE;
	char *host;
	const char *p;

	conn->server_name = GSS_C_NO_NAME;
	conn->context = GSS_C_NO_CONTEXT;

	p = g_strrstr (authority, ":");
	host = g_ascii_strdown (authority, p ? strlen (authority) - strlen (p) : -1);
	service = g_strconcat ("HTTP@", host, NULL);
	token.length = strlen (service);
	token.value = (gchar *) service;

	maj_stat = gss_import_name (&min_stat,
				    &token,
				    (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				    &conn->server_name);

	if (GSS_ERROR (maj_stat)) {
		soup_gss_error (maj_stat, min_stat, error_message);
		ret = FALSE;
		goto out;
	}

	conn->initialized = TRUE;
	ret = TRUE;
out:
	g_free (host);
	g_free (service);
	return ret;
}

static gint
soup_gss_client_step (SoupNegotiateConnectionState *conn, const gchar *challenge, char **error_message)
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
					 0,
					 GSS_C_INDEFINITE,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 &in,
					 NULL,
					 &out,
					 NULL,
					 NULL);

	if ((maj_stat != GSS_S_COMPLETE) && (maj_stat != GSS_S_CONTINUE_NEEDED)) {
		soup_gss_error (maj_stat, min_stat, error_message);
		ret = AUTH_GSS_ERROR;
		goto out;
	}

	ret = (maj_stat == GSS_S_COMPLETE) ? AUTH_GSS_COMPLETE : AUTH_GSS_CONTINUE;
	if (out.length) {
		gchar *response = g_base64_encode ((const guchar *) out.value, out.length);
		conn->response_header = g_strconcat ("Negotiate ", response, NULL);
		g_free (response);
		gss_release_buffer (&min_stat, &out);
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
		gss_delete_sec_context (&min_stat, &conn->context, GSS_C_NO_BUFFER);
}
#endif /* LIBSOUP_HAVE_GSSAPI */
