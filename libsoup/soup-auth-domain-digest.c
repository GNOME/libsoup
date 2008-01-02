/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-domain-digest.c: HTTP Digest Authentication (server-side)
 *
 * Copyright (C) 2007 Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "soup-auth-domain-digest.h"
#include "soup-auth-digest.h"
#include "soup-headers.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-uri.h"

G_DEFINE_TYPE (SoupAuthDomainDigest, soup_auth_domain_digest, SOUP_TYPE_AUTH_DOMAIN)

enum {
	GET_AUTH_INFO,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static char *accepts   (SoupAuthDomain *domain,
			SoupMessage    *msg,
			const char     *header);
static char *challenge (SoupAuthDomain *domain,
			SoupMessage    *msg);

static void
soup_auth_domain_digest_init (SoupAuthDomainDigest *digest)
{
}

static void
soup_auth_domain_digest_class_init (SoupAuthDomainDigestClass *digest_class)
{
	SoupAuthDomainClass *auth_domain_class =
		SOUP_AUTH_DOMAIN_CLASS (digest_class);
	GObjectClass *object_class = G_OBJECT_CLASS (digest_class);

	auth_domain_class->accepts   = accepts;
	auth_domain_class->challenge = challenge;

	/**
	 * SoupAuthDomainDigest::get_auth_info:
	 * @digest: the auth domain
	 * @msg: the message being authenticated
	 * @username: the provided username
	 * @hex_urp: on return, the hexified hash of the
	 * user:realm:password string for @username.
	 *
	 * Emitted when the auth domain needs to authenticate a user.
	 * @username is the username. If the handler recognizes that
	 * user, it should set @hex_urp accordingly, and return %TRUE.
	 * Otherwise it should return %FALSE.
	 *
	 * If you have a plaintext password database, you can use
	 * soup_auth_digest_domain_compute_hex_urp() to generate the
	 * hex_urp string from the username, realm, and plaintext
	 * password. (If you have neither a plaintext password nor a
	 * hex_urp, it is impossible to use Digest auth.)
	 *
	 * Return value: whether or not @username is known.
	 **/
	/* FIXME: what if there are multiple signal handlers? */
	signals[GET_AUTH_INFO] =
		g_signal_new ("get_auth_info",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupAuthDomainDigestClass, get_auth_info),
			      NULL, NULL,
			      soup_marshal_BOOLEAN__OBJECT_STRING_POINTER,
			      G_TYPE_BOOLEAN, 3,
			      SOUP_TYPE_MESSAGE,
			      G_TYPE_STRING,
			      G_TYPE_POINTER);
}

SoupAuthDomain *
soup_auth_domain_digest_new (const char *optname1, ...)
{
	SoupAuthDomain *domain;
	va_list ap;

	va_start (ap, optname1);
	domain = (SoupAuthDomain *)g_object_new_valist (SOUP_TYPE_AUTH_DOMAIN_DIGEST,
							optname1, ap);
	va_end (ap);

	g_return_val_if_fail (soup_auth_domain_get_realm (domain) != NULL, NULL);

	return domain;
}

static char *
accepts (SoupAuthDomain *domain, SoupMessage *msg, const char *header)
{
	SoupAuthDomainDigest *digest = (SoupAuthDomainDigest *)domain;
	GHashTable *params;
	const char *uri, *qop, *realm, *username;
	const char *nonce, *nc, *cnonce, *response;
	char hex_a1[33], hex_urp[33], computed_response[33], *ret_user;
	int nonce_count;
	SoupURI *dig_uri, *req_uri;
	gboolean accept = FALSE, ok = FALSE;

	if (strncmp (header, "Digest ", 7) != 0)
		return NULL;

	params = soup_header_parse_param_list (header + 7);
	if (!params)
		return NULL;

	/* Check uri */
	uri = g_hash_table_lookup (params, "uri");
	if (!uri)
		goto DONE;

	req_uri = soup_message_get_uri (msg);
	dig_uri = soup_uri_new (uri);
	if (dig_uri) {
		if (!soup_uri_equal (dig_uri, req_uri)) {
			soup_uri_free (dig_uri);
			goto DONE;
		}
		soup_uri_free (dig_uri);
	} else {	
		char *req_path;

		req_path = soup_uri_to_string (req_uri, TRUE);
		if (strcmp (uri, req_path) != 0) {
			g_free (req_path);
			goto DONE;
		}
		g_free (req_path);
	}

	/* Check qop; we only support "auth" for now */
	qop = g_hash_table_lookup (params, "qop");
	if (!qop || strcmp (qop, "auth") != 0)
		goto DONE;

	/* Check realm */
	realm = g_hash_table_lookup (params, "realm");
	if (!realm || strcmp (realm, soup_auth_domain_get_realm (domain)) != 0)
		goto DONE;

	username = g_hash_table_lookup (params, "username");
	if (!username)
		goto DONE;
	nonce = g_hash_table_lookup (params, "nonce");
	if (!nonce)
		goto DONE;
	nc = g_hash_table_lookup (params, "nc");
	if (!nc)
		goto DONE;
	nonce_count = atoi (nc);
	if (nonce_count <= 0)
		goto DONE;
	cnonce = g_hash_table_lookup (params, "cnonce");
	if (!cnonce)
		goto DONE;
	response = g_hash_table_lookup (params, "response");
	if (!response)
		goto DONE;

	g_signal_emit (digest, signals[GET_AUTH_INFO], 0,
		       msg, username, hex_urp, &ok);
	if (!ok)
		goto DONE;

	soup_auth_digest_compute_hex_a1 (hex_urp,
					 SOUP_AUTH_DIGEST_ALGORITHM_MD5,
					 nonce, cnonce, hex_a1);
	soup_auth_digest_compute_response (msg->method, uri, hex_a1,
					   SOUP_AUTH_DIGEST_QOP_AUTH,
					   nonce, cnonce, nonce_count,
					   computed_response);

	accept = (strcmp (response, computed_response) == 0);

 DONE:
	ret_user = accept ? g_strdup (username) : NULL;
	soup_header_free_param_list (params);
	return ret_user;
}

static char *
challenge (SoupAuthDomain *domain, SoupMessage *msg)
{
	GString *str;

	str = g_string_new ("Digest ");

	/* FIXME: escape realm */
	g_string_append_printf (str, "realm=\"%s\", ", 
				soup_auth_domain_get_realm (domain));

	g_string_append_printf (str, "nonce=\"%lu%lu\", ", 
				(unsigned long) msg,
				(unsigned long) time (0));

	g_string_append_printf (str, "qop=\"auth\", ");
	g_string_append_printf (str, "algorithm=\"MD5\"");

	return g_string_free (str, FALSE);
}

/**
 * soup_auth_domain_digest_compute_hex_urp:
 * @username: a username
 * @realm: an auth realm name
 * @password: the password for @username in @realm
 * @hex_urp: used to store the return value.
 *
 * Computes H(@username, ":", @realm, ":", @password), converts it to
 * hex digits, and returns it in @hex_urp.
 *
 * This can be used when connecting to #SoupAuthDomainDigest's
 * %get_auth_info signal; if you have a plaintext password database,
 * you can use soup_auth_domain_digest_compute_hex_urp() to create the
 * return value for that signal.
 **/
void
soup_auth_domain_digest_compute_hex_urp (const char *username,
					 const char *realm,
					 const char *password,
					 char        hex_urp[33])
{
	soup_auth_digest_compute_hex_urp (username, realm, password, hex_urp);
}
