/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-domain-basic.c: HTTP Basic Authentication (server-side)
 *
 * Copyright (C) 2007 Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-auth-domain-basic.h"
#include "soup-marshal.h"
#include "soup-message.h"

G_DEFINE_TYPE (SoupAuthDomainBasic, soup_auth_domain_basic, SOUP_TYPE_AUTH_DOMAIN)

enum {
	AUTHENTICATE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static char *accepts   (SoupAuthDomain *domain,
			SoupMessage    *msg,
			const char     *header);
static char *challenge (SoupAuthDomain *domain,
			SoupMessage    *msg);

static void
soup_auth_domain_basic_init (SoupAuthDomainBasic *basic)
{
}

static void
soup_auth_domain_basic_class_init (SoupAuthDomainBasicClass *basic_class)
{
	SoupAuthDomainClass *auth_domain_class =
		SOUP_AUTH_DOMAIN_CLASS (basic_class);
	GObjectClass *object_class = G_OBJECT_CLASS (basic_class);

	auth_domain_class->accepts   = accepts;
	auth_domain_class->challenge = challenge;

	/**
	 * SoupAuthDomainBasic::authenticate:
	 * @basic: the auth domain
	 * @msg: the message being authenticated
	 * @username: the provided username
	 * @password: the provided password
	 *
	 * Emitted when the auth domain needs to authenticate a
	 * username/password combination.
	 *
	 * Handlers for this signal should consider declaring the
	 * @password argument as a #gpointer rather than as a
	 * const char *, so that if the program crashes while
	 * handling the signal, bug-buddy won't capture the password
	 * in the stack trace.
	 *
	 * Return value: whether or not to accept the password
	 **/
	/* FIXME: what if there are multiple signal handlers? */
	signals[AUTHENTICATE] =
		g_signal_new ("authenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupAuthDomainBasicClass, authenticate),
			      NULL, NULL,
			      soup_marshal_BOOLEAN__OBJECT_STRING_STRING,
			      G_TYPE_BOOLEAN, 3,
			      SOUP_TYPE_MESSAGE,
			      G_TYPE_STRING,
			      G_TYPE_STRING);
}

SoupAuthDomain *
soup_auth_domain_basic_new (const char *optname1, ...)
{
	SoupAuthDomain *domain;
	va_list ap;

	va_start (ap, optname1);
	domain = (SoupAuthDomain *)g_object_new_valist (SOUP_TYPE_AUTH_DOMAIN_BASIC,
							optname1, ap);
	va_end (ap);

	g_return_val_if_fail (soup_auth_domain_get_realm (domain) != NULL, NULL);

	return domain;
}

static void
pw_free (char *pw)
{
	memset (pw, 0, strlen (pw));
	g_free (pw);
}

static char *
accepts (SoupAuthDomain *domain, SoupMessage *msg, const char *header)
{
	SoupAuthDomainBasic *basic = (SoupAuthDomainBasic *)domain;
	char *decoded, *colon;
	gsize len, plen;
	char *username, *password;
	gboolean ok = FALSE;

	if (strncmp (header, "Basic ", 6) != 0)
		return NULL;

	decoded = (char *)g_base64_decode (header + 6, &len);
	if (!decoded)
		return NULL;

	colon = memchr (decoded, ':', len);
	if (!colon) {
		pw_free (decoded);
		return NULL;
	}
	*colon = '\0';
	plen = len - (colon - decoded) - 1;

	password = g_strndup (colon + 1, plen);
	memset (colon + 1, 0, plen);
	username = decoded;

	g_signal_emit (basic, signals[AUTHENTICATE], 0,
		       msg, username, password, &ok);
	pw_free (password);

	if (ok)
		return username;
	else {
		g_free (username);
		return NULL;
	}
}

static char *
challenge (SoupAuthDomain *domain, SoupMessage *msg)
{
	/* FIXME: if realm has '"'s or '\'s in it, need to escape them */
	return g_strdup_printf ("Basic realm=\"%s\"",
				soup_auth_domain_get_realm (domain));
}
