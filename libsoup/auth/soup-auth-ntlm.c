/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-auth-ntlm.c: HTTP NTLM Authentication helper
 *
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include "soup-auth-ntlm.h"
#include "soup.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"

static void        soup_ntlm_lanmanager_hash   (const char  *password,
						guchar       hash[21]);
static void        soup_ntlm_nt_hash           (const char  *password,
						guchar       hash[21]);
static char       *soup_ntlm_request           (void);
static gboolean    soup_ntlm_parse_challenge   (const char  *challenge,
						char       **nonce,
						char       **default_domain,
						gboolean    *ntlmv2_session,
						gboolean    *negotiate_target,
						char		**target_info,
						size_t		*target_info_sz);
static char       *soup_ntlm_response          (const char  *nonce,
						const char  *user,
						guchar       nt_hash[21],
						guchar       lm_hash[21],
						const char  *host, 
						const char  *domain,
						gboolean     ntlmv2_session,
						gboolean     negotiate_target,
						const char	*target_info,
						size_t		target_info_sz);

typedef enum {
	SOUP_NTLM_NEW,
	SOUP_NTLM_SSO_FAILED,
	SOUP_NTLM_SENT_REQUEST,
	SOUP_NTLM_RECEIVED_CHALLENGE,
	SOUP_NTLM_SENT_RESPONSE,
	SOUP_NTLM_FAILED
} SoupNTLMState;

typedef struct {
	SoupNTLMState state;
	char *nonce;
	char *response_header;
	gboolean ntlmv2_session;
	gboolean negotiate_target;
	char *target_info;
	size_t target_info_sz;
} SoupNTLMConnectionState;

typedef enum {
	SOUP_NTLM_PASSWORD_NONE,
	SOUP_NTLM_PASSWORD_PROVIDED,
	SOUP_NTLM_PASSWORD_ACCEPTED,
	SOUP_NTLM_PASSWORD_REJECTED
} SoupNTLMPasswordState;

struct _SoupAuthNTLM {
	SoupConnectionAuth parent;
};

typedef struct {
	char *username, *domain;
	guchar nt_hash[21], lm_hash[21];
	SoupNTLMPasswordState password_state;

#ifdef USE_NTLM_AUTH
	/* Use Samba's 'winbind' daemon to support NTLM single-sign-on,
	 * by delegating the NTLM challenge/response protocal to a helper
	 * in ntlm_auth.
	 * http://devel.squid-cache.org/ntlm/squid_helper_protocol.html
	 * http://www.samba.org/samba/docs/man/manpages-3/winbindd.8.html
	 * http://www.samba.org/samba/docs/man/manpages-3/ntlm_auth.1.html
	 */
	gboolean sso_available;
	int fd_in;
	int fd_out;
#endif
} SoupAuthNTLMPrivate;

#ifdef USE_NTLM_AUTH
static gboolean ntlm_auth_available, ntlm_auth_debug;
static void sso_ntlm_close (SoupAuthNTLMPrivate *priv);
#endif

/**
 * SoupAuthNTLM:
 *
 * HTTP-based NTLM authentication.
 *
 * [class@Session]s do not support this type by default; if you want to
 * enable support for it, call [method@Session.add_feature_by_type],
 * passing %SOUP_TYPE_AUTH_NTLM.
 */

G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupAuthNTLM, soup_auth_ntlm, SOUP_TYPE_CONNECTION_AUTH)

static void
soup_auth_ntlm_init (SoupAuthNTLM *ntlm)
{
#ifdef USE_NTLM_AUTH
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (ntlm);
	const char *username = NULL, *slash;

	priv->sso_available = TRUE;
	priv->fd_in = -1;
	priv->fd_out = -1;

	username = getenv ("NTLMUSER");
	if (!username)
		username = g_get_user_name ();

	slash = strpbrk (username, "\\/");
	if (slash) {
		priv->username = g_strdup (slash + 1);
		priv->domain = g_strndup (username, slash - username);
	} else {
		priv->username = g_strdup (username);
		priv->domain = NULL;
	}
#endif
}

static void
soup_auth_ntlm_finalize (GObject *object)
{
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (SOUP_AUTH_NTLM (object));

	g_free (priv->username);
	g_free (priv->domain);

	memset (priv->nt_hash, 0, sizeof (priv->nt_hash));
	memset (priv->lm_hash, 0, sizeof (priv->lm_hash));

#ifdef USE_NTLM_AUTH
	sso_ntlm_close (priv);
#endif

	G_OBJECT_CLASS (soup_auth_ntlm_parent_class)->finalize (object);
}

#ifdef USE_NTLM_AUTH
static void
sso_ntlm_close (SoupAuthNTLMPrivate *priv)
{
	if (priv->fd_in != -1) {
		close (priv->fd_in);
		priv->fd_in = -1;
	}

	if (priv->fd_out != -1) {
		close (priv->fd_out);
		priv->fd_out = -1;
	}
}

static gboolean
sso_ntlm_initiate (SoupAuthNTLMPrivate *priv)
{
	char *argv[9];
	gboolean ret;

	if (!priv->sso_available)
		return FALSE;

	if (!ntlm_auth_available && !ntlm_auth_debug) {
		priv->sso_available = FALSE;
		return FALSE;
	}

	/* Return if ntlm_auth execution process exist already */
	if (priv->fd_in != -1 && priv->fd_out != -1)
		return TRUE;
	else {
		/* Clean all sso data before re-initiate */
		sso_ntlm_close (priv);
	}

	if (ntlm_auth_debug) {
		argv[0] = (char *) g_getenv ("SOUP_NTLM_AUTH_DEBUG");
		if (!*argv[0]) {
			priv->sso_available = FALSE;
			return FALSE;
		}
	} else
		argv[0] = NTLM_AUTH;
	argv[1] = "--helper-protocol";
	argv[2] = "ntlmssp-client-1";
	argv[3] = "--use-cached-creds";
	argv[4] = "--username";
	argv[5] = priv->username;
	argv[6] = priv->domain ? "--domain" : NULL;
	argv[7] = priv->domain;
	argv[8] = NULL;

	ret = g_spawn_async_with_pipes (NULL, argv, NULL,
					G_SPAWN_STDERR_TO_DEV_NULL,
					NULL, NULL,
					NULL, &priv->fd_in, &priv->fd_out,
					NULL, NULL);
	if (!ret)
		priv->sso_available = FALSE;
	return ret;
}

static char *
sso_ntlm_response (SoupAuthNTLMPrivate *priv, const char *input, SoupNTLMState conn_state)
{
	ssize_t size;
	char buf[1024];
	char *tmpbuf = buf;
	size_t	len_in = strlen (input), len_out = sizeof (buf);

	while (len_in > 0) {
		int written = write (priv->fd_in, input, len_in);
		if (written == -1) {
			if (errno == EINTR)
				continue;
			/* write failed if other errors happen */
			return NULL;
		}
		input += written;
		len_in -= written;
	}
	/* Read one line */
	while (len_out > 0) {
		size = read (priv->fd_out, tmpbuf, len_out);
		if (size == -1) {
			if (errno == EINTR)
				continue;
			return NULL;
		} else if (size == 0)
			return NULL;
		else if (tmpbuf[size - 1] == '\n') {
			tmpbuf[size - 1] = '\0';
			goto wrfinish;
		}
		tmpbuf += size;
		len_out -= size;
	}
	return NULL;

wrfinish:
	if (g_ascii_strcasecmp (buf, "PW") == 0) {
		/* Samba/winbind installed but not configured */
		return g_strdup ("PW");
	}
	if (conn_state == SOUP_NTLM_NEW &&
	    g_ascii_strncasecmp (buf, "YR ", 3) != 0) {
		/* invalid response for type 1 message */
		return NULL;
	}
	if (conn_state == SOUP_NTLM_RECEIVED_CHALLENGE &&
	    g_ascii_strncasecmp (buf, "KK ", 3) != 0 &&
	    g_ascii_strncasecmp (buf, "AF ", 3) != 0) {
		/* invalid response for type 3 message */
		return NULL;
	}

	return g_strdup_printf ("NTLM %.*s", (int)(size - 4), buf + 3);
}
#endif /* USE_NTLM_AUTH */

static gpointer
soup_auth_ntlm_create_connection_state (SoupConnectionAuth *auth)
{
	SoupNTLMConnectionState *conn;

	conn = g_slice_new0 (SoupNTLMConnectionState);
	conn->state = SOUP_NTLM_NEW;

	return conn;
}

static void
soup_auth_ntlm_free_connection_state (SoupConnectionAuth *auth,
				      gpointer state)
{
	SoupNTLMConnectionState *conn = state;

	g_free (conn->nonce);
	g_free (conn->response_header);
	g_free (conn->target_info);
	g_slice_free (SoupNTLMConnectionState, conn);
}

static gboolean
soup_auth_ntlm_update_connection (SoupConnectionAuth *auth, SoupMessage *msg,
				  const char *auth_header, gpointer state)
{
	SoupAuthNTLM *auth_ntlm = SOUP_AUTH_NTLM (auth);
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (auth_ntlm);
	SoupNTLMConnectionState *conn = state;
	gboolean success = TRUE;
	GUri *uri;
	char *authority;

	/* Note that we only return FALSE if some sort of parsing error
	 * occurs. Otherwise, the SoupAuth is still reusable (though it may
	 * no longer be _ready or _authenticated).
	 */

	if (!g_str_has_prefix (auth_header, "NTLM"))
		return FALSE;

	if (conn->state > SOUP_NTLM_SENT_REQUEST) {
		if (priv->password_state == SOUP_NTLM_PASSWORD_ACCEPTED) {
			/* We know our password is correct, so a 401
			 * means "permission denied". The code can't deal
			 * with re-authenticating correctly, so make sure
			 * we don't try.
			 */
			conn->state = SOUP_NTLM_FAILED;
			if (soup_message_is_keepalive (msg)) {
				soup_message_headers_append_common (soup_message_get_response_headers (msg),
                                                                    SOUP_HEADER_CONNECTION, "close");
			}
			return TRUE;
		}

#ifdef USE_NTLM_AUTH
		if (priv->sso_available) {
			conn->state = SOUP_NTLM_SSO_FAILED;
			priv->password_state = SOUP_NTLM_PASSWORD_NONE;
		} else {
#endif
			conn->state = SOUP_NTLM_FAILED;
			priv->password_state = SOUP_NTLM_PASSWORD_REJECTED;
#ifdef USE_NTLM_AUTH
		}
#endif
		return TRUE;
	}

	if (conn->state == SOUP_NTLM_NEW && !auth_header[4])
		return TRUE;

	if (!auth_header[4] || !auth_header[5]) {
		conn->state = SOUP_NTLM_FAILED;
		return FALSE;
	}

	if (!soup_ntlm_parse_challenge (auth_header + 5, &conn->nonce,
					priv->domain ? NULL : &priv->domain,
					&conn->ntlmv2_session, &conn->negotiate_target,
					&conn->target_info, &conn->target_info_sz)) {
		conn->state = SOUP_NTLM_FAILED;
		return FALSE;
	}

#ifdef USE_NTLM_AUTH
	if (priv->sso_available && conn->state == SOUP_NTLM_SENT_REQUEST) {
		char *input, *response;

		/* Re-Initiate ntlm_auth process in case it was closed/killed abnormally */
		if (!sso_ntlm_initiate (priv)) {
			conn->state = SOUP_NTLM_SSO_FAILED;
			success = FALSE;
			goto out;
		}

		input = g_strdup_printf ("TT %s\n", auth_header + 5);
		response = sso_ntlm_response (priv, input, conn->state);
		sso_ntlm_close (priv);
		g_free (input);

		if (!response) {
			conn->state = SOUP_NTLM_SSO_FAILED;
			success = FALSE;
		} else if (!g_ascii_strcasecmp (response, "PW")) {
			conn->state = SOUP_NTLM_SSO_FAILED;
			priv->sso_available = FALSE;
			g_free (response);
		} else {
			conn->response_header = response;
			if (priv->password_state != SOUP_NTLM_PASSWORD_ACCEPTED)
				priv->password_state = SOUP_NTLM_PASSWORD_PROVIDED;
		}
	}
 out:
#endif

	if (conn->state == SOUP_NTLM_SENT_REQUEST)
		conn->state = SOUP_NTLM_RECEIVED_CHALLENGE;

	uri = soup_message_get_uri (msg);
	authority = g_strdup_printf ("%s:%d", g_uri_get_host (uri), g_uri_get_port (uri));
	g_object_set (G_OBJECT (auth),
		      "realm", priv->domain,
		      "authority", authority,
		      NULL);
	g_free (authority);

	return success;
}

static GSList *
soup_auth_ntlm_get_protection_space (SoupAuth *auth, GUri *source_uri)
{
	char *space, *p;

	space = g_strdup (g_uri_get_path (source_uri));

	/* Strip filename component */
	p = strrchr (space, '/');
	if (p && p != space && p[1])
		*p = '\0';

	return g_slist_prepend (NULL, space);
}

static void
soup_auth_ntlm_authenticate (SoupAuth *auth, const char *username,
			     const char *password)
{
	SoupAuthNTLM *auth_ntlm = SOUP_AUTH_NTLM (auth);
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (auth_ntlm);
	const char *slash;

	g_return_if_fail (username != NULL);
	g_return_if_fail (password != NULL);

	if (priv->username)
		g_free (priv->username);
	if (priv->domain)
		g_free (priv->domain);

	slash = strpbrk (username, "\\/");
	if (slash) {
		priv->domain = g_strndup (username, slash - username);
		priv->username = g_strdup (slash + 1);
	} else {
		priv->domain = g_strdup ("");
		priv->username = g_strdup (username);
	}

	soup_ntlm_nt_hash (password, priv->nt_hash);
	soup_ntlm_lanmanager_hash (password, priv->lm_hash);

	priv->password_state = SOUP_NTLM_PASSWORD_PROVIDED;
}

static gboolean
soup_auth_ntlm_is_authenticated (SoupAuth *auth)
{
	SoupAuthNTLM *auth_ntlm = SOUP_AUTH_NTLM (auth);
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (auth_ntlm);

	return (priv->password_state != SOUP_NTLM_PASSWORD_NONE &&
		priv->password_state != SOUP_NTLM_PASSWORD_REJECTED);
}

static gboolean
soup_auth_ntlm_is_connection_ready (SoupConnectionAuth *auth,
				    SoupMessage        *msg,
				    gpointer            state)
{
	SoupAuthNTLM *auth_ntlm = SOUP_AUTH_NTLM (auth);
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (auth_ntlm);
	SoupNTLMConnectionState *conn = state;

	if (priv->password_state == SOUP_NTLM_PASSWORD_REJECTED)
		return FALSE;

	if (priv->password_state == SOUP_NTLM_PASSWORD_PROVIDED)
		return TRUE;

	return conn->state != SOUP_NTLM_FAILED;
}

static void
got_final_auth_result (SoupMessage *msg, gpointer data)
{
	SoupAuth *auth = data;
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (SOUP_AUTH_NTLM (auth));

	g_signal_handlers_disconnect_by_func (msg, G_CALLBACK (got_final_auth_result), auth);

	if (auth != soup_message_get_auth (msg))
		return;

	if (soup_message_get_status (msg) != SOUP_STATUS_UNAUTHORIZED)
		priv->password_state = SOUP_NTLM_PASSWORD_ACCEPTED;
}

static char *
soup_auth_ntlm_get_connection_authorization (SoupConnectionAuth *auth,
					     SoupMessage        *msg,
					     gpointer            state)
{
	SoupAuthNTLM *auth_ntlm = SOUP_AUTH_NTLM (auth);
	SoupAuthNTLMPrivate *priv = soup_auth_ntlm_get_instance_private (auth_ntlm);
	SoupNTLMConnectionState *conn = state;
	char *header = NULL;

	switch (conn->state) {
	case SOUP_NTLM_NEW:
#ifdef USE_NTLM_AUTH
		if (sso_ntlm_initiate (priv)) {
			header = sso_ntlm_response (priv, "YR\n", conn->state);
			if (header) {
				if (g_ascii_strcasecmp (header, "PW") != 0) {
					conn->state = SOUP_NTLM_SENT_REQUEST;
					break;
				} else {
					g_free (header);
					header = NULL;
					priv->sso_available = FALSE;
				}
			} else {
				g_debug ("NTLM single-sign-on using %s failed", NTLM_AUTH);
			}
		}
		/* If NTLM single-sign-on fails, go back to original
		 * request handling process.
		 */
#endif
		header = soup_ntlm_request ();
		conn->state = SOUP_NTLM_SENT_REQUEST;
		break;
	case SOUP_NTLM_RECEIVED_CHALLENGE:
		if (conn->response_header) {
			header = conn->response_header;
			conn->response_header = NULL;
		} else {
			header = soup_ntlm_response (conn->nonce,
						     priv->username,
						     priv->nt_hash,
						     priv->lm_hash,
						     NULL,
						     priv->domain,
						     conn->ntlmv2_session,
							 conn->negotiate_target,
							 conn->target_info,
							 conn->target_info_sz);
		}
		g_clear_pointer (&conn->nonce, g_free);
		conn->state = SOUP_NTLM_SENT_RESPONSE;

		if (priv->password_state != SOUP_NTLM_PASSWORD_ACCEPTED) {
			/* We need to know if this worked */
			g_signal_connect (msg, "got-headers",
					  G_CALLBACK (got_final_auth_result),
					  auth);
		}
		break;
#ifdef USE_NTLM_AUTH
	case SOUP_NTLM_SSO_FAILED:
		/* Restart request without SSO */
		g_debug ("NTLM single-sign-on by using %s failed", NTLM_AUTH);
		priv->sso_available = FALSE;
		header = soup_ntlm_request ();
		conn->state = SOUP_NTLM_SENT_REQUEST;
		break;
#endif
	default:
		break;
	}

	return header;
}

static void
soup_auth_ntlm_class_init (SoupAuthNTLMClass *auth_ntlm_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (auth_ntlm_class);
	SoupConnectionAuthClass *connauth_class = SOUP_CONNECTION_AUTH_CLASS (auth_ntlm_class);
	GObjectClass *object_class = G_OBJECT_CLASS (auth_ntlm_class);

	auth_class->scheme_name = "NTLM";
	auth_class->strength = 3;

	auth_class->get_protection_space = soup_auth_ntlm_get_protection_space;
	auth_class->authenticate = soup_auth_ntlm_authenticate;
	auth_class->is_authenticated = soup_auth_ntlm_is_authenticated;

	connauth_class->create_connection_state = soup_auth_ntlm_create_connection_state;
	connauth_class->free_connection_state = soup_auth_ntlm_free_connection_state;
	connauth_class->update_connection = soup_auth_ntlm_update_connection;
	connauth_class->get_connection_authorization = soup_auth_ntlm_get_connection_authorization;
	connauth_class->is_connection_ready = soup_auth_ntlm_is_connection_ready;

	object_class->finalize = soup_auth_ntlm_finalize;

#ifdef USE_NTLM_AUTH
	ntlm_auth_available = g_file_test (NTLM_AUTH, G_FILE_TEST_IS_EXECUTABLE);
	ntlm_auth_debug = (g_getenv ("SOUP_NTLM_AUTH_DEBUG") != NULL);
#endif
}

static void md4sum                (const unsigned char *in, 
				   int                  nbytes, 
				   unsigned char        digest[16]);

typedef guint32 DES_KS[16][2]; /* Single-key DES key schedule */

static void deskey                (DES_KS, unsigned char *, int);

static void des                   (DES_KS, unsigned char[8]);

static void setup_schedule        (const guchar *key_56, DES_KS ks);

static void calc_response         (const guchar        *key, 
				   const guchar        *plaintext,
				   guchar              *results);

#define LM_PASSWORD_MAGIC "\x4B\x47\x53\x21\x40\x23\x24\x25" \
                          "\x4B\x47\x53\x21\x40\x23\x24\x25" \
			  "\x00\x00\x00\x00\x00"

static void
soup_ntlm_lanmanager_hash (const char *password, guchar hash[21])
{
	guchar lm_password [15];
	DES_KS ks;
	int i;

	for (i = 0; i < 14 && password [i]; i++)
		lm_password [i] = g_ascii_toupper ((unsigned char) password [i]);

	for (; i < 15; i++)
		lm_password [i] = '\0';

	memcpy (hash, LM_PASSWORD_MAGIC, 21);

	setup_schedule (lm_password, ks);
	des (ks, hash);

	setup_schedule (lm_password + 7, ks);
	des (ks, hash + 8);
}

static void
soup_ntlm_nt_hash (const char *password, guchar hash[21])
{
	unsigned char *buf, *p;

	p = buf = g_malloc (strlen (password) * 2);

	while (*password) {
		*p++ = *password++;
		*p++ = '\0';
	}

	md4sum (buf, p - buf, hash);
	memset (hash + 16, 0, 5);

	g_free (buf);
}

typedef struct {
	guint16 length;
	guint16 length2;
	guint16 offset;
	guchar  zero_pad[2];
} NTLMString;

#define NTLM_CHALLENGE_NONCE_OFFSET         24
#define NTLM_CHALLENGE_NONCE_LENGTH          8
#define NTLM_CHALLENGE_DOMAIN_STRING_OFFSET 12
#define NTLM_CHALLENGE_TARGET_INFORMATION_OFFSET      40

#define NTLM_CHALLENGE_FLAGS_OFFSET         20
#define NTLM_FLAGS_NEGOTIATE_NTLMV2 0x00080000
#define NTLM_FLAGS_NEGOTIATE_TARGET_INFORMATION 0x00800000
#define NTLM_FLAGS_REQUEST_TARGET 0x00000004

#define NTLM_RESPONSE_HEADER "NTLMSSP\x00\x03\x00\x00\x00"
#define NTLM_RESPONSE_FLAGS 0x8201
#define NTLM_RESPONSE_TARGET_INFORMATION_OFFSET 44
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY 0x00080000

#define HMAC_MD5_LENGTH                     16

typedef struct {
        guchar     header[12];

	NTLMString lm_resp;
	NTLMString nt_resp;
	NTLMString domain;
	NTLMString user;
	NTLMString host;
	NTLMString session_key;

        guint32    flags;
} NTLMResponse;

static void
ntlm_set_string (NTLMString *string, int *offset, int len)
{
	string->offset = GUINT16_TO_LE (*offset);
	string->length = string->length2 = GUINT16_TO_LE (len);
	*offset += len;
}

static char *
soup_ntlm_request (void)
{
	return g_strdup ("NTLM TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA");
}

static gboolean
soup_ntlm_parse_challenge (const char *challenge,
			   char      **nonce,
			   char      **default_domain,
			   gboolean   *ntlmv2_session,
			   gboolean   *negotiate_target,
			   char		**target_info,
			   size_t	*target_info_sz)
{
	gsize clen;
	NTLMString domain;
	NTLMString target;
	guchar *chall;
	guint32 flags;

	chall = g_base64_decode (challenge, &clen);
	if (clen < NTLM_CHALLENGE_DOMAIN_STRING_OFFSET ||
	    clen < NTLM_CHALLENGE_NONCE_OFFSET + NTLM_CHALLENGE_NONCE_LENGTH) {
		g_free (chall);
		return FALSE;
	}

	memcpy (&flags, chall + NTLM_CHALLENGE_FLAGS_OFFSET, sizeof(flags));
	flags = GUINT_FROM_LE (flags);
	*ntlmv2_session = (flags & NTLM_FLAGS_NEGOTIATE_NTLMV2) ? TRUE : FALSE;
	/* To know if NTLMv2 responses should be calculated */
	*negotiate_target = (flags & NTLM_FLAGS_NEGOTIATE_TARGET_INFORMATION ) ? TRUE : FALSE;
        if (*negotiate_target) {
            if (clen < NTLM_CHALLENGE_TARGET_INFORMATION_OFFSET + sizeof (target)) {
                g_free (chall);
                return FALSE;
            }
        }

	if (default_domain) {
		memcpy (&domain, chall + NTLM_CHALLENGE_DOMAIN_STRING_OFFSET, sizeof (domain));
		domain.length = GUINT16_FROM_LE (domain.length);
		domain.offset = GUINT16_FROM_LE (domain.offset);

		if (clen < domain.length + domain.offset) {
			g_free (chall);
			return FALSE;
		}

		g_free (*default_domain);
		*default_domain = g_convert ((char *)chall + domain.offset,
					     domain.length, "UTF-8", "UCS-2LE",
					     NULL, NULL, NULL);
	}

	if (nonce) {
		g_free (*nonce);
		*nonce = g_memdup2 (chall + NTLM_CHALLENGE_NONCE_OFFSET,
				   NTLM_CHALLENGE_NONCE_LENGTH);
	}
	/* For NTLMv2 response */
	if (*negotiate_target && target_info) {
		memcpy (&target, chall + NTLM_CHALLENGE_TARGET_INFORMATION_OFFSET, sizeof (target));
		target.length = GUINT16_FROM_LE (target.length);
		target.offset = GUINT16_FROM_LE (target.offset);

		if (clen < target.length + target.offset) {
			g_free (chall);
			return FALSE;
		}
		g_free (*target_info);
		*target_info = g_memdup2 (chall + target.offset, target.length);
		*target_info_sz = target.length;
	}

	g_free (chall);
	return TRUE;
}

static void
calc_ntlm2_session_response (const char *nonce,
			     guchar      nt_hash[21],
			     guchar      lm_hash[21],
			     guchar     *lm_resp,
			     gsize       lm_resp_sz,
			     guchar     *nt_resp)
{
	guint32 client_nonce[2];
	guchar ntlmv2_hash[16];
	GChecksum *ntlmv2_cksum;
	gsize ntlmv2_hash_sz = sizeof (ntlmv2_hash);

	/* FIXME: if GLib ever gets a more secure random number
	 * generator, use it here
	 */
	client_nonce[0] = g_random_int();
	client_nonce[1] = g_random_int();

	ntlmv2_cksum = g_checksum_new (G_CHECKSUM_MD5);
	g_checksum_update (ntlmv2_cksum, (const guchar *) nonce, 8);
	g_checksum_update (ntlmv2_cksum, (const guchar *) client_nonce, sizeof (client_nonce));
	g_checksum_get_digest (ntlmv2_cksum, ntlmv2_hash, &ntlmv2_hash_sz);
	g_checksum_free (ntlmv2_cksum);

	/* Send the padded client nonce as a fake lm_resp */
	memset (lm_resp, 0, lm_resp_sz);
	memcpy (lm_resp, client_nonce, sizeof (client_nonce));

	/* Compute nt_hash as usual but with a new nonce */
	calc_response (nt_hash, ntlmv2_hash, nt_resp);
}

/* Compute HMAC-MD5 with Glib function*/
static void
calc_hmac_md5 (unsigned char *hmac, const guchar *key, gsize key_sz, const guchar *data, gsize data_sz)
{
	char *hmac_hex, *hex_pos;
	size_t count;

	hmac_hex = g_compute_hmac_for_data(G_CHECKSUM_MD5, key, key_sz, data, data_sz);
	hex_pos = hmac_hex;
	for (count = 0; count < HMAC_MD5_LENGTH; count++)
	{
		/* The 'hh' sscanf format modifier is C99, so we enable it on
		 * non-Windows or if __USE_MINGW_ANSI_STDIO is enabled or`
		 * if we are building on Visual Studio 2015 or later
		 */
#if !defined (G_OS_WIN32) || (__USE_MINGW_ANSI_STDIO == 1) || (_MSC_VER >= 1900)
		sscanf(hex_pos, "%2hhx", &hmac[count]);
#else
		unsigned int tmp_hmac;
		sscanf(hex_pos, "%2x", &tmp_hmac);
		hmac[count] = (guint8)tmp_hmac;
#endif

		hex_pos += 2;
	}
	g_free(hmac_hex);
}

static void
calc_ntlmv2_response (const char *user, const char *domain,
						const guchar *nt_hash, const gsize nt_hash_sz,
						const guchar *nonce,
						const char *target_info, size_t target_info_sz,
						guchar *lm_resp, size_t lm_resp_sz,
						guchar *nt_resp, size_t nt_resp_sz)
{
	const unsigned char blob_signature[] = {0x01,0x01,0x00,0x00};
	const unsigned char blob_reserved[] = {0x00,0x00,0x00,0x00};
	gint64 blob_timestamp;
	unsigned char client_nonce[8];
	const unsigned char blob_unknown[] = {0x00,0x00,0x00,0x00};

	unsigned char ntv2_hash[HMAC_MD5_LENGTH];
	guchar *nonce_blob, *blob, *p_blob;
	unsigned char nonce_blob_hash[HMAC_MD5_LENGTH];
	unsigned char nonce_client_nonce[16], nonce_client_nonce_hash[HMAC_MD5_LENGTH];
	gchar *user_uppercase, *user_domain, *user_domain_conv;
	gsize user_domain_conv_sz;
	size_t blob_sz;
	int i;

	/* create HMAC-MD5 hash of Unicode uppercase username and Unicode domain */
	user_uppercase = g_utf8_strup (user, strlen (user));
	user_domain = g_strconcat (user_uppercase, domain, NULL);
	user_domain_conv = g_convert (user_domain, -1, "UCS-2LE", "UTF-8", NULL, &user_domain_conv_sz, NULL);
	calc_hmac_md5 (ntv2_hash, nt_hash, nt_hash_sz, (const guchar *)user_domain_conv, user_domain_conv_sz);
	g_free (user_uppercase);
	g_free (user_domain);
	g_free (user_domain_conv);

	/* create random client nonce */
	for (i = 0; i < sizeof (client_nonce); i++)
	{
		client_nonce[i] = g_random_int();
	}

	/* create timestamp for blob
	 * LE, 64-bit signed value, number of tenths of a ms since January 1, 1601.*/
	blob_timestamp = GINT64_TO_LE(((unsigned long)time(NULL) + 11644473600) * 10000000);

	/* create blob */
	blob_sz = sizeof (blob_signature) + sizeof (blob_reserved) +
			sizeof (blob_timestamp) + sizeof (client_nonce) +
			sizeof (blob_unknown) + target_info_sz;
	p_blob = blob = g_malloc (blob_sz);
	memset (blob, 0, blob_sz);
	memcpy (p_blob, blob_signature, sizeof (blob_signature));
	memcpy (p_blob += sizeof (blob_signature), blob_reserved, sizeof (blob_reserved));
	memcpy (p_blob += sizeof (blob_reserved), &blob_timestamp, sizeof (blob_timestamp));
	memcpy (p_blob += sizeof (blob_timestamp), client_nonce, sizeof (client_nonce));
	memcpy (p_blob += sizeof (client_nonce), blob_unknown, sizeof (blob_unknown));
	memcpy (p_blob + sizeof (blob_unknown), target_info, target_info_sz);

	/* create HMAC-MD5 hash of concatenated nonce and blob */
	nonce_blob = g_malloc (NTLM_CHALLENGE_NONCE_LENGTH + blob_sz);
	memcpy (nonce_blob, nonce, NTLM_CHALLENGE_NONCE_LENGTH);
	memcpy (nonce_blob + NTLM_CHALLENGE_NONCE_LENGTH, blob, blob_sz);
	calc_hmac_md5 (nonce_blob_hash, (const guchar *)ntv2_hash, (gsize) sizeof (ntv2_hash), (const guchar *) nonce_blob, (gsize) NTLM_CHALLENGE_NONCE_LENGTH + blob_sz);
	g_free (nonce_blob);

	/* create NTv2 response */
	memset (nt_resp, 0, nt_resp_sz);
	memcpy (nt_resp, nonce_blob_hash, sizeof (nonce_blob_hash));
	memcpy (nt_resp + sizeof (nonce_blob_hash), blob, blob_sz);

	g_free (blob);

	/* LMv2
	 * create HMAC-MD5 hash of concatenated nonce and client nonce
	 */
	memcpy (nonce_client_nonce, nonce, NTLM_CHALLENGE_NONCE_LENGTH);
	memcpy (nonce_client_nonce + NTLM_CHALLENGE_NONCE_LENGTH, client_nonce, sizeof (client_nonce));
	calc_hmac_md5 (nonce_client_nonce_hash, (const guchar *) ntv2_hash, (gsize) sizeof (ntv2_hash), (const guchar *) nonce_client_nonce, (gsize) NTLM_CHALLENGE_NONCE_LENGTH + sizeof (client_nonce));

	/* create LMv2 response */
	memset (lm_resp, 0, lm_resp_sz);
	memcpy (lm_resp, nonce_client_nonce_hash, sizeof (nonce_client_nonce_hash));
	memcpy (lm_resp + sizeof (nonce_client_nonce_hash), client_nonce, sizeof (client_nonce));
}

static char *
soup_ntlm_response (const char *nonce, 
		    const char *user,
		    guchar      nt_hash[21],
		    guchar      lm_hash[21],
		    const char *host, 
		    const char *domain,
		    gboolean    ntlmv2_session,
		    gboolean    negotiate_target,
		    const char	*target_info,
		    size_t	target_info_sz)
{

	int offset;
	gsize hlen, dlen, ulen, nt_resp_sz;
	guchar lm_resp[24], *nt_resp;
	char *user_conv, *host_conv, *domain_conv;
	NTLMResponse resp;
	char *out, *p;
	int state, save;

	if (negotiate_target)
	{
		/* nonce_blob_hash 16 + blob_signature 4 + blob_reserved 4 +
		 * blob_timestamp 8 + client_nonce 8 + blob_unknown 4 +
		 * target_info*/
		nt_resp_sz = NTLM_RESPONSE_TARGET_INFORMATION_OFFSET + target_info_sz;
	} else {
		nt_resp_sz = 24;
	}
	nt_resp = g_malloc (nt_resp_sz);

	if (ntlmv2_session && !negotiate_target) {
		calc_ntlm2_session_response (nonce, nt_hash, lm_hash,
					     lm_resp, sizeof(lm_resp), nt_resp);
	} else if (!negotiate_target){
		/* Compute a regular NTLMv1 response */
		calc_response (nt_hash, (guchar *) nonce, nt_resp);
		calc_response (lm_hash, (guchar *) nonce, lm_resp);
	} else {
		calc_ntlmv2_response (user, domain,
					nt_hash, 21,
					(guchar *) nonce,
					target_info, target_info_sz,
					lm_resp, sizeof (lm_resp),
					nt_resp, (size_t) nt_resp_sz);
	}

	memset (&resp, 0, sizeof (resp));
	memcpy (resp.header, NTLM_RESPONSE_HEADER, sizeof (resp.header));
	resp.flags = GUINT32_TO_LE (NTLM_RESPONSE_FLAGS);
	if (ntlmv2_session)
		resp.flags |= GUINT32_TO_LE (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
	if (negotiate_target)
			resp.flags |= GUINT32_TO_LE (NTLM_FLAGS_REQUEST_TARGET);
	offset = sizeof (resp);

	if (!host)
		host = "UNKNOWN";

	domain_conv = g_convert (domain, -1, "UCS-2LE", "UTF-8", NULL, &dlen, NULL);
	user_conv = g_convert (user, -1, "UCS-2LE", "UTF-8", NULL, &ulen, NULL);
	host_conv = g_convert (host, -1, "UCS-2LE", "UTF-8", NULL, &hlen, NULL);

	ntlm_set_string (&resp.domain, &offset, dlen);
	ntlm_set_string (&resp.user, &offset, ulen);
	ntlm_set_string (&resp.host, &offset, hlen);
	ntlm_set_string (&resp.lm_resp, &offset, sizeof (lm_resp));
	ntlm_set_string (&resp.nt_resp, &offset, nt_resp_sz);

	out = g_malloc (((offset + 3) * 4) / 3 + 6);
	memcpy (out, "NTLM ", 5);
	p = out + 5;

	state = save = 0;

	p += g_base64_encode_step ((const guchar *) &resp, sizeof (resp), 
				   FALSE, p, &state, &save);
	p += g_base64_encode_step ((const guchar *) domain_conv, dlen, 
				   FALSE, p, &state, &save);
	p += g_base64_encode_step ((const guchar *) user_conv, ulen, 
				   FALSE, p, &state, &save);
	p += g_base64_encode_step ((const guchar *) host_conv, hlen, 
				   FALSE, p, &state, &save);
	p += g_base64_encode_step (lm_resp, sizeof (lm_resp), 
				   FALSE, p, &state, &save);
	p += g_base64_encode_step (nt_resp, nt_resp_sz,
				   FALSE, p, &state, &save);
	p += g_base64_encode_close (FALSE, p, &state, &save);
	*p = '\0';

	g_free (domain_conv);
	g_free (user_conv);
	g_free (host_conv);
	g_free (nt_resp);

	return out;
}

/* DES utils */
/* Set up a key schedule based on a 56bit key */
static void
setup_schedule (const guchar *key_56, DES_KS ks)
{
	guchar key[8];
	int i, c, bit;

	key[0] = (key_56[0])                                 ;
	key[1] = (key_56[1] >> 1) | ((key_56[0] << 7) & 0xFF);
	key[2] = (key_56[2] >> 2) | ((key_56[1] << 6) & 0xFF);
	key[3] = (key_56[3] >> 3) | ((key_56[2] << 5) & 0xFF);
	key[4] = (key_56[4] >> 4) | ((key_56[3] << 4) & 0xFF);
	key[5] = (key_56[5] >> 5) | ((key_56[4] << 3) & 0xFF);
	key[6] = (key_56[6] >> 6) | ((key_56[5] << 2) & 0xFF);
	key[7] =                    ((key_56[6] << 1) & 0xFF);

	/* Fix parity */
	for (i = 0; i < 8; i++) {
		for (c = bit = 0; bit < 8; bit++)
			if (key[i] & (1 << bit))
				c++;
		if (!(c & 1))
			key[i] ^= 0x01;
	}

        deskey (ks, key, 0);
}

static void
calc_response (const guchar *key, const guchar *plaintext, guchar *results)
{
        DES_KS ks;

	memcpy (results, plaintext, 8);
	memcpy (results + 8, plaintext, 8);
	memcpy (results + 16, plaintext, 8);

        setup_schedule (key, ks);
	des (ks, results);

        setup_schedule (key + 7, ks);
	des (ks, results + 8);

        setup_schedule (key + 14, ks);
        des (ks, results + 16);
}


/* 
 * MD4 encoder. (The one everyone else uses is not GPL-compatible;
 * this is a reimplementation from spec.) This doesn't need to be
 * efficient for our purposes, although it would be nice to fix
 * it to not malloc()...
 */

#define F(X,Y,Z) ( ((X)&(Y)) | ((~(X))&(Z)) )
#define G(X,Y,Z) ( ((X)&(Y)) | ((X)&(Z)) | ((Y)&(Z)) )
#define H(X,Y,Z) ( (X)^(Y)^(Z) )
#define ROT(val, n) ( ((val) << (n)) | ((val) >> (32 - (n))) )

static void
md4sum (const unsigned char *in, int nbytes, unsigned char digest[16])
{
	unsigned char *M;
	guint32 A, B, C, D, AA, BB, CC, DD, X[16];
	int pbytes, nbits = nbytes * 8, i, j;

	/* There is *always* padding of at least one bit. */
	pbytes = ((119 - (nbytes % 64)) % 64) + 1;
	M = alloca (nbytes + pbytes + 8);
	memcpy (M, in, nbytes);
	memset (M + nbytes, 0, pbytes + 8);
	M[nbytes] = 0x80;
	M[nbytes + pbytes] = nbits & 0xFF;
	M[nbytes + pbytes + 1] = (nbits >> 8) & 0xFF;
	M[nbytes + pbytes + 2] = (nbits >> 16) & 0xFF;
	M[nbytes + pbytes + 3] = (nbits >> 24) & 0xFF;

	A = 0x67452301;
	B = 0xEFCDAB89;
	C = 0x98BADCFE;
	D = 0x10325476;

	for (i = 0; i < nbytes + pbytes + 8; i += 64) {
		for (j = 0; j < 16; j++) {
			X[j] =  (M[i + j*4]) |
				(M[i + j*4 + 1] << 8) |
				(M[i + j*4 + 2] << 16) |
				(M[i + j*4 + 3] << 24);
		}

		AA = A;
		BB = B;
		CC = C;
		DD = D;

		A = ROT (A + F(B, C, D) + X[0], 3);
		D = ROT (D + F(A, B, C) + X[1], 7);
		C = ROT (C + F(D, A, B) + X[2], 11);
		B = ROT (B + F(C, D, A) + X[3], 19);
		A = ROT (A + F(B, C, D) + X[4], 3);
		D = ROT (D + F(A, B, C) + X[5], 7);
		C = ROT (C + F(D, A, B) + X[6], 11);
		B = ROT (B + F(C, D, A) + X[7], 19);
		A = ROT (A + F(B, C, D) + X[8], 3);
		D = ROT (D + F(A, B, C) + X[9], 7);
		C = ROT (C + F(D, A, B) + X[10], 11);
		B = ROT (B + F(C, D, A) + X[11], 19);
		A = ROT (A + F(B, C, D) + X[12], 3);
		D = ROT (D + F(A, B, C) + X[13], 7);
		C = ROT (C + F(D, A, B) + X[14], 11);
		B = ROT (B + F(C, D, A) + X[15], 19);

		A = ROT (A + G(B, C, D) + X[0] + 0x5A827999, 3);
		D = ROT (D + G(A, B, C) + X[4] + 0x5A827999, 5);
		C = ROT (C + G(D, A, B) + X[8] + 0x5A827999, 9);
		B = ROT (B + G(C, D, A) + X[12] + 0x5A827999, 13);
		A = ROT (A + G(B, C, D) + X[1] + 0x5A827999, 3);
		D = ROT (D + G(A, B, C) + X[5] + 0x5A827999, 5);
		C = ROT (C + G(D, A, B) + X[9] + 0x5A827999, 9);
		B = ROT (B + G(C, D, A) + X[13] + 0x5A827999, 13);
		A = ROT (A + G(B, C, D) + X[2] + 0x5A827999, 3);
		D = ROT (D + G(A, B, C) + X[6] + 0x5A827999, 5);
		C = ROT (C + G(D, A, B) + X[10] + 0x5A827999, 9);
		B = ROT (B + G(C, D, A) + X[14] + 0x5A827999, 13);
		A = ROT (A + G(B, C, D) + X[3] + 0x5A827999, 3);
		D = ROT (D + G(A, B, C) + X[7] + 0x5A827999, 5);
		C = ROT (C + G(D, A, B) + X[11] + 0x5A827999, 9);
		B = ROT (B + G(C, D, A) + X[15] + 0x5A827999, 13);

		A = ROT (A + H(B, C, D) + X[0] + 0x6ED9EBA1, 3);
		D = ROT (D + H(A, B, C) + X[8] + 0x6ED9EBA1, 9);
		C = ROT (C + H(D, A, B) + X[4] + 0x6ED9EBA1, 11);
		B = ROT (B + H(C, D, A) + X[12] + 0x6ED9EBA1, 15);
		A = ROT (A + H(B, C, D) + X[2] + 0x6ED9EBA1, 3);
		D = ROT (D + H(A, B, C) + X[10] + 0x6ED9EBA1, 9);
		C = ROT (C + H(D, A, B) + X[6] + 0x6ED9EBA1, 11);
		B = ROT (B + H(C, D, A) + X[14] + 0x6ED9EBA1, 15);
		A = ROT (A + H(B, C, D) + X[1] + 0x6ED9EBA1, 3);
		D = ROT (D + H(A, B, C) + X[9] + 0x6ED9EBA1, 9);
		C = ROT (C + H(D, A, B) + X[5] + 0x6ED9EBA1, 11);
		B = ROT (B + H(C, D, A) + X[13] + 0x6ED9EBA1, 15);
		A = ROT (A + H(B, C, D) + X[3] + 0x6ED9EBA1, 3);
		D = ROT (D + H(A, B, C) + X[11] + 0x6ED9EBA1, 9);
		C = ROT (C + H(D, A, B) + X[7] + 0x6ED9EBA1, 11);
		B = ROT (B + H(C, D, A) + X[15] + 0x6ED9EBA1, 15);

		A += AA;
		B += BB;
		C += CC;
		D += DD;
	}

	digest[0]  =  A        & 0xFF;
	digest[1]  = (A >>  8) & 0xFF;
	digest[2]  = (A >> 16) & 0xFF;
	digest[3]  = (A >> 24) & 0xFF;
	digest[4]  =  B        & 0xFF;
	digest[5]  = (B >>  8) & 0xFF;
	digest[6]  = (B >> 16) & 0xFF;
	digest[7]  = (B >> 24) & 0xFF;
	digest[8]  =  C        & 0xFF;
	digest[9]  = (C >>  8) & 0xFF;
	digest[10] = (C >> 16) & 0xFF;
	digest[11] = (C >> 24) & 0xFF;
	digest[12] =  D        & 0xFF;
	digest[13] = (D >>  8) & 0xFF;
	digest[14] = (D >> 16) & 0xFF;
	digest[15] = (D >> 24) & 0xFF;
}


/* Public domain DES implementation from Phil Karn */
static const guint32 Spbox[8][64] = {
	{ 0x01010400,0x00000000,0x00010000,0x01010404,
	  0x01010004,0x00010404,0x00000004,0x00010000,
	  0x00000400,0x01010400,0x01010404,0x00000400,
	  0x01000404,0x01010004,0x01000000,0x00000004,
	  0x00000404,0x01000400,0x01000400,0x00010400,
	  0x00010400,0x01010000,0x01010000,0x01000404,
	  0x00010004,0x01000004,0x01000004,0x00010004,
	  0x00000000,0x00000404,0x00010404,0x01000000,
	  0x00010000,0x01010404,0x00000004,0x01010000,
	  0x01010400,0x01000000,0x01000000,0x00000400,
	  0x01010004,0x00010000,0x00010400,0x01000004,
	  0x00000400,0x00000004,0x01000404,0x00010404,
	  0x01010404,0x00010004,0x01010000,0x01000404,
	  0x01000004,0x00000404,0x00010404,0x01010400,
	  0x00000404,0x01000400,0x01000400,0x00000000,
	  0x00010004,0x00010400,0x00000000,0x01010004 },
	{ 0x80108020,0x80008000,0x00008000,0x00108020,
	  0x00100000,0x00000020,0x80100020,0x80008020,
	  0x80000020,0x80108020,0x80108000,0x80000000,
	  0x80008000,0x00100000,0x00000020,0x80100020,
	  0x00108000,0x00100020,0x80008020,0x00000000,
	  0x80000000,0x00008000,0x00108020,0x80100000,
	  0x00100020,0x80000020,0x00000000,0x00108000,
	  0x00008020,0x80108000,0x80100000,0x00008020,
	  0x00000000,0x00108020,0x80100020,0x00100000,
	  0x80008020,0x80100000,0x80108000,0x00008000,
	  0x80100000,0x80008000,0x00000020,0x80108020,
	  0x00108020,0x00000020,0x00008000,0x80000000,
	  0x00008020,0x80108000,0x00100000,0x80000020,
	  0x00100020,0x80008020,0x80000020,0x00100020,
	  0x00108000,0x00000000,0x80008000,0x00008020,
	  0x80000000,0x80100020,0x80108020,0x00108000 },
	{ 0x00000208,0x08020200,0x00000000,0x08020008,
	  0x08000200,0x00000000,0x00020208,0x08000200,
	  0x00020008,0x08000008,0x08000008,0x00020000,
	  0x08020208,0x00020008,0x08020000,0x00000208,
	  0x08000000,0x00000008,0x08020200,0x00000200,
	  0x00020200,0x08020000,0x08020008,0x00020208,
	  0x08000208,0x00020200,0x00020000,0x08000208,
	  0x00000008,0x08020208,0x00000200,0x08000000,
	  0x08020200,0x08000000,0x00020008,0x00000208,
	  0x00020000,0x08020200,0x08000200,0x00000000,
	  0x00000200,0x00020008,0x08020208,0x08000200,
	  0x08000008,0x00000200,0x00000000,0x08020008,
	  0x08000208,0x00020000,0x08000000,0x08020208,
	  0x00000008,0x00020208,0x00020200,0x08000008,
	  0x08020000,0x08000208,0x00000208,0x08020000,
	  0x00020208,0x00000008,0x08020008,0x00020200 },
	{ 0x00802001,0x00002081,0x00002081,0x00000080,
	  0x00802080,0x00800081,0x00800001,0x00002001,
	  0x00000000,0x00802000,0x00802000,0x00802081,
	  0x00000081,0x00000000,0x00800080,0x00800001,
	  0x00000001,0x00002000,0x00800000,0x00802001,
	  0x00000080,0x00800000,0x00002001,0x00002080,
	  0x00800081,0x00000001,0x00002080,0x00800080,
	  0x00002000,0x00802080,0x00802081,0x00000081,
	  0x00800080,0x00800001,0x00802000,0x00802081,
	  0x00000081,0x00000000,0x00000000,0x00802000,
	  0x00002080,0x00800080,0x00800081,0x00000001,
	  0x00802001,0x00002081,0x00002081,0x00000080,
	  0x00802081,0x00000081,0x00000001,0x00002000,
	  0x00800001,0x00002001,0x00802080,0x00800081,
	  0x00002001,0x00002080,0x00800000,0x00802001,
	  0x00000080,0x00800000,0x00002000,0x00802080 },
	{ 0x00000100,0x02080100,0x02080000,0x42000100,
	  0x00080000,0x00000100,0x40000000,0x02080000,
	  0x40080100,0x00080000,0x02000100,0x40080100,
	  0x42000100,0x42080000,0x00080100,0x40000000,
	  0x02000000,0x40080000,0x40080000,0x00000000,
	  0x40000100,0x42080100,0x42080100,0x02000100,
	  0x42080000,0x40000100,0x00000000,0x42000000,
	  0x02080100,0x02000000,0x42000000,0x00080100,
	  0x00080000,0x42000100,0x00000100,0x02000000,
	  0x40000000,0x02080000,0x42000100,0x40080100,
	  0x02000100,0x40000000,0x42080000,0x02080100,
	  0x40080100,0x00000100,0x02000000,0x42080000,
	  0x42080100,0x00080100,0x42000000,0x42080100,
	  0x02080000,0x00000000,0x40080000,0x42000000,
	  0x00080100,0x02000100,0x40000100,0x00080000,
	  0x00000000,0x40080000,0x02080100,0x40000100 },
	{ 0x20000010,0x20400000,0x00004000,0x20404010,
	  0x20400000,0x00000010,0x20404010,0x00400000,
	  0x20004000,0x00404010,0x00400000,0x20000010,
	  0x00400010,0x20004000,0x20000000,0x00004010,
	  0x00000000,0x00400010,0x20004010,0x00004000,
	  0x00404000,0x20004010,0x00000010,0x20400010,
	  0x20400010,0x00000000,0x00404010,0x20404000,
	  0x00004010,0x00404000,0x20404000,0x20000000,
	  0x20004000,0x00000010,0x20400010,0x00404000,
	  0x20404010,0x00400000,0x00004010,0x20000010,
	  0x00400000,0x20004000,0x20000000,0x00004010,
	  0x20000010,0x20404010,0x00404000,0x20400000,
	  0x00404010,0x20404000,0x00000000,0x20400010,
	  0x00000010,0x00004000,0x20400000,0x00404010,
	  0x00004000,0x00400010,0x20004010,0x00000000,
	  0x20404000,0x20000000,0x00400010,0x20004010 },
	{ 0x00200000,0x04200002,0x04000802,0x00000000,
	  0x00000800,0x04000802,0x00200802,0x04200800,
	  0x04200802,0x00200000,0x00000000,0x04000002,
	  0x00000002,0x04000000,0x04200002,0x00000802,
	  0x04000800,0x00200802,0x00200002,0x04000800,
	  0x04000002,0x04200000,0x04200800,0x00200002,
	  0x04200000,0x00000800,0x00000802,0x04200802,
	  0x00200800,0x00000002,0x04000000,0x00200800,
	  0x04000000,0x00200800,0x00200000,0x04000802,
	  0x04000802,0x04200002,0x04200002,0x00000002,
	  0x00200002,0x04000000,0x04000800,0x00200000,
	  0x04200800,0x00000802,0x00200802,0x04200800,
	  0x00000802,0x04000002,0x04200802,0x04200000,
	  0x00200800,0x00000000,0x00000002,0x04200802,
	  0x00000000,0x00200802,0x04200000,0x00000800,
	  0x04000002,0x04000800,0x00000800,0x00200002 },
	{ 0x10001040,0x00001000,0x00040000,0x10041040,
	  0x10000000,0x10001040,0x00000040,0x10000000,
	  0x00040040,0x10040000,0x10041040,0x00041000,
	  0x10041000,0x00041040,0x00001000,0x00000040,
	  0x10040000,0x10000040,0x10001000,0x00001040,
	  0x00041000,0x00040040,0x10040040,0x10041000,
	  0x00001040,0x00000000,0x00000000,0x10040040,
	  0x10000040,0x10001000,0x00041040,0x00040000,
	  0x00041040,0x00040000,0x10041000,0x00001000,
	  0x00000040,0x10040040,0x00001000,0x00041040,
	  0x10001000,0x00000040,0x10000040,0x10040000,
	  0x10040040,0x10000000,0x00040000,0x10001040,
	  0x00000000,0x10041040,0x00040040,0x10000040,
	  0x10040000,0x10001000,0x10001040,0x00000000,
	  0x10041040,0x00041000,0x00041000,0x00001040,
	  0x00001040,0x00040040,0x10000000,0x10041000 }
};

#undef F
#define	F(l,r,key){\
	work = ((r >> 4) | (r << 28)) ^ key[0];\
	l ^= Spbox[6][work & 0x3f];\
	l ^= Spbox[4][(work >> 8) & 0x3f];\
	l ^= Spbox[2][(work >> 16) & 0x3f];\
	l ^= Spbox[0][(work >> 24) & 0x3f];\
	work = r ^ key[1];\
	l ^= Spbox[7][work & 0x3f];\
	l ^= Spbox[5][(work >> 8) & 0x3f];\
	l ^= Spbox[3][(work >> 16) & 0x3f];\
	l ^= Spbox[1][(work >> 24) & 0x3f];\
}
/* Encrypt or decrypt a block of data in ECB mode */
static void
des (guint32 ks[16][2], unsigned char block[8])
{
	guint32 left,right,work;
	
	/* Read input block and place in left/right in big-endian order */
	left = ((guint32)block[0] << 24)
	 | ((guint32)block[1] << 16)
	 | ((guint32)block[2] << 8)
	 | (guint32)block[3];
	right = ((guint32)block[4] << 24)
	 | ((guint32)block[5] << 16)
	 | ((guint32)block[6] << 8)
	 | (guint32)block[7];

	/* Hoey's clever initial permutation algorithm, from Outerbridge
	 * (see Schneier p 478)	
	 *
	 * The convention here is the same as Outerbridge: rotate each
	 * register left by 1 bit, i.e., so that "left" contains permuted
	 * input bits 2, 3, 4, ... 1 and "right" contains 33, 34, 35, ... 32	
	 * (using origin-1 numbering as in the FIPS). This allows us to avoid
	 * one of the two rotates that would otherwise be required in each of
	 * the 16 rounds.
	 */
	work = ((left >> 4) ^ right) & 0x0f0f0f0f;
	right ^= work;
	left ^= work << 4;
	work = ((left >> 16) ^ right) & 0xffff;
	right ^= work;
	left ^= work << 16;
	work = ((right >> 2) ^ left) & 0x33333333;
	left ^= work;
	right ^= (work << 2);
	work = ((right >> 8) ^ left) & 0xff00ff;
	left ^= work;
	right ^= (work << 8);
	right = (right << 1) | (right >> 31);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left << 1) | (left >> 31);

	/* Now do the 16 rounds */
	F(left,right,ks[0]);
	F(right,left,ks[1]);
	F(left,right,ks[2]);
	F(right,left,ks[3]);
	F(left,right,ks[4]);
	F(right,left,ks[5]);
	F(left,right,ks[6]);
	F(right,left,ks[7]);
	F(left,right,ks[8]);
	F(right,left,ks[9]);
	F(left,right,ks[10]);
	F(right,left,ks[11]);
	F(left,right,ks[12]);
	F(right,left,ks[13]);
	F(left,right,ks[14]);
	F(right,left,ks[15]);

	/* Inverse permutation, also from Hoey via Outerbridge and Schneier */
	right = (right << 31) | (right >> 1);
	work = (left ^ right) & 0xaaaaaaaa;
	left ^= work;
	right ^= work;
	left = (left >> 1) | (left  << 31);
	work = ((left >> 8) ^ right) & 0xff00ff;
	right ^= work;
	left ^= work << 8;
	work = ((left >> 2) ^ right) & 0x33333333;
	right ^= work;
	left ^= work << 2;
	work = ((right >> 16) ^ left) & 0xffff;
	left ^= work;
	right ^= work << 16;
	work = ((right >> 4) ^ left) & 0x0f0f0f0f;
	left ^= work;
	right ^= work << 4;

	/* Put the block back into the user's buffer with final swap */
	block[0] = right >> 24;
	block[1] = right >> 16;
	block[2] = right >> 8;
	block[3] = right;
	block[4] = left >> 24;
	block[5] = left >> 16;
	block[6] = left >> 8;
	block[7] = left;
}

/* Key schedule-related tables from FIPS-46 */

/* permuted choice table (key) */
static const unsigned char pc1[] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

/* number left rotations of pc1 */
static const unsigned char totrot[] = {
	1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
};

/* permuted choice key (table) */
static const unsigned char pc2[] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

/* End of DES-defined tables */


/* bit 0 is left-most in byte */
static const int bytebit[] = {
	0200,0100,040,020,010,04,02,01
};


/* Generate key schedule for encryption or decryption
 * depending on the value of "decrypt"
 */
static void
deskey (DES_KS k, unsigned char *key, int decrypt)
{
	unsigned char pc1m[56];		/* place to modify pc1 into */
	unsigned char pcr[56];		/* place to rotate pc1 into */
	register int i,j,l;
	int m;
	unsigned char ks[8];

	for (j=0; j<56; j++) {		/* convert pc1 to bits of key */
		l=pc1[j]-1;		/* integer bit location	 */
		m = l & 07;		/* find bit		 */
		pc1m[j]=(key[l>>3] &	/* find which key byte l is in */
			bytebit[m])	/* and which bit of that byte */
			? 1 : 0;	/* and store 1-bit result */
	}
	for (i=0; i<16; i++) {		/* key chunk for each iteration */
		memset(ks,0,sizeof(ks));	/* Clear key schedule */
		for (j=0; j<56; j++)	/* rotate pc1 the right amount */
			pcr[j] = pc1m[(l=j+totrot[decrypt? 15-i : i])<(j<28? 28 : 56) ? l: l-28];
			/* rotate left and right halves independently */
		for (j=0; j<48; j++){	/* select bits individually */
			/* check bit that goes to ks[j] */
			if (pcr[pc2[j]-1]){
				/* mask it in if it's there */
				l= j % 6;
				ks[j/6] |= bytebit[l] >> 2;
			}
		}
		/* Now convert to packed odd/even interleaved form */
		k[i][0] = ((guint32)ks[0] << 24)
		 | ((guint32)ks[2] << 16)
		 | ((guint32)ks[4] << 8)
		 | ((guint32)ks[6]);
		k[i][1] = ((guint32)ks[1] << 24)
		 | ((guint32)ks[3] << 16)
		 | ((guint32)ks[5] << 8)
		 | ((guint32)ks[7]);
	}
}
