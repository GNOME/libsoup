/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-ntlm-offset: 8 -*- */
/*
 * soup-connection-ntlm.c: NTLM-using Connection
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <string.h>

#include "soup-connection-ntlm.h"
#include "soup-private.h"
#include "soup-uri.h"

void send_request (SoupConnection *conn, SoupMessage *req);

struct SoupConnectionNTLMPrivate {
	char *user;
	guchar nt_hash[21], lm_hash[21];
	gboolean authenticated;
};

#define PARENT_TYPE SOUP_TYPE_CONNECTION
static SoupConnectionClass *parent_class;

static char     *soup_ntlm_request         (void);
static gboolean  soup_ntlm_parse_challenge (const char  *challenge,
					    char       **nonce,
					    char       **default_domain);
static char     *soup_ntlm_response        (const char  *nonce, 
					    const char  *user,
					    const char  *password,
					    const char  *host, 
					    const char  *domain);

static void
init (GObject *object)
{
	SoupConnectionNTLM *ntlm = SOUP_CONNECTION_NTLM (object);

	ntlm->priv = g_new0 (SoupConnectionNTLMPrivate, 1);
}

static void
finalize (GObject *object)
{
	SoupConnectionNTLM *ntlm = SOUP_CONNECTION_NTLM (object);

	g_free (ntlm->priv->user);
	memset (ntlm->priv->nt_hash, 0, sizeof (ntlm->priv->nt_hash));
	memset (ntlm->priv->lm_hash, 0, sizeof (ntlm->priv->lm_hash));

	g_free (ntlm->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	SoupConnectionClass *connection_class =
		SOUP_CONNECTION_CLASS (object_class);

	parent_class = g_type_class_ref (PARENT_TYPE);

	connection_class->send_request = send_request;
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_connection_ntlm, SoupConnectionNTLM, class_init, init, PARENT_TYPE)


static void
ntlm_authorize_pre (SoupMessage *msg, gpointer user_data)
{
	SoupConnectionNTLM *ntlm = user_data;
	const GSList *headers;
	const char *val;
	char *nonce, *header;
	char *username, *domain_username = NULL, *password = NULL;
	char *slash, *domain;

	if (ntlm->priv->authenticated) {
		/* We already authenticated, but then got another 401.
		 * That means "permission denied", so don't try to
		 * authenticate again.
		 */
		return;
	}

	headers = soup_message_get_header_list (msg->response_headers,
						"WWW-Authenticate");
	while (headers) {
		val = headers->data;
		if (!strncmp (val, "NTLM ", 5))
			break;
	}
	if (!headers)
		return;

	if (!soup_ntlm_parse_challenge (val, &nonce, &domain))
		return;

	soup_connection_authenticate (SOUP_CONNECTION (ntlm), msg,
				      "NTLM", domain,
				      &domain_username, &password);
	if (!domain_username) {
		g_free (nonce);
		g_free (domain);
		return;
	}

	slash = strpbrk (domain_username, "\\/");
	if (slash) {
		g_free (domain);
		domain = g_strdup (domain_username);
		username = slash + 1;
	} else
		username = domain_username;

	header = soup_ntlm_response (nonce, username, password, NULL, domain);
	g_free (domain_username);
	g_free (password);
	g_free (domain);
	g_free (nonce);

	soup_message_remove_header (msg->request_headers, "Authorization");
	soup_message_add_header (msg->request_headers,
				 "Authorization", header);
	g_free (header);
	ntlm->priv->authenticated = TRUE;

	/* Remove the WWW-Authenticate headers so the session won't try
	 * to do Basic auth too.
	 */
	soup_message_remove_header (msg->response_headers, "WWW-Authenticate");
}

static void
ntlm_authorize_post (SoupMessage *msg, gpointer conn)
{
	SoupConnectionNTLM *ntlm = conn;

	if (ntlm->priv->authenticated &&
	    soup_message_get_header (msg->request_headers, "Authorization")) {
		/* We just added the last Auth header, so restart it. */
		soup_connection_send_request (conn, msg);
	}
}

void
send_request (SoupConnection *conn, SoupMessage *req)
{
	SoupConnectionNTLM *ntlm = SOUP_CONNECTION_NTLM (conn);

	if (!ntlm->priv->authenticated) {
		char *header = soup_ntlm_request ();

		soup_message_add_header (req->request_headers,
					 "Authorization", header);
		g_free (header);
	}

	soup_message_remove_handler (req, SOUP_HANDLER_PRE_BODY,
				     ntlm_authorize_pre, conn);
	soup_message_add_status_code_handler (req, SOUP_STATUS_UNAUTHORIZED,
					      SOUP_HANDLER_PRE_BODY,
					      ntlm_authorize_pre, conn);

	soup_message_remove_handler (req, SOUP_HANDLER_POST_BODY,
				     ntlm_authorize_post, conn);
	soup_message_add_status_code_handler (req, SOUP_STATUS_UNAUTHORIZED,
					      SOUP_HANDLER_POST_BODY,
					      ntlm_authorize_post, conn);

	SOUP_CONNECTION_CLASS (parent_class)->send_request (conn, req);
}



/* MD4 */
static void md4sum                (const unsigned char *in, 
				   int                  nbytes, 
				   unsigned char        digest[16]);

/* DES */
typedef unsigned long DES_KS[16][2]; /* Single-key DES key schedule */

static void deskey                (DES_KS, unsigned char *, int);

static void des                   (DES_KS, unsigned char *);

static void setup_schedule        (const guchar *key_56, DES_KS ks);

static void calc_response         (const guchar        *key, 
				   const guchar        *plaintext,
				   guchar              *results);

#define LM_PASSWORD_MAGIC "\x4B\x47\x53\x21\x40\x23\x24\x25" \
                          "\x4B\x47\x53\x21\x40\x23\x24\x25" \
			  "\x00\x00\x00\x00\x00"

static void
lanmanager_hash (const char *password, guchar hash[21])
{
	guchar lm_password [15];
	DES_KS ks;
	int i;

	for (i = 0; i < 14 && password [i]; i++)
		lm_password [i] = toupper ((unsigned char) password [i]);

	for (; i < 15; i++)
		lm_password [i] = '\0';

	memcpy (hash, LM_PASSWORD_MAGIC, 21);

	setup_schedule (lm_password, ks);
	des (ks, hash);

	setup_schedule (lm_password + 7, ks);
	des (ks, hash + 8);
}

static void
nt_hash (const char *password, guchar hash[21])
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

#define NTLM_RESPONSE_HEADER "NTLMSSP\x00\x03\x00\x00\x00"
#define NTLM_RESPONSE_FLAGS 0x8202

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
	return g_strdup ("NTLM TlRMTVNTUAABAAAABoIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA");
}

static gboolean
soup_ntlm_parse_challenge (const char *challenge,
			   char      **nonce,
			   char      **default_domain)
{
	int clen, decodelen;
	NTLMString domain;
	char *chall;
	int state, save;

	if (strncmp (challenge, "NTLM ", 5) != 0)
		return FALSE;

	decodelen = strlen (challenge) - 5;
	chall = g_malloc (decodelen);

	state = save = 0;
	clen = soup_base64_decode_step ((guchar *) challenge + 5, 
					decodelen,
					chall, 
					&state, 
					&save);

	if (clen < NTLM_CHALLENGE_DOMAIN_STRING_OFFSET ||
	    clen < NTLM_CHALLENGE_NONCE_OFFSET + NTLM_CHALLENGE_NONCE_LENGTH) {
		g_free (chall);
		return FALSE;
	}

	if (default_domain) {
		memcpy (&domain, chall + NTLM_CHALLENGE_DOMAIN_STRING_OFFSET, sizeof (domain));
		domain.length = GUINT16_FROM_LE (domain.length);
		domain.offset = GUINT16_FROM_LE (domain.offset);

		if (clen < domain.length + domain.offset) {
			g_free (chall);
			return FALSE;
		}

		*default_domain = g_strndup (chall + domain.offset, domain.length);
	}

	if (nonce) {
		*nonce = g_memdup (chall + NTLM_CHALLENGE_NONCE_OFFSET,
				   NTLM_CHALLENGE_NONCE_LENGTH);
	}

	g_free (chall);
	return TRUE;
}

static char *
soup_ntlm_response (const char *nonce, 
		    const char *user,
		    const char *password,
		    const char *host, 
		    const char *domain)
{
	int hlen, dlen, ulen, offset;
	guchar hash[21], lm_resp[24], nt_resp[24];
	NTLMResponse resp;
	unsigned char *out, *p;
	int state, save;

	nt_hash (password, hash);
	calc_response (hash, nonce, nt_resp);
	lanmanager_hash (password, hash);
	calc_response (hash, nonce, lm_resp);

	memset (&resp, 0, sizeof (resp));
	memcpy (resp.header, NTLM_RESPONSE_HEADER, sizeof (resp.header));
	resp.flags = GUINT32_TO_LE (NTLM_RESPONSE_FLAGS);

	offset = sizeof (resp);

	dlen = strlen (domain);
	ntlm_set_string (&resp.domain, &offset, dlen);
	ulen = strlen (user);
	ntlm_set_string (&resp.user, &offset, ulen);
	if (!host)
		host = "UNKNOWN";
	hlen = strlen (host);
	ntlm_set_string (&resp.host, &offset, hlen);
	ntlm_set_string (&resp.lm_resp, &offset, sizeof (lm_resp));
	ntlm_set_string (&resp.nt_resp, &offset, sizeof (nt_resp));

	out = g_malloc (((offset + 3) * 4) / 3 + 6);
	strncpy (out, "NTLM ", 5);
	p = out + 5;

	state = save = 0;

	p += soup_base64_encode_step ((guchar *) &resp, 
				      sizeof (resp), 
				      FALSE, 
				      p, 
				      &state, 
				      &save);
	p += soup_base64_encode_step ((guchar *) domain, 
				      dlen, 
				      FALSE, 
				      p, 
				      &state, 
				      &save);
	p += soup_base64_encode_step ((guchar *) user, 
				      ulen, 
				      FALSE, 
				      p, 
				      &state, 
				      &save);
	p += soup_base64_encode_step ((guchar *) host, 
				      hlen, 
				      FALSE, 
				      p,
				      &state, 
				      &save);
	p += soup_base64_encode_step (lm_resp, 
				      sizeof (lm_resp), 
				      FALSE, 
				      p, 
				      &state, 
				      &save);

	p += soup_base64_encode_close (nt_resp, 
				       sizeof (nt_resp), 
				       FALSE, 
				       p, 
				       &state, 
				       &save);
	*p = '\0';

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

	pbytes = (120 - (nbytes % 64)) % 64;
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
static unsigned long Spbox[8][64] = {
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
des(ks,block)
unsigned long ks[16][2];	/* Key schedule */
unsigned char block[8];		/* Data block */
{
	unsigned long left,right,work;
	
	/* Read input block and place in left/right in big-endian order */
	left = ((unsigned long)block[0] << 24)
	 | ((unsigned long)block[1] << 16)
	 | ((unsigned long)block[2] << 8)
	 | (unsigned long)block[3];
	right = ((unsigned long)block[4] << 24)
	 | ((unsigned long)block[5] << 16)
	 | ((unsigned long)block[6] << 8)
	 | (unsigned long)block[7];

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
static unsigned char pc1[] = {
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
static unsigned char totrot[] = {
	1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28
};

/* permuted choice key (table) */
static unsigned char pc2[] = {
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
static int bytebit[] = {
	0200,0100,040,020,010,04,02,01
};


/* Generate key schedule for encryption or decryption
 * depending on the value of "decrypt"
 */
static void
deskey(k,key,decrypt)
DES_KS k;			/* Key schedule array */
unsigned char *key;		/* 64 bits (will use only 56) */
int decrypt;			/* 0 = encrypt, 1 = decrypt */
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
		k[i][0] = ((long)ks[0] << 24)
		 | ((long)ks[2] << 16)
		 | ((long)ks[4] << 8)
		 | ((long)ks[6]);
		k[i][1] = ((long)ks[1] << 24)
		 | ((long)ks[3] << 16)
		 | ((long)ks[5] << 8)
		 | ((long)ks[7]);
	}
}
