/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to rpmMD5Init, call rpmMD5Update as
 * needed on buffers full of bytes, and then call rpmMD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ifndef SOUP_MD5_UTILS_H
#define SOUP_MD5_UTILS_H

#include <glib.h>

typedef struct {
	/*< private >*/
	guint32  buf[4];
	guint32  bits[2];
	guchar   in[64];
	gboolean doByteReverse;
} SoupMD5Context;

void soup_md5_init      (SoupMD5Context *ctx);
void soup_md5_update    (SoupMD5Context *ctx,
			 gconstpointer   buf,
			 gsize           len);
void soup_md5_final     (SoupMD5Context *ctx,
			 guchar          digest[16]);
void soup_md5_final_hex (SoupMD5Context *ctx,
			 char            digest[33]);


#endif	/* SOUP_MD5_UTILS_H */
