/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#ifndef SOUP_MESSAGE_HEADERS_H
#define SOUP_MESSAGE_HEADERS_H 1

#include <libsoup/soup-types.h>

typedef struct SoupMessageHeaders SoupMessageHeaders;
typedef enum {
	SOUP_MESSAGE_HEADERS_REQUEST,
	SOUP_MESSAGE_HEADERS_RESPONSE
} SoupMessageHeadersType;

SoupMessageHeaders *soup_message_headers_new      (SoupMessageHeadersType type);

void                soup_message_headers_free     (SoupMessageHeaders *hdrs);

void                soup_message_headers_append   (SoupMessageHeaders *hdrs,
						   const char         *name,
						   const char         *value);
void                soup_message_headers_replace  (SoupMessageHeaders *hdrs,
						   const char         *name,
						   const char         *value);

void                soup_message_headers_remove   (SoupMessageHeaders *hdrs,
						   const char         *name);
void                soup_message_headers_clear    (SoupMessageHeaders *hdrs);

const char         *soup_message_headers_find     (SoupMessageHeaders *hdrs,
						   const char         *name);
const char         *soup_message_headers_find_nth (SoupMessageHeaders *hdrs,
						   const char         *name,
						   int                 index);

typedef void      (*SoupMessageHeadersForeachFunc)(const char         *name,
						   const char         *value,
						   gpointer            user_data);

void                soup_message_headers_foreach  (SoupMessageHeaders *hdrs,
						   SoupMessageHeadersForeachFunc func,
						   gpointer            user_data);

/* Specific headers */

/**
 * SoupEncoding:
 * @SOUP_ENCODING_UNRECOGNIZED: unknown / error
 * @SOUP_ENCODING_NONE: no body is present (which is not the same as a
 * 0-length body, and only occurs in certain places)
 * @SOUP_ENCODING_CONTENT_LENGTH: Content-Length encoding
 * @SOUP_ENCODING_EOF: Response body ends when the connection is closed
 * @SOUP_ENCODING_CHUNKED: chunked encoding (currently only supported
 * for response)
 * @SOUP_ENCODING_BYTERANGES: multipart/byteranges (Reserved for future
 * use: NOT CURRENTLY IMPLEMENTED)
 *
 * How a message body is encoded for transport
 **/
typedef enum {
	SOUP_ENCODING_UNRECOGNIZED,
	SOUP_ENCODING_NONE,
	SOUP_ENCODING_CONTENT_LENGTH,
	SOUP_ENCODING_EOF,
	SOUP_ENCODING_CHUNKED,
	SOUP_ENCODING_BYTERANGES
} SoupEncoding;

SoupEncoding    soup_message_headers_get_encoding        (SoupMessageHeaders *hdrs);
void            soup_message_headers_set_encoding        (SoupMessageHeaders *hdrs,
							  SoupEncoding        encoding);

gsize           soup_message_headers_get_content_length  (SoupMessageHeaders *hdrs);
void            soup_message_headers_set_content_length  (SoupMessageHeaders *hdrs,
							  gsize               content_length);

typedef enum {
	SOUP_EXPECTATION_UNRECOGNIZED = (1 << 0),
	SOUP_EXPECTATION_CONTINUE     = (1 << 1)
} SoupExpectation;

SoupExpectation soup_message_headers_get_expectations    (SoupMessageHeaders *hdrs);
void            soup_message_headers_set_expectations    (SoupMessageHeaders *hdrs,
							  SoupExpectation     expectations);

#endif /* SOUP_MESSAGE_HEADERS_H */
