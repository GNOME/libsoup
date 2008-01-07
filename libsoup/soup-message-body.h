/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_BODY_H
#define SOUP_MESSAGE_BODY_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

/**
 * SoupMemoryUse:
 * @SOUP_MEMORY_STATIC: The memory is statically allocated and
 * constant; libsoup can use the passed-in buffer directly and not
 * need to worry about it being modified or freed.
 * @SOUP_MEMORY_TAKE: The caller has allocated the memory for the
 * #SoupBuffer's use; libsoup will assume ownership of it and free it
 * (with g_free()) when it is done with it.
 * @SOUP_MEMORY_COPY: The passed-in data belongs to the caller; the
 * #SoupBuffer will copy it into new memory, leaving the caller free
 * to reuse the original memory.
 * @SOUP_MEMORY_TEMPORARY: The passed-in data belongs to the caller,
 * but will remain valid for the lifetime of the #SoupBuffer. The
 * difference between this and @SOUP_MEMORY_STATIC is that if you copy
 * a @SOUP_MEMORY_TEMPORARY buffer, it will make a copy of the memory
 * as well, rather than reusing the original memory.
 *
 * Describes how #SoupBuffer should use the data passed in by the
 * caller.
 **/
typedef enum {
	SOUP_MEMORY_STATIC,
	SOUP_MEMORY_TAKE,
	SOUP_MEMORY_COPY,
	SOUP_MEMORY_TEMPORARY,
} SoupMemoryUse;

/**
 * SoupBuffer:
 * @data: the data
 * @length: length of @data
 *
 * A data buffer, generally used to represent a chunk of a
 * #SoupMessageBody.
 *
 * @data is a #char because that's generally convenient; in some
 * situations you may need to cast it to #guchar or another type.
 **/
typedef struct {
	const char *data;
	gsize       length;
} SoupBuffer;

GType soup_buffer_get_type (void);
#define SOUP_TYPE_BUFFER (soup_buffer_get_type ())

SoupBuffer *soup_buffer_new           (SoupMemoryUse  use,
				       gconstpointer  data,
				       gsize          length);
SoupBuffer *soup_buffer_new_subbuffer (SoupBuffer    *parent,
				       gsize          offset,
				       gsize          length);

SoupBuffer *soup_buffer_copy          (SoupBuffer    *buffer);
void        soup_buffer_free          (SoupBuffer    *buffer);

/**
 * SoupMessageBody:
 * @data: the data
 * @length: length of @data
 *
 * A #SoupMessage request or response body.
 *
 * Note that while @length always reflects the full length of the
 * message body, @data is normally %NULL, and will only be filled in
 * after soup_message_body_flatten() is called. For client-side
 * messages, this automatically happens for the response body after it
 * has been fully read, unless you set the
 * %SOUP_MESSAGE_OVERWRITE_CHUNKS flags. Likewise, for server-side
 * messages, the request body is automatically filled in after being
 * read.
 *
 * As an added bonus, when @data is filled in, it is always terminated
 * with a '\0' byte (which is not reflected in @length).
 **/
typedef struct {
	const char *data;
	goffset     length;
} SoupMessageBody;

SoupMessageBody *soup_message_body_new           (void);

void             soup_message_body_append        (SoupMessageBody *body,
						  SoupMemoryUse    use,
						  gconstpointer    data,
						  gsize            length);
void             soup_message_body_append_buffer (SoupMessageBody *body,
						  SoupBuffer      *buffer);
void             soup_message_body_truncate      (SoupMessageBody *body);
void             soup_message_body_complete      (SoupMessageBody *body);

SoupBuffer      *soup_message_body_flatten       (SoupMessageBody *body);

SoupBuffer      *soup_message_body_get_chunk     (SoupMessageBody *body,
						  goffset          offset);

void             soup_message_body_free          (SoupMessageBody *body);

G_END_DECLS

#endif /* SOUP_MESSAGE_BODY_H */
