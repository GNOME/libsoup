/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-body.c: SoupMessage request/response bodies
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <string.h>

#include "soup-message-body.h"

/**
 * SECTION:soup-message-body
 * @short_description: HTTP message body
 * @see_also: #SoupMessage
 *
 * #SoupMessageBody represents the request or response body of a
 * #SoupMessage.
 *
 * In addition to #SoupMessageBody, libsoup also defines a "smaller"
 * data buffer type, #SoupBuffer, which is primarily used as a
 * component of #SoupMessageBody. In particular, when using chunked
 * encoding to transmit or receive a message, each chunk is
 * represented as a #SoupBuffer.
 **/

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
	SoupBuffer     buffer;
	SoupMemoryUse  use;
	guint          refcount;

	/* @other is used in subbuffers to store a reference to
	 * the parent buffer, or in TEMPORARY buffers to store a
	 * reference to a copy (see soup_buffer_copy()). Either
	 * way, we hold a ref.
	 */
	SoupBuffer    *other;
} SoupBufferPrivate;

/**
 * soup_buffer_new:
 * @use: how @data is to be used by the buffer
 * @data: data
 * @length: length of @data
 *
 * Creates a new #SoupBuffer containing @length bytes from @data.
 *
 * Return value: the new #SoupBuffer.
 **/
SoupBuffer *
soup_buffer_new (SoupMemoryUse use, gconstpointer data, gsize length)
{
	SoupBufferPrivate *priv = g_slice_new0 (SoupBufferPrivate);

	if (use == SOUP_MEMORY_COPY) {
		priv->buffer.data = g_memdup (data, length);
		priv->use = SOUP_MEMORY_TAKE;
	} else {
		priv->buffer.data = data;
		priv->use = use;
	}
	priv->buffer.length = length;
	priv->refcount = 1;

	return (SoupBuffer *)priv;
}

/**
 * soup_buffer_new_subbuffer:
 * @parent: the parent #SoupBuffer
 * @offset: offset within @parent to start at
 * @length: number of bytes to copy from @parent
 *
 * Creates a new #SoupBuffer containing @length bytes "copied" from
 * @parent starting at @offset. (Normally this will not actually copy
 * any data, but will instead simply reference the same data as
 * @parent does.)
 *
 * Return value: the new #SoupBuffer.
 **/
SoupBuffer *
soup_buffer_new_subbuffer (SoupBuffer *parent, gsize offset, gsize length)
{
	SoupBufferPrivate *priv;

	priv = g_slice_new0 (SoupBufferPrivate);
	priv->other = soup_buffer_copy (parent);
	priv->buffer.data = priv->other->data + offset;
	priv->buffer.length = length;
	priv->use = SOUP_MEMORY_STATIC;
	priv->refcount = 1;
	return (SoupBuffer *)priv;
}

/**
 * soup_buffer_copy:
 * @buffer: a #SoupBuffer
 *
 * Makes a copy of @buffer. In reality, #SoupBuffer is a refcounted
 * type, and calling soup_buffer_copy() will normally just increment
 * the refcount on @buffer and return it. However, if @buffer was
 * created with #SOUP_MEMORY_TEMPORARY memory, then soup_buffer_copy()
 * will actually return a copy of it, so that the data in the copy
 * will remain valid after the temporary buffer is freed.
 *
 * Return value: the new (or newly-reffed) buffer
 **/
SoupBuffer *
soup_buffer_copy (SoupBuffer *buffer)
{
	SoupBufferPrivate *priv = (SoupBufferPrivate *)buffer;

	/* For non-TEMPORARY buffers, this is just a ref */
	if (priv->use != SOUP_MEMORY_TEMPORARY) {
		priv->refcount++;
		return buffer;
	}

	/* For TEMPORARY buffers, we need to do a real copy the
	 * first time, and then after that, we just keep returning
	 * the copy. Use priv->other to store the copy.
	 */

	if (!priv->other) {
		priv->other = soup_buffer_new (SOUP_MEMORY_COPY,
					       buffer->data, buffer->length);
	}
	return soup_buffer_copy (priv->other);
}

/**
 * soup_buffer_free:
 * @buffer: a #SoupBuffer
 *
 * Frees @buffer. (In reality, as described in the documentation for
 * soup_buffer_copy(), this is actually an "unref" operation, and may
 * or may not actually free @buffer.)
 **/
void
soup_buffer_free (SoupBuffer *buffer)
{
	SoupBufferPrivate *priv = (SoupBufferPrivate *)buffer;

	if (!--priv->refcount) {
		if (priv->use == SOUP_MEMORY_TAKE)
			g_free ((gpointer)buffer->data);
		if (priv->other)
			soup_buffer_free (priv->other);
		g_slice_free (SoupBufferPrivate, priv);
	}
}

GType
soup_buffer_get_type (void)
{
	static GType type = 0;

	if (type == 0) {
		type = g_boxed_type_register_static (
			g_intern_static_string ("SoupBuffer"),
			(GBoxedCopyFunc)soup_buffer_copy,
			(GBoxedFreeFunc)soup_buffer_free);
	}
	return type;
}


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
	SoupMessageBody body;
	GSList *chunks, *last;
	SoupBuffer *flattened;
} SoupMessageBodyPrivate;

/**
 * soup_message_body_new:
 *
 * Creates a new #SoupMessageBody. #SoupMessage uses this internally; you
 * will not normally need to call it yourself.
 *
 * Return value: a new #SoupMessageBody.
 **/
SoupMessageBody *
soup_message_body_new (void)
{
	return (SoupMessageBody *)g_slice_new0 (SoupMessageBodyPrivate);
}

static void
append_buffer (SoupMessageBody *body, SoupBuffer *buffer)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	if (priv->last) {
		priv->last = g_slist_append (priv->last, buffer);
		priv->last = priv->last->next;
	} else
		priv->chunks = priv->last = g_slist_append (NULL, buffer);

	if (priv->flattened) {
		soup_buffer_free (priv->flattened);
		priv->flattened = NULL;
		body->data = NULL;
	}
	body->length += buffer->length;
}

/**
 * soup_message_body_append:
 * @body: a #SoupMessageBody
 * @use: how to use @data
 * @data: data to append
 * @length: length of @data
 *
 * Appends @length bytes from @data to @body according to @use.
 **/
void
soup_message_body_append (SoupMessageBody *body, SoupMemoryUse use,
			  gconstpointer data, gsize length)
{
	if (length > 0)
		append_buffer (body, soup_buffer_new (use, data, length));
}

/**
 * soup_message_body_append_buffer:
 * @body: a #SoupMessageBody
 * @buffer: a #SoupBuffer
 *
 * Appends the data from @buffer to @body. (#SoupMessageBody uses
 * #SoupBuffers internally, so this is normally a constant-time
 * operation that doesn't actually require copying the data in
 * @buffer.)
 **/
void
soup_message_body_append_buffer (SoupMessageBody *body, SoupBuffer *buffer)
{
	g_return_if_fail (buffer->length > 0);
	append_buffer (body, soup_buffer_copy (buffer));
}

/**
 * soup_message_body_truncate:
 * @body: a #SoupMessageBody
 *
 * Deletes all of the data in @body.
 **/
void
soup_message_body_truncate (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;
	GSList *iter;

	for (iter = priv->chunks; iter; iter = iter->next)
		soup_buffer_free (iter->data);
	g_slist_free (priv->chunks);
	priv->chunks = priv->last = NULL;

	if (priv->flattened) {
		soup_buffer_free (priv->flattened);
		priv->flattened = NULL;
		body->data = NULL;
	}
	body->length = 0;
}

/**
 * soup_message_body_complete:
 * @body: a #SoupMessageBody
 *
 * Tags @body as being complete; Call this when using chunked encoding
 * after you have appended the last chunk.
 **/
void
soup_message_body_complete (SoupMessageBody *body)
{
	append_buffer (body, soup_buffer_new (SOUP_MEMORY_STATIC, NULL, 0));
}

/**
 * soup_message_body_flatten:
 * @body: a #SoupMessageBody
 *
 * Fills in @body's data field with a buffer containing all of the
 * data in @body (plus an additional '\0' byte not counted by @body's
 * length field).
 *
 * Return value: a #SoupBuffer containing the same data as @body.
 * (You must free this buffer if you do not want it.)
 **/
SoupBuffer *
soup_message_body_flatten (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;
	char *buf, *ptr;
	GSList *iter;
	SoupBuffer *chunk;

	if (!priv->flattened) {
#if GLIB_SIZEOF_SIZE_T < 8
		g_return_val_if_fail (body->length < G_MAXSIZE, NULL);
#endif

		buf = ptr = g_malloc (body->length + 1);
		for (iter = priv->chunks; iter; iter = iter->next) {
			chunk = iter->data;
			memcpy (ptr, chunk->data, chunk->length);
			ptr += chunk->length;
		}
		*ptr = '\0';

		priv->flattened = soup_buffer_new (SOUP_MEMORY_TAKE,
						   buf, body->length);
		body->data = priv->flattened->data;
	}

	return soup_buffer_copy (priv->flattened);
}

/**
 * soup_message_body_get_chunk:
 * @body: a #SoupMessageBody
 * @offset: an offset
 *
 * Gets a #SoupBuffer containing data from @body starting at @offset.
 * The size of the returned chunk is unspecified. You can iterate
 * through the entire body by first calling
 * soup_message_body_get_chunk() with an offset of 0, and then on each
 * successive call, increment the offset by the length of the
 * previously-returned chunk.
 *
 * If @offset is greater than or equal to the total length of @body,
 * then the return value depends on whether or not
 * soup_message_body_complete() has been called or not; if it has,
 * then soup_message_body_get_chunk() will return a 0-length chunk
 * (indicating the end of @body). If it has not, then
 * soup_message_body_get_chunk() will return %NULL (indicating that
 * @body may still potentially have more data, but that data is not
 * currently available).
 *
 * Return value: a #SoupBuffer, or %NULL.
 **/
SoupBuffer *
soup_message_body_get_chunk (SoupMessageBody *body, goffset offset)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;
	GSList *iter;
	SoupBuffer *chunk = NULL;

	for (iter = priv->chunks; iter; iter = iter->next) {
		chunk = iter->data;

		if (offset < chunk->length || offset == 0)
			break;

		offset -= chunk->length;
	}

	if (!iter)
		return NULL;

	if (offset == 0)
		return soup_buffer_copy (chunk);
	else {
		return soup_buffer_new_subbuffer (chunk, offset,
						  chunk->length - offset);
	}
}

void
soup_message_body_free (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	soup_message_body_truncate (body);
	g_slice_free (SoupMessageBodyPrivate, priv);
}
