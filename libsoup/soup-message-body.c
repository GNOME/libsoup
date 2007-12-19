/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-body.c: SoupMessage request/response bodies
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <string.h>

#include "soup-message-body.h"

typedef struct {
	SoupBuffer     buffer;
	SoupMemoryUse  use;
	guint          refcount;
	SoupBuffer    *parent;
} SoupBufferPrivate;

/**
 * soup_buffer_new:
 * @data: data
 * @length: length of @data
 * @use: how @data is to be used by the buffer
 *
 * Creates a new #SoupBuffer containing @length bytes from @data.
 *
 * Return value: the new #SoupBuffer.
 **/
SoupBuffer *
soup_buffer_new (gconstpointer data, gsize length, SoupMemoryUse use)
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
	SoupBufferPrivate *parent_priv = (SoupBufferPrivate *)parent;
	SoupBufferPrivate *priv;

	/* If the parent is TEMPORARY, copy just the subbuffer part
	 * into new memory.
	 */
	if (parent_priv->use == SOUP_MEMORY_TEMPORARY) {
		return soup_buffer_new (parent->data + offset, length,
					SOUP_MEMORY_COPY);
	}

	/* Otherwise don't copy anything, and just reuse the existing
	 * memory.
	 */
	priv = g_slice_new0 (SoupBufferPrivate);
	priv->parent = soup_buffer_copy (parent);
	priv->buffer.data = priv->parent->data + offset;
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

	/* Only actually copy it if it's temporary memory */
	if (priv->use == SOUP_MEMORY_TEMPORARY)
		return soup_buffer_new_subbuffer (buffer, 0, buffer->length);

	/* Otherwise just bump the refcount */
	priv->refcount++;
	return buffer;
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
		if (priv->parent)
			soup_buffer_free (priv->parent);
		g_slice_free (SoupBufferPrivate, priv);
	}
}

struct SoupMessageBody {
	GSList *chunks, *last;
};

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
	return g_slice_new0 (SoupMessageBody);
}

static void
append_buffer (SoupMessageBody *body, SoupBuffer *buffer)
{
	if (body->last) {
		body->last = g_slist_append (body->last, buffer);
		body->last = body->last->next;
	} else
		body->chunks = body->last = g_slist_append (NULL, buffer);
}

/**
 * soup_message_body_append:
 * @body: a #SoupMessageBody
 * @data: data to append
 * @length: length of @data
 * @use: how to use @data
 *
 * Appends @length bytes from @data to @body according to @use.
 **/
void
soup_message_body_append (SoupMessageBody *body,
			  gconstpointer data, gsize length, SoupMemoryUse use)
{
	g_return_if_fail (length > 0);
	append_buffer (body, soup_buffer_new (data, length, use));
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
	GSList *iter;

	for (iter = body->chunks; iter; iter = iter->next)
		soup_buffer_free (iter->data);
	g_slist_free (body->chunks);
	body->chunks = body->last = NULL;
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
	append_buffer (body, soup_buffer_new (NULL, 0, SOUP_MEMORY_STATIC));
}

/**
 * soup_message_body_flatten:
 * @body: a #SoupMessageBody
 *
 * Generates a single #SoupBuffer containing all of the data in @body.
 * (In particular, if @body was built up with multiple
 * soup_message_body_append() or soup_message_body_append_buffer()
 * calls, the appended chunks will not actually be merged together
 * unless you call this method.)
 *
 * Return value: a #SoupBuffer containing all of the data in @body,
 * which must be freed with soup_buffer_free() when you are done with
 * it.
 **/
SoupBuffer *
soup_message_body_flatten (SoupMessageBody *body)
{
	guchar *buf, *ptr;
	gsize size;
	GSList *iter;
	SoupBuffer *chunk;

	if (!body->chunks)
		return soup_buffer_new (NULL, 0, SOUP_MEMORY_STATIC);

	/* If there is only 1 chunk (or 1 non-empty chunk followed by
	 * an empty one), just return it rather than building a new
	 * buffer.
	 */
	if ((body->last == body->chunks) ||
	    (body->last == body->chunks->next &&
	     ((SoupBuffer *)body->last)->length == 0))
		return soup_buffer_copy (body->chunks->data);

	size = soup_message_body_get_length (body);
	buf = g_malloc (size);
	for (iter = body->chunks, ptr = buf; iter; iter = iter->next) {
		chunk = iter->data;
		memcpy (ptr, chunk->data, chunk->length);
		ptr += chunk->length;
	}
	
	return soup_buffer_new (buf, size, SOUP_MEMORY_TAKE);
}

/**
 * soup_message_body_get_length:
 * @body: a #SoupMessageBody
 *
 * Gets the total length of @body.
 *
 * Return value: the total length of @body
 **/
gsize
soup_message_body_get_length (SoupMessageBody *body)
{
	gsize size;
	GSList *iter;
	SoupBuffer *chunk;

	for (iter = body->chunks, size = 0; iter; iter = iter->next) {
		chunk = iter->data;
		size += chunk->length;
	}

	return size;
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
soup_message_body_get_chunk (SoupMessageBody *body, gsize offset)
{
	GSList *iter;
	SoupBuffer *chunk = NULL;

	for (iter = body->chunks; iter; iter = iter->next) {
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
	soup_message_body_truncate (body);
	g_slice_free (SoupMessageBody, body);
}
