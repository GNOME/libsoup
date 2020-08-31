/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-body.c: SoupMessage request/response bodies
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-message-body.h"
#include "soup.h"

/**
 * SECTION:soup-message-body
 * @short_description: HTTP message body
 * @see_also: #SoupMessage
 *
 * #SoupMessageBody represents the request or response body of a
 * #SoupMessage.
 **/

/**
 * SoupMemoryUse:
 * @SOUP_MEMORY_STATIC: The memory is statically allocated and
 * constant; libsoup can use the passed-in buffer directly and not
 * need to worry about it being modified or freed.
 * @SOUP_MEMORY_TAKE: The caller has allocated the memory and libsoup
 * will assume ownership of it and free it with g_free().
 * @SOUP_MEMORY_COPY: The passed-in data belongs to the caller and
 * libsoup will copy it into new memory leaving the caller free
 * to reuse the original memory.
 **/

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
 * has been fully read. Likewise, for server-side
 * messages, the request body is automatically filled in after being
 * read.
 *
 * As an added bonus, when @data is filled in, it is always terminated
 * with a '\0' byte (which is not reflected in @length).
 **/

typedef struct {
	SoupMessageBody body;
	GSList *chunks, *last;
	GBytes *flattened;
	gboolean accumulate;
	goffset base_offset;
	int ref_count;
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
	SoupMessageBodyPrivate *priv;

	priv = g_slice_new0 (SoupMessageBodyPrivate);
	priv->accumulate = TRUE;
	priv->ref_count = 1;

	return (SoupMessageBody *)priv;
}

/**
 * soup_message_body_set_accumulate:
 * @body: a #SoupMessageBody
 * @accumulate: whether or not to accumulate body chunks in @body
 *
 * Sets or clears the accumulate flag on @body. (The default value is
 * %TRUE.) If set to %FALSE, @body's %data field will not be filled in
 * after the body is fully sent/received, and the chunks that make up
 * @body may be discarded when they are no longer needed.
 *
 * In particular, if you set this flag to %FALSE on an "incoming"
 * message body (that is, the #SoupMessage:response_body of a
 * client-side message, or #SoupMessage:request_body of a server-side
 * message), this will cause each chunk of the body to be discarded
 * after its corresponding #SoupMessage::got_chunk signal is emitted.
 *
 * If you set this flag to %FALSE on the #SoupMessage:response_body of
 * a server-side message, it will cause each chunk of the body to be
 * discarded after its corresponding #SoupMessage::wrote_chunk signal
 * is emitted.
 *
 * If you set the flag to %FALSE on the #SoupMessage:request_body of a
 * client-side message, it will block the accumulation of chunks into
 * @body's %data field, but it will not normally cause the chunks to
 * be discarded after being written like in the server-side
 * #SoupMessage:response_body case, because the request body needs to
 * be kept around in case the request needs to be sent a second time
 * due to redirection or authentication. However, if you set the
 * %SOUP_MESSAGE_CAN_REBUILD flag on the message, then the chunks will
 * be discarded, and you will be responsible for recreating the
 * request body after the #SoupMessage::restarted signal is emitted.
 *
 * Since: 2.24
 **/
void
soup_message_body_set_accumulate (SoupMessageBody *body,
				  gboolean         accumulate)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	priv->accumulate = accumulate;
}

/**
 * soup_message_body_get_accumulate:
 * @body: a #SoupMessageBody
 *
 * Gets the accumulate flag on @body; see
 * soup_message_body_set_accumulate() for details.
 *
 * Return value: the accumulate flag for @body.
 *
 * Since: 2.24
 **/
gboolean
soup_message_body_get_accumulate (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	return priv->accumulate;
}

static void
append_buffer (SoupMessageBody *body, GBytes *buffer)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	if (priv->last) {
		priv->last = g_slist_append (priv->last, buffer);
		priv->last = priv->last->next;
	} else
		priv->chunks = priv->last = g_slist_append (NULL, buffer);

        g_clear_pointer (&priv->flattened, g_bytes_unref);
        body->data = NULL;
	body->length += g_bytes_get_size (buffer);
}

/**
 * soup_message_body_append:
 * @body: a #SoupMessageBody
 * @use: how to use @data
 * @data: (array length=length) (element-type guint8): data to append
 * @length: length of @data
 *
 * Appends @length bytes from @data to @body according to @use.
 **/
void
soup_message_body_append (SoupMessageBody *body, SoupMemoryUse use,
			  gconstpointer data, gsize length)
{
        GBytes *bytes;
        if (length > 0) {
                if (use == SOUP_MEMORY_TAKE)
                        bytes = g_bytes_new_take ((guchar*)data, length);
                else if (use == SOUP_MEMORY_STATIC)
                        bytes = g_bytes_new_static (data, length);
                else
                        bytes = g_bytes_new (data, length);
                append_buffer (body, g_steal_pointer (&bytes));
        }
	else if (use == SOUP_MEMORY_TAKE)
		g_free ((gpointer)data);
}

/**
 * soup_message_body_append_take: (rename-to soup_message_body_append)
 * @body: a #SoupMessageBody
 * @data: (array length=length) (transfer full): data to append
 * @length: length of @data
 *
 * Appends @length bytes from @data to @body.
 *
 * This function is exactly equivalent to soup_message_body_append()
 * with %SOUP_MEMORY_TAKE as second argument; it exists mainly for
 * convenience and simplifying language bindings.
 *
 * Since: 2.32
 **/
void
soup_message_body_append_take (SoupMessageBody *body,
			       guchar *data, gsize length)
{
	soup_message_body_append(body, SOUP_MEMORY_TAKE, data, length);
}

/**
 * soup_message_body_append_bytes:
 * @body: a #SoupMessageBody
 * @buffer: a #GBytes
 *
 * Appends the data from @buffer to @body.
 **/
void
soup_message_body_append_bytes (SoupMessageBody *body, GBytes *buffer)
{
	g_return_if_fail (g_bytes_get_size (buffer) > 0);
	append_buffer (body, g_bytes_ref (buffer));
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

	g_slist_free_full (priv->chunks, (GDestroyNotify)g_bytes_unref);
	priv->chunks = priv->last = NULL;
	priv->base_offset = 0;
        g_clear_pointer (&priv->flattened, g_bytes_unref);
        body->data = NULL;
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
	append_buffer (body, g_bytes_new_static (NULL, 0));
}

/**
 * soup_message_body_flatten:
 * @body: a #SoupMessageBody
 *
 * Fills in @body's data field with a buffer containing all of the
 * data in @body (plus an additional '\0' byte not counted by @body's
 * length field).
 *
 * Return: (transfer full): a #GBytes containing the same data as @body.
 * (You must g_bytes_unref() this if you do not want it.)
 **/
GBytes *
soup_message_body_flatten (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	g_return_val_if_fail (priv->accumulate == TRUE, NULL);

	if (!priv->flattened) {
#if GLIB_SIZEOF_SIZE_T < 8
		g_return_val_if_fail (body->length < G_MAXSIZE, NULL);
#endif

                GByteArray *array = g_byte_array_sized_new (body->length + 1);
		for (GSList *iter = priv->chunks; iter; iter = iter->next) {
			GBytes *chunk = iter->data;
                        gsize chunk_size;
                        const guchar *chunk_data = g_bytes_get_data (chunk, &chunk_size);
                        g_byte_array_append (array, chunk_data, chunk_size);
		}
                // NUL terminate the array but don't reflect that in the length
                g_byte_array_append (array, (guchar*)"\0", 1);
                array->len -= 1;

		priv->flattened = g_byte_array_free_to_bytes (array);
                body->data = g_bytes_get_data (priv->flattened, NULL);
	}

	return g_bytes_ref (priv->flattened);
}

/**
 * soup_message_body_get_chunk:
 * @body: a #SoupMessageBody
 * @offset: an offset
 *
 * Gets a #GBytes containing data from @body starting at @offset.
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
 * Return value: (nullable): a #GBytes, or %NULL.
 **/
GBytes *
soup_message_body_get_chunk (SoupMessageBody *body, goffset offset)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;
	GSList *iter;
	GBytes *chunk = NULL;

	offset -= priv->base_offset;
	for (iter = priv->chunks; iter; iter = iter->next) {
		chunk = iter->data;
                gsize chunk_length = g_bytes_get_size (chunk);

		if (offset < chunk_length || offset == 0)
			break;

		offset -= chunk_length;
	}

	if (!iter)
		return NULL;

        return g_bytes_new_from_bytes (chunk, offset, g_bytes_get_size (chunk) - offset);
}

/**
 * soup_message_body_got_chunk:
 * @body: a #SoupMessageBody
 * @chunk: a #GBytes received from the network
 *
 * Handles the #SoupMessageBody part of receiving a chunk of data from
 * the network. Normally this means appending @chunk to @body, exactly
 * as with soup_message_body_append_bytes(), but if you have set
 * @body's accumulate flag to %FALSE, then that will not happen.
 *
 * This is a low-level method which you should not normally need to
 * use.
 *
 * Since: 2.24
 **/
void
soup_message_body_got_chunk (SoupMessageBody *body, GBytes *chunk)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	if (!priv->accumulate)
		return;

	soup_message_body_append_bytes (body, chunk);
}

/**
 * soup_message_body_wrote_chunk:
 * @body: a #SoupMessageBody
 * @chunk: a #GBytes returned from soup_message_body_get_chunk()
 *
 * Handles the #SoupMessageBody part of writing a chunk of data to the
 * network. Normally this is a no-op, but if you have set @body's
 * accumulate flag to %FALSE, then this will cause @chunk to be
 * discarded to free up memory.
 *
 * This is a low-level method which you should not need to use, and
 * there are further restrictions on its proper use which are not
 * documented here.
 *
 * Since: 2.24
 **/
void
soup_message_body_wrote_chunk (SoupMessageBody *body, GBytes *chunk)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;
	GBytes *chunk2;

	if (priv->accumulate)
		return;

	chunk2 = priv->chunks->data;
	g_return_if_fail (g_bytes_get_size (chunk) == g_bytes_get_size (chunk2));
	g_return_if_fail (chunk == chunk2);

	priv->chunks = g_slist_remove (priv->chunks, chunk2);
	if (!priv->chunks)
		priv->last = NULL;

	priv->base_offset += g_bytes_get_size (chunk2);
	g_bytes_unref (chunk2);
}

static SoupMessageBody *
soup_message_body_copy (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	g_atomic_int_inc (&priv->ref_count);
	return body;
}

/**
 * soup_message_body_free:
 * @body: a #SoupMessageBody
 *
 * Frees @body. You will not normally need to use this, as
 * #SoupMessage frees its associated message bodies automatically.
 **/
void
soup_message_body_free (SoupMessageBody *body)
{
	SoupMessageBodyPrivate *priv = (SoupMessageBodyPrivate *)body;

	if (!g_atomic_int_dec_and_test (&priv->ref_count))
		return;

	soup_message_body_truncate (body);
	g_slice_free (SoupMessageBodyPrivate, priv);
}

G_DEFINE_BOXED_TYPE (SoupMessageBody, soup_message_body, soup_message_body_copy, soup_message_body_free)
