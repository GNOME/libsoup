/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-multipart.c: multipart HTTP message bodies
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-multipart.h"
#include "soup-headers.h"
#include "soup-message-headers-private.h"
#include "soup.h"

/**
 * SoupMultipart:
 *
 * Represents a multipart HTTP message body, parsed according to the
 * syntax of RFC 2046.
 *
 * Of particular interest to HTTP are `multipart/byte-ranges` and
 * `multipart/form-data`,
 *
 * Although the headers of a [struct@Multipart] body part will contain the
 * full headers from that body part, libsoup does not interpret them
 * according to MIME rules. For example, each body part is assumed to
 * have "binary" Content-Transfer-Encoding, even if its headers
 * explicitly state otherwise. In other words, don't try to use
 * [struct@Multipart] for handling real MIME multiparts.
 *
 **/

struct _SoupMultipart {
	char *mime_type, *boundary;
	GPtrArray *headers, *bodies;
};

static SoupMultipart *
soup_multipart_new_internal (char *mime_type, char *boundary)
{
	SoupMultipart *multipart;

	multipart = g_slice_new (SoupMultipart);
	multipart->mime_type = mime_type;
	multipart->boundary = boundary;
	multipart->headers = g_ptr_array_new_with_free_func ((GDestroyNotify)soup_message_headers_unref);
	multipart->bodies = g_ptr_array_new_with_free_func ((GDestroyNotify)g_bytes_unref);

	return multipart;
}

static char *
generate_boundary (void)
{
	guint32 data[2];

	data[0] = g_random_int ();
	data[1] = g_random_int ();

	/* The maximum boundary string length is 69 characters, and a
	 * stringified SHA256 checksum is 64 bytes long.
	 */
	return g_compute_checksum_for_data (G_CHECKSUM_SHA256,
					    (const guchar *)&data,
					    sizeof (data));
}

/**
 * soup_multipart_new:
 * @mime_type: the MIME type of the multipart to create.
 *
 * Creates a new empty [struct@Multipart] with a randomly-generated
 * boundary string.
 *
 * Note that @mime_type must be the full MIME type, including "multipart/".
 *
 * See also: [ctor@Message.new_from_multipart].
 * 
 * Returns: a new empty #SoupMultipart of the given @mime_type
 **/
SoupMultipart *
soup_multipart_new (const char *mime_type)
{
	return soup_multipart_new_internal (g_strdup (mime_type),
					    generate_boundary ());
}

static const char *
find_boundary (const char *start, const char *end,
	       const char *boundary, int boundary_len)
{
	const char *b;

	for (b = memchr (start, '-', end - start);
	     b && b + boundary_len + 4 < end;
	     b = memchr (b + 2, '-', end - (b + 2))) {
		/* Check for "--boundary" */
		if (b[1] != '-' ||
		    memcmp (b + 2, boundary, boundary_len) != 0)
			continue;

		/* Check that it's at start of line */
		if (!(b == start || (b - start >= 2 && b[-1] == '\n' && b[-2] == '\r')))
			continue;

		/* Check for "--" or "\r\n" after boundary */
		if ((b[boundary_len + 2] == '-' && b[boundary_len + 3] == '-') ||
		    (b[boundary_len + 2] == '\r' && b[boundary_len + 3] == '\n'))
			return b;
	}
	return NULL;
}

/**
 * soup_multipart_new_from_message:
 * @headers: the headers of the HTTP message to parse
 * @body: the body of the HTTP message to parse
 *
 * Parses @headers and @body to form a new [struct@Multipart]
 *
 * Returns: (nullable): a new #SoupMultipart (or %NULL if the
 *   message couldn't be parsed or wasn't multipart).
 **/
SoupMultipart *
soup_multipart_new_from_message (SoupMessageHeaders *headers,
				 GBytes             *body)
{
	SoupMultipart *multipart;
	const char *content_type, *boundary;
	GHashTable *params;
	int boundary_len;
	const char *start, *split, *end, *body_end;
	SoupMessageHeaders *part_headers;
	GBytes *part_body;

	content_type = soup_message_headers_get_content_type (headers, &params);
	if (!content_type)
		return NULL;

	boundary = g_hash_table_lookup (params, "boundary");
	if (strncmp (content_type, "multipart/", 10) != 0 || !boundary) {
		g_hash_table_destroy (params);
		return NULL;
	}

	multipart = soup_multipart_new_internal (
		g_strdup (content_type), g_strdup (boundary));
	g_hash_table_destroy (params);

        gsize body_size;
        const char *body_data = g_bytes_get_data (body, &body_size);
	body_end = body_data + body_size;
	boundary = multipart->boundary;
	boundary_len = strlen (boundary);

	/* skip preamble */
	start = find_boundary (body_data, body_end,
			       boundary, boundary_len);
	if (!start) {
		soup_multipart_free (multipart);
		return NULL;
	}

	while (start[2 + boundary_len] != '-') {
		end = find_boundary (start + 2 + boundary_len, body_end,
				     boundary, boundary_len);
		if (!end) {
			soup_multipart_free (multipart);
			return NULL;
		}

		split = g_strstr_len (start, body_end - start, "\r\n\r\n");
		if (!split || split > end) {
			soup_multipart_free (multipart);
			return NULL;
		}
		split += 4;

		/* @start points to the start of the boundary line
		 * preceding this part, and @split points to the end
		 * of the headers / start of the body.
		 *
		 * We tell soup_headers_parse() to start parsing at
		 * @start, because it skips the first line of the
		 * input anyway (expecting it to be either a
		 * Request-Line or Status-Line).
		 */
		part_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
		g_ptr_array_add (multipart->headers, part_headers);
		if (!soup_headers_parse (start, split - 2 - start,
					 part_headers)) {
			soup_multipart_free (multipart);
			return NULL;
		}

		/* @split, as previously mentioned, points to the
		 * start of the body, and @end points to the start of
		 * the following boundary line, which is to say 2 bytes
		 * after the end of the body.
		 */
		part_body = g_bytes_new_from_bytes (body, // FIXME
						    split - body_data,
						    end - 2 >= split ? end - 2 - split : 0);
		g_ptr_array_add (multipart->bodies, part_body);

		start = end;
	}

	return multipart;
}

/**
 * soup_multipart_get_length:
 * @multipart: a #SoupMultipart
 *
 * Gets the number of body parts in @multipart.
 *
 * Returns: the number of body parts in @multipart
 **/
int
soup_multipart_get_length (SoupMultipart *multipart)
{
	return multipart->bodies->len;
}

/**
 * soup_multipart_get_part:
 * @multipart: a #SoupMultipart
 * @part: the part number to get (counting from 0)
 * @headers: (out) (transfer none): return location for the MIME part
 *   headers
 * @body: (out) (transfer none): return location for the MIME part
 *   body
 *
 * Gets the indicated body part from @multipart.
 *
 * Returns: %TRUE on success, %FALSE if @part is out of range (in
 *   which case @headers and @body won't be set)
 **/
gboolean
soup_multipart_get_part (SoupMultipart *multipart, int part,
			 SoupMessageHeaders **headers, GBytes **body)
{
	if (part < 0 || part >= multipart->bodies->len)
		return FALSE;
	*headers = multipart->headers->pdata[part];
	*body = multipart->bodies->pdata[part];
	return TRUE;
}

/**
 * soup_multipart_append_part:
 * @multipart: a #SoupMultipart
 * @headers: the MIME part headers
 * @body: the MIME part body
 *
 * Adds a new MIME part to @multipart with the given headers and body.
 *
 * (The multipart will make its own copies of @headers and @body, so
 * you should free your copies if you are not using them for anything
 * else.)
 **/
void
soup_multipart_append_part (SoupMultipart      *multipart,
			    SoupMessageHeaders *headers,
			    GBytes         *body)
{
	SoupMessageHeaders *headers_copy;
	SoupMessageHeadersIter iter;
	const char *name, *value;

	/* Copying @headers is annoying, but the alternatives seem
	 * worse:
	 *
	 * 1) We don't want to use g_boxed_copy, because
	 *    SoupMessageHeaders actually implements that as just a
	 *    ref, which would be confusing since SoupMessageHeaders
	 *    is mutable and the caller might modify @headers after
	 *    appending it.
	 *
	 * 2) We can't change SoupMessageHeaders to not just do a ref
	 *    from g_boxed_copy, because that would break language
	 *    bindings (which need to be able to hold a ref on
	 *    soup_message_get_request_headers (msg), but don't want
         *    to duplicate it).
	 *
	 * 3) We don't want to steal the reference to @headers,
	 *    because then we'd have to either also steal the
	 *    reference to @body (which would be inconsistent with
	 *    other GBytes methods), or NOT steal the reference to
	 *    @body, in which case there'd be inconsistency just
	 *    between the two arguments of this method!
	 */
	headers_copy = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	soup_message_headers_iter_init (&iter, headers);
	while (soup_message_headers_iter_next (&iter, &name, &value))
		soup_message_headers_append (headers_copy, name, value);

	g_ptr_array_add (multipart->headers, headers_copy);
	g_ptr_array_add (multipart->bodies, g_bytes_ref (body));
}

/**
 * soup_multipart_append_form_string:
 * @multipart: a multipart (presumably of type "multipart/form-data")
 * @control_name: the name of the control associated with @data
 * @data: the body data
 *
 * Adds a new MIME part containing @data to @multipart.
 *
 * Uses "Content-Disposition: form-data", as per the HTML forms specification.
 **/
void
soup_multipart_append_form_string (SoupMultipart *multipart,
				   const char *control_name, const char *data)
{
	GBytes *body;

	body = g_bytes_new (data, strlen (data));
	soup_multipart_append_form_file (multipart, control_name,
					 NULL, NULL, body);
	g_bytes_unref (body);
}

/**
 * soup_multipart_append_form_file:
 * @multipart: a multipart (presumably of type "multipart/form-data")
 * @control_name: the name of the control associated with this file
 * @filename: (nullable): the name of the file, or %NULL if not known
 * @content_type: (nullable): the MIME type of the file, or %NULL if not known
 * @body: the file data
 *
 * Adds a new MIME part containing @body to @multipart
 *
 * Uses "Content-Disposition: form-data", as per the HTML forms specification.
 **/
void
soup_multipart_append_form_file (SoupMultipart *multipart,
				 const char *control_name, const char *filename,
				 const char *content_type, GBytes *body)
{
	SoupMessageHeaders *headers;
	GString *disposition;

	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	disposition = g_string_new ("form-data; ");
	soup_header_g_string_append_param_quoted (disposition, "name", control_name);
	if (filename) {
		g_string_append (disposition, "; ");
		soup_header_g_string_append_param_quoted (disposition, "filename", filename);
	}
	soup_message_headers_append_common (headers, SOUP_HEADER_CONTENT_DISPOSITION,
                                            disposition->str);
	g_string_free (disposition, TRUE);

	if (content_type) {
		soup_message_headers_append_common (headers, SOUP_HEADER_CONTENT_TYPE,
                                                    content_type);
	}

	g_ptr_array_add (multipart->headers, headers);
	g_ptr_array_add (multipart->bodies, g_bytes_ref (body));
}

/**
 * soup_multipart_to_message:
 * @multipart: a #SoupMultipart
 * @dest_headers: the headers of the HTTP message to serialize @multipart to
 * @dest_body: (out): the body of the HTTP message to serialize @multipart to
 *
 * Serializes @multipart to @dest_headers and @dest_body.
 **/
void
soup_multipart_to_message (SoupMultipart      *multipart,
			   SoupMessageHeaders *dest_headers,
			   GBytes            **dest_body)
{
	SoupMessageHeaders *part_headers;
	GBytes *part_body;
	SoupMessageHeadersIter iter;
	const char *name, *value;
	GString *str;
	GHashTable *params;
	guint i;

	params = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (params, "boundary", multipart->boundary);
	soup_message_headers_set_content_type (dest_headers,
					       multipart->mime_type,
					       params);
	g_hash_table_destroy (params);

	str = g_string_new (NULL);

	for (i = 0; i < multipart->bodies->len; i++) {
		part_headers = multipart->headers->pdata[i];
		part_body = multipart->bodies->pdata[i];

		if (i > 0)
			g_string_append (str, "\r\n");
		g_string_append (str, "--");
		g_string_append (str, multipart->boundary);
		g_string_append (str, "\r\n");
		soup_message_headers_iter_init (&iter, part_headers);
		while (soup_message_headers_iter_next (&iter, &name, &value))
			g_string_append_printf (str, "%s: %s\r\n", name, value);
		g_string_append (str, "\r\n");
		g_string_append_len (str,
				     g_bytes_get_data (part_body, NULL),
				     g_bytes_get_size (part_body));
	}

	g_string_append (str, "\r\n--");
	g_string_append (str, multipart->boundary);
	g_string_append (str, "--\r\n");

	/* (The "\r\n" after the close-delimiter seems wrong according
	 * to my reading of RFCs 2046 and 2616, but that's what
	 * everyone else does.)
	 */

	*dest_body = g_string_free_to_bytes (str);
}

/**
 * soup_multipart_free:
 * @multipart: a #SoupMultipart
 *
 * Frees @multipart.
 **/
void
soup_multipart_free (SoupMultipart *multipart)
{
	g_free (multipart->mime_type);
	g_free (multipart->boundary);
	g_ptr_array_free (multipart->headers, TRUE);
	g_ptr_array_free (multipart->bodies, TRUE);

	g_slice_free (SoupMultipart, multipart);
}

static SoupMultipart *
soup_multipart_copy (SoupMultipart *multipart)
{
	SoupMultipart *copy;
	guint i;

	copy = soup_multipart_new_internal (g_strdup (multipart->mime_type),
					    g_strdup (multipart->boundary));
	for (i = 0; i < multipart->bodies->len; i++) {
		soup_multipart_append_part (copy,
					    multipart->headers->pdata[i],
					    multipart->bodies->pdata[i]);
	}
	return copy;
}

G_DEFINE_BOXED_TYPE (SoupMultipart, soup_multipart, soup_multipart_copy, soup_multipart_free)
