/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-coding.c: Data encoding/decoding class
 *
 * Copyright (C) 2005 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-coding.h"
#include "soup-enum-types.h"
#include "soup-session-feature.h"

static void soup_coding_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupCoding, soup_coding, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_coding_session_feature_init))

enum {
	PROP_0,

	PROP_DIRECTION,

	LAST_PROP
};

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static SoupBuffer *apply (SoupCoding *coding,
			  gconstpointer input, gsize input_length,
			  gboolean done, GError **error);

static void
soup_coding_class_init (SoupCodingClass *coding_class)
{
	GObjectClass *object_class = (GObjectClass *)coding_class;

	object_class->set_property = set_property;
	object_class->get_property = get_property;

	coding_class->apply = apply;

	/* properties */
	g_object_class_install_property (
		object_class, PROP_DIRECTION,
#if 0
		g_param_spec_enum (SOUP_CODING_DIRECTION,
#else
		g_param_spec_uint (SOUP_CODING_DIRECTION,
#endif
				   "Direction",
				   "Whether to encode or decode",
				   0, 2,
				   SOUP_CODING_ENCODE,
				   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
soup_coding_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				  gpointer interface_data)
{
	;
}

static void
soup_coding_init (SoupCoding *coding)
{
	;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupCoding *coding = SOUP_CODING (object);

	switch (prop_id) {
	case PROP_DIRECTION:
#if 0
		coding->direction = g_value_get_enum (value);
#else
		coding->direction = g_value_get_uint (value);
#endif
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupCoding *coding = SOUP_CODING (object);

	switch (prop_id) {
	case PROP_DIRECTION:
#if 0
		g_value_set_enum (value, coding->direction);
#else
		g_value_set_uint (value, coding->direction);
#endif
		break;
	default:
		break;
	}
}

static SoupBuffer *
apply (SoupCoding *coding,
       gconstpointer input, gsize input_length,
       gboolean done, GError **error)
{
	gsize outbuf_length, outbuf_used, outbuf_cur, input_used, input_cur;
	char *outbuf;
	SoupCodingStatus status;

	if (coding->direction == SOUP_CODING_ENCODE)
		outbuf_length = MAX (input_length / 2, 1024);
	else
		outbuf_length = MAX (input_length * 2, 1024);
	outbuf = g_malloc (outbuf_length);
	outbuf_cur = input_cur = 0;

	do {
		status = soup_coding_apply_into (
			coding,
			(guchar *)input + input_cur, input_length - input_cur,
			&input_used,
			outbuf + outbuf_cur, outbuf_length - outbuf_cur,
			&outbuf_used,
			done, error);
		input_cur += input_used;
		outbuf_cur += outbuf_used;

		switch (status) {
		case SOUP_CODING_STATUS_OK:
		case SOUP_CODING_STATUS_COMPLETE:
			break;

		case SOUP_CODING_STATUS_NEED_SPACE:
			outbuf_length *= 2;
			outbuf = g_realloc (outbuf, outbuf_length);
			break;

		case SOUP_CODING_STATUS_ERROR:
		default:
			g_free (outbuf);
			return NULL;
		}
	} while (input_cur < input_length ||
		 (done && status != SOUP_CODING_STATUS_COMPLETE));

	if (outbuf_cur)
		return soup_buffer_new (SOUP_MEMORY_TAKE, outbuf, outbuf_cur);
	else {
		g_free (outbuf);
		return NULL;
	}
}

/**
 * soup_coding_apply:
 * @coding: a #SoupCoding
 * @input: input data
 * @input_length: length of @input
 * @done: %TRUE if this is the last piece of data to encode/decode
 * @error: error pointer
 *
 * Applies @coding to @input_length bytes of data from @input, and
 * returns a new #SoupBuffer containing the encoded/decoded data. If
 * @done is %FALSE, the encoder may buffer some or all of the data in
 * @input rather than outputting it right away. If @done is %TRUE, the
 * encoder will flush any buffered data, and (if possible) verify that
 * the input has reached the end of the stream.
 *
 * Return value: a #SoupBuffer containing the encoded/decoded data, or
 * %NULL if no data can be returned at this point, or if an error
 * occurred. (If you pass %NULL for @error, there is no way to
 * distinguish the latter two cases).
 **/
SoupBuffer *
soup_coding_apply (SoupCoding *coding,
		   gconstpointer input, gsize input_length,
		   gboolean done, GError **error)
{
	g_return_val_if_fail (SOUP_IS_CODING (coding), NULL);

	return SOUP_CODING_GET_CLASS (coding)->apply (
		coding, input, input_length, done, error);
}

/**
 * SoupCodingStatus:
 * @SOUP_CODING_STATUS_OK: Success
 * @SOUP_CODING_STATUS_ERROR: An error occurred
 * @SOUP_CODING_STATUS_NEED_SPACE: Output buffer was too small to
 * output any data.
 * @SOUP_CODING_STATUS_COMPLETE: The stream end has been reached and
 * the output buffer contains the last bytes of encoded/decoded data.
 *
 * The result from a call to soup_coding_apply_into().
 **/

/**
 * soup_coding_apply_into:
 * @coding: a #SoupCoding
 * @input: input data
 * @input_length: length of @input
 * @input_used: on return, contains the number of bytes of @input that
 * were encoded/decoded.
 * @output: output buffer
 * @output_length: length of @output
 * @output_used: on return, contains the number of bytes of @output that
 * were filled with encoded/decoded data.
 * @done: %TRUE if this is the last piece of data to encode/decode
 * @error: error pointer
 *
 * Applies @coding to @input_length bytes of data from @input, and
 * outputs between %0 and @output_length encoded/decoded bytes into
 * @output. @input and @output may not overlap.
 *
 * Return value: the status; %SOUP_CODING_STATUS_OK on intermediate
 * success, %SOUP_CODING_STATUS_COMPLETE if the stream has been fully
 * encoded/decoded, %SOUP_CODING_STATUS_NEED_SPACE if a larger
 * @output_length is required to make progress, or
 * %SOUP_CODING_STATUS_ERROR on error (in which case @error will be
 * set).
 **/
SoupCodingStatus
soup_coding_apply_into (SoupCoding *coding,
			gconstpointer input, gsize input_length, gsize *input_used,
			gpointer output, gsize output_length, gsize *output_used,
			gboolean done, GError **error)
{
	g_return_val_if_fail (SOUP_IS_CODING (coding), 0);

	return SOUP_CODING_GET_CLASS (coding)->apply_into (
		coding, input, input_length, input_used,
		output, output_length, output_used,
		done, error);
}

GQuark
soup_coding_error_quark (void)
{
	static GQuark error;
	if (!error)
		error = g_quark_from_static_string ("soup_coding_error_quark");
	return error;
}
