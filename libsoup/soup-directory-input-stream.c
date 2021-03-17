/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008, 2010 Red Hat, Inc.
 * Copyright (C) 2010 Igalia, S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup-directory-input-stream.h"
#include "soup.h"

#define ROW_FORMAT  "<td sortable-data=\"%s\"><a href=\"%s\">%s</a></td><td align=\"right\" sortable-data=\"%" G_GOFFSET_FORMAT "\">%s</td><td align=\"right\" sortable-data=\"%" G_GINT64_FORMAT "\">%s&ensp;%s</td>\n"
#define EXIT_STRING "</table>\n</html>\n"

G_DEFINE_TYPE (SoupDirectoryInputStream, soup_directory_input_stream, G_TYPE_INPUT_STREAM)

static SoupBuffer *
soup_directory_input_stream_parse_info (SoupDirectoryInputStream *stream,
					GFileInfo *info)
{
	SoupBuffer *buffer;
	GString *string;
	const char *file_name;
	char *escaped, *path, *xml_string, *size, *date, *time, *name;
	goffset raw_size;
	gint64 timestamp;
#if !GLIB_CHECK_VERSION (2, 61, 2)
	GTimeVal modified;
#endif
	GDateTime *modification_time;

	if (!g_file_info_get_name (info))
		return NULL;

	file_name = g_file_info_get_display_name (info);
	if (!file_name) {
		file_name = g_file_info_get_name (info);
		/* FIXME: convert somehow? */
		if (!g_utf8_validate (file_name, -1, NULL))
			return NULL;
	}
	string = g_string_new ("<tr>");

	xml_string = g_markup_escape_text (file_name, -1);
	escaped = g_uri_escape_string (file_name, NULL, FALSE);
	path = g_strconcat (stream->uri, G_DIR_SEPARATOR_S, escaped, NULL);
	raw_size = g_file_info_get_size (info);

	if (g_file_info_get_file_type (info) == G_FILE_TYPE_REGULAR)
		size = g_format_size (raw_size);
	else
		size = g_strdup("");

	if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
		name = g_strdup_printf("1.%s", path);
	else
		name = g_strdup_printf("%s", path);

#if GLIB_CHECK_VERSION (2, 61, 2)
	modification_time = g_file_info_get_modification_date_time (info);
#else
	g_file_info_get_modification_time (info, &modified);
	modification_time = g_date_time_new_from_timeval_local (&modified);
#endif
	time = g_date_time_format (modification_time, "%X");
	date = g_date_time_format (modification_time, "%x");
	timestamp = g_date_time_to_unix (modification_time);
	g_date_time_unref (modification_time);

	g_string_append_printf (string, ROW_FORMAT, name, path, xml_string, raw_size, size, timestamp, time, date);
	g_string_append (string, "</tr>\n");
	buffer = soup_buffer_new (SOUP_MEMORY_TAKE, string->str, string->len);

	g_free (time);
	g_free (date);
	g_free (escaped);
	g_free (size);
	g_free (name);
	g_free (path);
	g_free (xml_string);
	g_string_free (string, FALSE);

	return buffer;
}

static SoupBuffer *
soup_directory_input_stream_read_next_file (SoupDirectoryInputStream  *stream,
					    GCancellable              *cancellable,
					    GError                   **error)
{
	GFileInfo *info;
	SoupBuffer *buffer;
	GError *err = NULL;

	do {
		info = g_file_enumerator_next_file (stream->enumerator, cancellable, &err);
		if (info == NULL) {
			if (err) {
				g_propagate_error (error, err);
				return NULL;
			} else if (!stream->done) {
				stream->done = TRUE;
				return soup_buffer_new (SOUP_MEMORY_STATIC,
							EXIT_STRING,
							sizeof (EXIT_STRING));
			} else {
				return NULL;
			}
		}

		buffer = soup_directory_input_stream_parse_info (stream, info);
		g_object_unref (info);
	} while (buffer == NULL);

	return buffer;
}

static gssize
soup_directory_input_stream_read (GInputStream  *input,
				  void          *buffer,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupDirectoryInputStream *stream = SOUP_DIRECTORY_INPUT_STREAM (input);
	gsize total, size;

	for (total = 0; total < count; total += size) {
		if (stream->buffer == NULL) {
			stream->buffer = soup_directory_input_stream_read_next_file (stream, cancellable, error);
			if (stream->buffer == NULL) {
				/* FIXME: Is this correct or should we forward the error? */
				if (total)
					g_clear_error (error);
				return total;
			}
		}

		size = MIN (stream->buffer->length, count - total);
		memcpy ((char *)buffer + total, stream->buffer->data, size);
		if (size == stream->buffer->length) {
			soup_buffer_free (stream->buffer);
			stream->buffer = NULL;
		} else {
			SoupBuffer *sub = soup_buffer_new_subbuffer (stream->buffer,
								     size,
								     stream->buffer->length - size);
			soup_buffer_free (stream->buffer);
			stream->buffer = sub;
		}
	}

	return total;
}

static gboolean
soup_directory_input_stream_close (GInputStream  *input,
				   GCancellable  *cancellable,
				   GError       **error)
{
	SoupDirectoryInputStream *stream = SOUP_DIRECTORY_INPUT_STREAM (input);
	gboolean result;

	if (stream->buffer) {
		soup_buffer_free (stream->buffer);
		stream->buffer = NULL;
	}

	result = g_file_enumerator_close (stream->enumerator,
					  cancellable,
					  error);
	g_object_unref (stream->enumerator);
	stream->enumerator = NULL;

	g_free (stream->uri);
	stream->uri = NULL;

	return result;
}

static void
soup_directory_input_stream_class_init (SoupDirectoryInputStreamClass *stream_class)
{
	GInputStreamClass *inputstream_class = G_INPUT_STREAM_CLASS (stream_class);

	inputstream_class->read_fn = soup_directory_input_stream_read;
	inputstream_class->close_fn = soup_directory_input_stream_close;
}

static
char *soup_directory_input_stream_create_header (SoupDirectoryInputStream *stream)
{
	char *header;
	GBytes *css = g_resources_lookup_data ("/org/gnome/libsoup/directory.css", G_RESOURCE_LOOKUP_FLAGS_NONE, NULL);
	GBytes *js = g_resources_lookup_data ("/org/gnome/libsoup/directory.js", G_RESOURCE_LOOKUP_FLAGS_NONE, NULL);

	header = g_strdup_printf ("<html><head>" \
                            "<title>%s</title>" \
                            "<meta http-equiv=\"Content-Type\" content=\"text/html;\" charset=\"UTF-8\">" \
                            "<style>%s</style>" \
                            "<script>%s</script>" \
                            "</head>" \
                            "<body>" \
                            "<table>" \
                            "<thead>" \
                            "<th align=\"left\">%s</th><th align=\"right\">%s</th><th align=\"right\">%s</th>" \
                            "</thead>",
                            stream->uri,
                            css ? (gchar *)g_bytes_get_data (css, NULL) : "",
                            js ? (gchar *)g_bytes_get_data (js, NULL) : "",
                            _("Name"),
                            _("Size"),
                            _("Date Modified"));
	return header;
}

static void
soup_directory_input_stream_init (SoupDirectoryInputStream *stream)
{
}

static void
soup_directory_input_stream_setup_buffer (SoupDirectoryInputStream *stream)
{
	char *init = soup_directory_input_stream_create_header (stream);

	stream->buffer = soup_buffer_new (SOUP_MEMORY_TAKE,
					  init,
					  strlen (init));
}

GInputStream *
soup_directory_input_stream_new (GFileEnumerator *enumerator,
				 SoupURI         *uri)
{
	GInputStream *stream;

	g_return_val_if_fail (G_IS_FILE_ENUMERATOR (enumerator), NULL);
	g_return_val_if_fail (uri != NULL, NULL);

	stream = g_object_new (SOUP_TYPE_DIRECTORY_INPUT_STREAM, NULL);

	SOUP_DIRECTORY_INPUT_STREAM (stream)->enumerator = g_object_ref (enumerator);
	SOUP_DIRECTORY_INPUT_STREAM (stream)->uri = soup_uri_to_string (uri, FALSE);

	soup_directory_input_stream_setup_buffer (SOUP_DIRECTORY_INPUT_STREAM (stream));

	return stream;
}
