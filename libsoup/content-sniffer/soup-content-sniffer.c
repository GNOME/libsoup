/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-content-sniffer.c
 *
 * Copyright (C) 2009, 2013 Gustavo Noronha Silva.
 *
 * This code implements the following specification:
 *
 *  http://mimesniff.spec.whatwg.org/ as of 11 June 2013
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-content-sniffer.h"
#include "soup-session-feature-private.h"
#include "soup-content-processor.h"
#include "soup-content-sniffer-stream.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-session-feature-private.h"

/**
 * SoupContentSniffer:
 *
 * Sniffs the mime type of messages.
 *
 * A [class@ContentSniffer] tries to detect the actual content type of
 * the files that are being downloaded by looking at some of the data
 * before the [class@Message] emits its [signal@Message::got-headers] signal.
 * [class@ContentSniffer] implements [iface@SessionFeature], so you can add
 * content sniffing to a session with [method@Session.add_feature] or
 * [method@Session.add_feature_by_type].
 **/

static void soup_content_sniffer_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

static SoupContentProcessorInterface *soup_content_sniffer_default_content_processor_interface;
static void soup_content_sniffer_content_processor_init (SoupContentProcessorInterface *interface, gpointer interface_data);

struct _SoupContentSniffer {
        GObject parent_instance;
};

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupContentSniffer, soup_content_sniffer, G_TYPE_OBJECT,
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						      soup_content_sniffer_session_feature_init)
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_CONTENT_PROCESSOR,
						      soup_content_sniffer_content_processor_init))


static GInputStream *
soup_content_sniffer_content_processor_wrap_input (SoupContentProcessor *processor,
						   GInputStream *base_stream,
						   SoupMessage *msg,
						   GError **error)
{
	return g_object_new (SOUP_TYPE_CONTENT_SNIFFER_STREAM,
			     "base-stream", base_stream,
			     "message", msg,
			     "sniffer", SOUP_CONTENT_SNIFFER (processor),
			     NULL);
}

static void
soup_content_sniffer_content_processor_init (SoupContentProcessorInterface *processor_interface,
                                            gpointer interface_data)
{
	soup_content_sniffer_default_content_processor_interface =
		g_type_default_interface_peek (SOUP_TYPE_CONTENT_PROCESSOR);

	processor_interface->processing_stage = SOUP_STAGE_BODY_DATA;
	processor_interface->wrap_input = soup_content_sniffer_content_processor_wrap_input;
}

static void
soup_content_sniffer_init (SoupContentSniffer *content_sniffer)
{
}

typedef struct {
	const guchar *mask;
	const guchar *pattern;
	guint         pattern_length;
	const char   *sniffed_type;
} SoupContentSnifferMediaPattern;

static char*
sniff_media (SoupContentSniffer *sniffer,
	     GBytes *buffer,
	     SoupContentSnifferMediaPattern table[],
	     int table_length)
{

        gsize resource_length;
        const guchar *resource = g_bytes_get_data (buffer, &resource_length);
        resource_length = MIN (512, resource_length);
	int i;

	for (i = 0; i < table_length; i++) {
		SoupContentSnifferMediaPattern *type_row = &(table[i]);
		guint j;

		if (resource_length < type_row->pattern_length)
			continue;

		for (j = 0; j < type_row->pattern_length; j++) {
			if ((type_row->mask[j] & resource[j]) != type_row->pattern[j])
				break;
		}

		/* This means our comparison above matched completely */
		if (j == type_row->pattern_length)
			return g_strdup (type_row->sniffed_type);
	}

	return NULL;
}

/* This table is based on the MIMESNIFF spec;
 * See 6.1 Matching an image type pattern
 */
static SoupContentSnifferMediaPattern image_types_table[] = {

	/* Windows icon signature. */
	{ (const guchar *)"\xFF\xFF\xFF\xFF",
	  (const guchar *)"\x00\x00\x01\x00",
	  4,
	  "image/x-icon" },

	/* Windows cursor signature. */
	{ (const guchar *)"\xFF\xFF\xFF\xFF",
	  (const guchar *)"\x00\x00\x02\x00",
	  4,
	  "image/x-icon" },

	/* BMP. */
	{ (const guchar *)"\xFF\xFF",
	  (const guchar *)"BM",
	  2,
	  "image/bmp" },

	/* GIFs. */
	{ (const guchar *)"\xFF\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"GIF87a",
	  6,
	  "image/gif" },

	{ (const guchar *)"\xFF\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"GIF89a",
	  6,
	  "image/gif" },

	/* WEBP. */
	{ (const guchar *)"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"RIFF\x00\x00\x00\x00WEBPVP",
	  14,
	  "image/webp" },

	/* PNG. */
	{ (const guchar *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"\x89PNG\x0D\x0A\x1A\x0A",
	  8,
	  "image/png" },

	/* JPEG. */
	{ (const guchar *)"\xFF\xFF\xFF",
	  (const guchar *)"\xFF\xD8\xFF",
	  3,
	  "image/jpeg" },
};

static char*
sniff_images (SoupContentSniffer *sniffer, GBytes *buffer)
{
	return sniff_media (sniffer,
			    buffer,
			    image_types_table,
			    G_N_ELEMENTS (image_types_table));
}

/* This table is based on the MIMESNIFF spec;
 * See 6.2 Matching an audio or video type pattern
 */
static SoupContentSnifferMediaPattern audio_video_types_table[] = {
	{ (const guchar *)"\xFF\xFF\xFF\xFF",
	  (const guchar *)"\x1A\x45\xDF\xA3",
	  4,
	  "video/webm" },

	{ (const guchar *)"\xFF\xFF\xFF\xFF",
	  (const guchar *)".snd",
	  4,
	  "audio/basic" },


	{ (const guchar *)"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
	  (const guchar *)"FORM\0\0\0\0AIFF",
	  12,
	  "audio/aiff" },

	{ (const guchar *)"\xFF\xFF\xFF",
	  (const guchar *)"ID3",
	  3,
	  "audio/mpeg" },

	{ (const guchar *)"\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"OggS\0",
	  5,
	  "application/ogg" },

	{ (const guchar *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"MThd\x00\x00\x00\x06",
	  8,
	  "audio/midi" },

	{ (const guchar *)"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
	  (const guchar *)"RIFF\x00\x00\x00\x00AVI ",
	  12,
	  "video/avi" },

	{ (const guchar *)"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
	  (const guchar *)"RIFF\x00\x00\x00\x00WAVE",
	  12,
	  "audio/wave" },
};

static gboolean
data_has_prefix (const char *data, const char *prefix, gsize max_length)
{
        if (strlen (prefix) > max_length)
                return FALSE;

        return memcmp (data, prefix, strlen (prefix)) == 0;
}

static gboolean
sniff_mp4 (SoupContentSniffer *sniffer, GBytes *buffer)
{
	gsize resource_length;
	const char *resource = g_bytes_get_data (buffer, &resource_length);
	resource_length = MIN (512, resource_length);
	guint32 box_size;
	guint i;

        if (resource_length < sizeof (guint32))
                return FALSE;

	box_size = *((guint32*)resource);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	box_size = ((box_size >> 24) |
		    ((box_size << 8) & 0x00FF0000) |
		    ((box_size >> 8) & 0x0000FF00) |
		    (box_size << 24));
#endif

	if (resource_length < 12 || resource_length < box_size || box_size % 4 != 0)
		return FALSE;

	if (!data_has_prefix (resource + 4, "ftyp", resource_length - 4))
		return FALSE;

	if (!data_has_prefix (resource + 8, "mp4", resource_length - 8))
		return FALSE;

	for (i = 16; i < box_size && i < resource_length; i = i + 4) {
		if (data_has_prefix (resource + i, "mp4", resource_length - i))
			return TRUE;
	}

	return FALSE;
}

static char*
sniff_audio_video (SoupContentSniffer *sniffer, GBytes *buffer)
{
	char *sniffed_type;

	sniffed_type = sniff_media (sniffer,
				    buffer,
				    audio_video_types_table,
				    G_N_ELEMENTS (audio_video_types_table));

	if (sniffed_type != NULL)
		return sniffed_type;

	if (sniff_mp4 (sniffer, buffer))
		return g_strdup ("video/mp4");

	return NULL;
}

/* This table is based on the MIMESNIFF spec;
 * See 7.1 Identifying a resource with an unknown MIME type
 */
typedef struct {
	/* @has_ws is TRUE if @pattern contains "generic" whitespace */
	gboolean      has_ws;
	/* @has_tag_termination is TRUE if we should check for a tag-terminating
	 * byte (0x20 " " or 0x3E ">") after the pattern match.
	 */
	gboolean      has_tag_termination;
	const guchar *mask;
	const guchar *pattern;
	guint         pattern_length;
	const char   *sniffed_type;
	gboolean      scriptable;
} SoupContentSnifferPattern;


/* When has_ws is TRUE, spaces in the pattern will indicate where insignificant space
 * is allowed. Those spaces are marked with \x00 on the mask.
 */
static SoupContentSnifferPattern types_table[] = {
	/* Scriptable types. */

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xFF\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xFF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <!DOCTYPE HTML",
	  14,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <HTML",
	  5,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <HEAD",
	  5,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <SCRIPT",
	  7,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <IFRAME",
	  7,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xFF",
	  (const guchar *)" <H1",
	  3,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF",
	  (const guchar *)" <DIV",
	  4,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <FONT",
	  5,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <TABLE",
	  6,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF",
	  (const guchar *)" <A",
	  2,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <STYLE",
	  6,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <TITLE",
	  6,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF",
	  (const guchar *)" <B",
	  2,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF\xDF\xDF",
	  (const guchar *)" <BODY",
	  5,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF\xDF",
	  (const guchar *)" <BR",
	  3,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xDF",
	  (const guchar *)" <P",
	  2,
	  "text/html",
	  TRUE },

	{ TRUE, TRUE,
	  (const guchar *)"\x00\xFF\xFF\xFF\xFF",
	  (const guchar *)" <!--",
	  4,
	  "text/html",
	  TRUE },

	{ TRUE, FALSE,
	  (const guchar *)"\x00\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)" <?xml",
	  5,
	  "text/xml",
	  TRUE },

	{ FALSE, FALSE,
	  (const guchar *)"\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"%PDF-",
	  5,
	  "application/pdf",
	  TRUE },

	/* Non-scriptable types. */
	{ FALSE, FALSE,
	  (const guchar *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
	  (const guchar *)"%!PS-Adobe-",
	  11,
	  "application/postscript",
	  FALSE },

	{ FALSE, FALSE, /* UTF-16BE BOM */
	  (const guchar *)"\xFF\xFF\x00\x00",
	  (const guchar *)"\xFE\xFF\x00\x00",
	  4,
	  "text/plain",
	  FALSE },

	{ FALSE, FALSE, /* UTF-16LE BOM */
	  (const guchar *)"\xFF\xFF\x00\x00",
	  (const guchar *)"\xFF\xFE\x00\x00",
	  4,
	  "text/plain",
	  FALSE },

	{ FALSE, FALSE, /* UTF-8 BOM */
	  (const guchar *)"\xFF\xFF\xFF\x00",
	  (const guchar *)"\xEF\xBB\xBF\x00",
	  4,
	  "text/plain",
	  FALSE },
};

/* Whether a given byte looks like it might be part of binary content.
 * Source: HTML5 spec; borrowed from the Chromium mime sniffer code,
 * which is BSD-licensed
 */
static char byte_looks_binary[] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1,  /* 0x00 - 0x0F */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,  /* 0x10 - 0x1F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x20 - 0x2F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x30 - 0x3F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x40 - 0x4F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x50 - 0x5F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x60 - 0x6F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x70 - 0x7F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x80 - 0x8F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0x90 - 0x9F */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0xA0 - 0xAF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0xB0 - 0xBF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0xC0 - 0xCF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0xD0 - 0xDF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0xE0 - 0xEF */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* 0xF0 - 0xFF */
};

/* HTML5: 2.7.4 Content-Type sniffing: unknown type */
static char*
sniff_unknown (SoupContentSniffer *sniffer, GBytes *buffer,
	       gboolean sniff_scriptable)
{
	char *sniffed_type = NULL;
	gsize resource_length;
	const guchar *resource = g_bytes_get_data (buffer, &resource_length);
	resource_length = MIN (512, resource_length);
	guint i;

        if (resource_length == 0)
                return g_strdup ("text/plain");

	for (i = 0; i < G_N_ELEMENTS (types_table); i++) {
		SoupContentSnifferPattern *type_row = &(types_table[i]);

		if (!sniff_scriptable && type_row->scriptable)
			continue;

		if (type_row->has_ws) {
			guint index_stream = 0;
			guint index_pattern = 0;
			gboolean skip_row = FALSE;

			while ((index_stream < resource_length - 1) &&
			       (index_pattern <= type_row->pattern_length)) {
				/* Skip insignificant white space ("WS" in the spec) */
				if (type_row->pattern[index_pattern] == ' ') {
					if (resource[index_stream] == '\x09' ||
					    resource[index_stream] == '\x0a' ||
					    resource[index_stream] == '\x0c' ||
					    resource[index_stream] == '\x0d' ||
					    resource[index_stream] == '\x20')
						index_stream++;
					else
						index_pattern++;
				} else {
					if ((type_row->mask[index_pattern] & resource[index_stream]) != type_row->pattern[index_pattern]) {
						skip_row = TRUE;
						break;
					}
					index_pattern++;
					index_stream++;
				}
			}

			if (skip_row)
				continue;

			if (index_pattern > type_row->pattern_length) {
				if (type_row->has_tag_termination &&
				    resource[index_stream] != '\x20' &&
				    resource[index_stream] != '\x3E')
					continue;

				return g_strdup (type_row->sniffed_type);
			}
		} else {
			guint j;

			if (resource_length < type_row->pattern_length)
				continue;

			for (j = 0; j < type_row->pattern_length; j++) {
				if ((type_row->mask[j] & resource[j]) != type_row->pattern[j])
					break;
			}

			/* This means our comparison above matched completely */
			if (j == type_row->pattern_length)
				return g_strdup (type_row->sniffed_type);
		}
	}

	sniffed_type = sniff_images (sniffer, buffer);

	if (sniffed_type != NULL)
		return sniffed_type;

	sniffed_type = sniff_audio_video (sniffer, buffer);

	if (sniffed_type != NULL)
		return sniffed_type;

	for (i = 0; i < resource_length; i++) {
		if (byte_looks_binary[resource[i]])
			return g_strdup ("application/octet-stream");
	}

	return g_strdup ("text/plain");
}

/* MIMESNIFF: 7.2 Sniffing a mislabeled binary resource */
static char*
sniff_text_or_binary (SoupContentSniffer *sniffer, GBytes *buffer)
{
	gsize resource_length;
	const guchar *resource = g_bytes_get_data (buffer, &resource_length);
	resource_length = MIN (512, resource_length);
	gboolean looks_binary = FALSE;
	int i;

	/* 2. Detecting UTF-16BE, UTF-16LE BOMs means it's text/plain */
	if (resource_length >= 2) {
		if ((resource[0] == 0xFE && resource[1] == 0xFF) ||
		    (resource[0] == 0xFF && resource[1] == 0xFE))
			return g_strdup ("text/plain");
	}

	/* 3. UTF-8 BOM. */
	if (resource_length >= 3) {
		if (resource[0] == 0xEF && resource[1] == 0xBB && resource[2] == 0xBF)
			return g_strdup ("text/plain");
	}

	/* 4. Look to see if any of the first n bytes looks binary */
	for (i = 0; i < resource_length; i++) {
		if (byte_looks_binary[resource[i]]) {
			looks_binary = TRUE;
			break;
		}
	}

	if (!looks_binary)
		return g_strdup ("text/plain");

	/* 5. Execute 7.1 Identifying a resource with an unknown MIME type.
	 * TODO: sniff-scriptable needs to be unset.
	 */
	return sniff_unknown (sniffer, buffer, TRUE);
}

static gboolean
skip_insignificant_space (const char *resource, gsize *pos, gsize resource_length)
{
        if (*pos >= resource_length)
	        return TRUE;

	while ((resource[*pos] == '\x09') ||
	       (resource[*pos] == '\x20') ||
	       (resource[*pos] == '\x0A') ||
	       (resource[*pos] == '\x0D')) {
		*pos = *pos + 1;

		if (*pos >= resource_length)
			return TRUE;
	}

	return FALSE;
}

static char*
sniff_feed_or_html (SoupContentSniffer *sniffer, GBytes *buffer)
{
	gsize resource_length;
	const char *resource = g_bytes_get_data (buffer, &resource_length);
	resource_length = MIN (512, resource_length);
	gsize pos = 0;

	if (resource_length < 3)
		goto text_html;

	/* Skip a leading UTF-8 BOM */
	if ((guchar)resource[0] == 0xEF && (guchar)resource[1] == 0xBB && (guchar)resource[2] == 0xBF)
		pos = 3;

 look_for_tag:
	if (skip_insignificant_space (resource, &pos, resource_length))
		goto text_html;

	if (resource[pos] != '<')
		return g_strdup ("text/html");

	pos++;

	if ((pos + 2) > resource_length)
		goto text_html;

	/* Skip comments. */
	if (data_has_prefix (resource + pos, "!--", resource_length - pos)) {
		pos = pos + 3;

		if ((pos + 2) > resource_length)
			goto text_html;

		while (!data_has_prefix (resource + pos, "-->", resource_length - pos)) {
			pos++;

			if ((pos + 2) > resource_length)
				goto text_html;
		}

		pos = pos + 3;

		goto look_for_tag;
	}

	if (pos > resource_length)
		goto text_html;

	if (resource[pos] == '!') {
		do {
			pos++;

			if ((pos + 1) > resource_length)
				goto text_html;
		} while (resource[pos] != '>');

		pos++;

		goto look_for_tag;
	} else if (resource[pos] == '?') {
		do {
			pos++;

			if ((pos + 1) > resource_length)
				goto text_html;
		} while (!data_has_prefix (resource + pos, "?>", resource_length - pos));

		pos = pos + 2;

		goto look_for_tag;
	}

	if ((pos + 3) > resource_length)
		goto text_html;

	if (data_has_prefix (resource + pos, "rss", resource_length - pos))
		return g_strdup ("application/rss+xml");

	if ((pos + 4) > resource_length)
		goto text_html;

	if (data_has_prefix (resource + pos, "feed", resource_length - pos))
		return g_strdup ("application/atom+xml");

	if ((pos + 7) > resource_length)
		goto text_html;

	if (data_has_prefix (resource + pos, "rdf:RDF", resource_length - pos)) {
		pos = pos + 7;

		if (skip_insignificant_space (resource, &pos, resource_length))
			goto text_html;

		if ((pos + 32) > resource_length)
			goto text_html;

		if (data_has_prefix (resource + pos, "xmlns=\"http://purl.org/rss/1.0/\"", resource_length - pos)) {
			pos = pos + 32;

			if (skip_insignificant_space (resource, &pos, resource_length))
				goto text_html;

			if ((pos + 55) > resource_length)
				goto text_html;

			if (data_has_prefix (resource + pos, "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"", resource_length - pos))
				return g_strdup ("application/rss+xml");
		}

		if ((pos + 55) > resource_length)
			goto text_html;

		if (data_has_prefix (resource + pos, "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"", resource_length - pos)) {
			pos = pos + 55;

			if (skip_insignificant_space (resource, &pos, resource_length))
				goto text_html;

			if ((pos + 32) > resource_length)
				goto text_html;

			if (data_has_prefix (resource + pos, "xmlns=\"http://purl.org/rss/1.0/\"", resource_length - pos))
				return g_strdup ("application/rss+xml");
		}
	}

 text_html:
	return g_strdup ("text/html");
}

/**
 * soup_content_sniffer_sniff:
 * @sniffer: a #SoupContentSniffer
 * @msg: the message to sniff
 * @buffer: a buffer containing the start of @msg's response body
 * @params: (element-type utf8 utf8) (out) (transfer full) (nullable): return
 *   location for Content-Type parameters (eg, "charset"), or %NULL
 *
 * Sniffs @buffer to determine its Content-Type.
 *
 * The result may also be influenced by the Content-Type declared in @msg's
 * response headers.
 *
 * Returns: the sniffed Content-Type of @buffer; this will never be %NULL,
 *   but may be `application/octet-stream`.
 */
char *
soup_content_sniffer_sniff (SoupContentSniffer *sniffer, SoupMessage *msg,
			    GBytes *buffer, GHashTable **params)
{
	const char *content_type;
	const char *x_content_type_options;
	char *sniffed_type = NULL;
	gboolean no_sniff = FALSE;

	content_type = soup_message_headers_get_content_type (soup_message_get_response_headers (msg), params);

	/* MIMESNIFF: 7 Determining the sniffed MIME type of a resource. */

	x_content_type_options = soup_message_headers_get_one_common (soup_message_get_response_headers (msg), SOUP_HEADER_X_CONTENT_TYPE_OPTIONS);
	if (!g_strcmp0 (x_content_type_options, "nosniff"))
		no_sniff = TRUE;

	/* 1. Unknown/undefined supplied type with sniff-scritable = !nosniff. */
	if ((content_type == NULL) ||
	    !g_ascii_strcasecmp (content_type, "unknown/unknown") ||
	    !g_ascii_strcasecmp (content_type, "application/unknown") ||
	    !g_ascii_strcasecmp (content_type, "*/*"))
		return sniff_unknown (sniffer, buffer, !no_sniff);

	/* 2. If nosniff is specified in X-Content-Type-Options use the supplied MIME type. */
	if (no_sniff)
		return g_strdup (content_type);

	/* 3. check-for-apache-bug */
	if ((content_type != NULL) &&
	    (g_str_equal (content_type, "text/plain") ||
	     g_str_equal (content_type, "text/plain; charset=ISO-8859-1") ||
	     g_str_equal (content_type, "text/plain; charset=iso-8859-1") ||
	     g_str_equal (content_type, "text/plain; charset=UTF-8")))
		return sniff_text_or_binary (sniffer, buffer);

	/* 4. XML types sent by the server are always used. */
	if (g_str_has_suffix (content_type, "+xml") ||
	    !g_ascii_strcasecmp (content_type, "text/xml") ||
	    !g_ascii_strcasecmp (content_type, "application/xml"))
		return g_strdup (content_type);

	/* 5. Distinguish feed from HTML. */
	if (!g_ascii_strcasecmp (content_type, "text/html"))
		return sniff_feed_or_html (sniffer, buffer);

	/* 6. Image types.
	 */
	if (!g_ascii_strncasecmp (content_type, "image/", 6)) {
		sniffed_type = sniff_images (sniffer, buffer);
		if (sniffed_type != NULL)
			return sniffed_type;
		return g_strdup (content_type);
	}

	/* 7. Audio and video types. */
	if (!g_ascii_strncasecmp (content_type, "audio/", 6) ||
	    !g_ascii_strncasecmp (content_type, "video/", 6) ||
	    !g_ascii_strcasecmp (content_type, "application/ogg")) {
	        sniffed_type = sniff_audio_video (sniffer, buffer);
	        if (sniffed_type != NULL)
		        return sniffed_type;
		return g_strdup (content_type);
        }

	/* If we got text/plain, use text_or_binary */
	if (g_str_equal (content_type, "text/plain")) {
		return sniff_text_or_binary (sniffer, buffer);
	}

	return g_strdup (content_type);
}

static void
soup_content_sniffer_request_queued (SoupSessionFeature *feature,
				     SoupMessage        *msg)
{
	soup_message_set_content_sniffer (msg, SOUP_CONTENT_SNIFFER (feature));
}

static void
soup_content_sniffer_request_unqueued (SoupSessionFeature *feature,
				       SoupMessage        *msg)
{
	soup_message_set_content_sniffer (msg, NULL);
}

static void
soup_content_sniffer_class_init (SoupContentSnifferClass *content_sniffer_class)
{
}

static void
soup_content_sniffer_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					   gpointer interface_data)
{
	feature_interface->request_queued = soup_content_sniffer_request_queued;
	feature_interface->request_unqueued = soup_content_sniffer_request_unqueued;
}

/**
 * soup_content_sniffer_new:
 *
 * Creates a new [class@ContentSniffer].
 *
 * Returns: a new #SoupContentSniffer
 **/
SoupContentSniffer *
soup_content_sniffer_new (void)
{
	return g_object_new (SOUP_TYPE_CONTENT_SNIFFER, NULL);
}
