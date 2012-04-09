/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * tld-parser.c
 *
 * Copyright (C) 2012 Igalia S.L.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <glib/gprintf.h>
#include <gio/gio.h>
#include "soup-tld-private.h"

#define MAX_LINE_LENGTH 256

int
main(int argc, char **argv)
{
	GFile *tlds_file, *inc_file;
	GFileInputStream *file_reader;
	GFileOutputStream *file_writer;
	GDataInputStream *data_reader;
	char *rule;

	g_type_init ();

	tlds_file = g_file_new_for_path (argv[1]);
	file_reader = g_file_read (tlds_file, NULL, NULL);
	g_object_unref (tlds_file);

	if (!file_reader)
		return 1;

	data_reader = g_data_input_stream_new (G_INPUT_STREAM (file_reader));
	g_object_unref (file_reader);
	if (!data_reader)
		return 1;

	inc_file = g_file_new_for_path (argv[2]);
	file_writer = g_file_replace (inc_file, NULL, FALSE, G_FILE_CREATE_NONE, NULL, NULL);
	g_object_unref (inc_file);

	if (!file_writer) {
		g_object_unref (data_reader);
		return 1;
	}

	do {
		char *domain;
		gsize size;
		char output_line[MAX_LINE_LENGTH];
		guint flags;

		rule = g_data_input_stream_read_line (data_reader, &size, NULL, NULL);

		if (!rule)
			break;

		/* If the line is empty or is a comment then ignore. */
		if (!size || g_str_has_prefix (rule, "//")) {
			g_free (rule);
			continue;
		}

		flags = 0;
		domain = rule;
		/* Lines starting with '!' are exceptions to the rules */
		if (*rule == '!') {
			domain++;
			flags |= SOUP_TLD_RULE_EXCEPTION;
		}

		if (g_str_has_prefix (domain, "*.")) {
			domain += 2;
			flags |= SOUP_TLD_RULE_MATCH_ALL;
		}

		/* Skip the leading dot (is optional) */
		if (*domain == '.')
			domain++;

		size = g_snprintf (output_line, MAX_LINE_LENGTH, "{ \"%s\", %d },\n", g_strstrip(domain), flags);
		g_output_stream_write (G_OUTPUT_STREAM (file_writer), output_line, size, NULL, NULL);

		g_free (rule);

	} while (TRUE);

	g_object_unref (data_reader);
	g_object_unref (file_writer);

	return 0;
}
