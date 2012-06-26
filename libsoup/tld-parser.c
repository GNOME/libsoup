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
	gboolean ret = FALSE;
	GError *local_error = NULL;
	GError **error = &local_error;
	GFile *tlds_file = NULL;
	GFile *inc_file = NULL;
	GFileInputStream *file_reader = NULL;
	GFileOutputStream *file_writer = NULL;
	GDataInputStream *data_reader = NULL;
	char *rule = NULL;

	g_type_init ();

	tlds_file = g_file_new_for_path (argv[1]);
	file_reader = g_file_read (tlds_file, NULL, error);
	if (!file_reader)
		goto out;

	data_reader = g_data_input_stream_new (G_INPUT_STREAM (file_reader));

	inc_file = g_file_new_for_path (argv[2]);
	file_writer = g_file_replace (inc_file, NULL, FALSE, G_FILE_CREATE_NONE, NULL, error);
	if (!file_writer)
		goto out;

	do {
		char *domain;
		gsize size;
		char output_line[MAX_LINE_LENGTH];
		guint flags;
		GError *temp_error = NULL;

		g_free (rule);
		rule = g_data_input_stream_read_line (data_reader, &size, NULL, &temp_error);
		if (temp_error) {
			g_propagate_error (error, temp_error);
			goto out;
		}
		if (rule == NULL)
			break;

		/* If the line is empty or is a comment then ignore. */
		if (!size || g_str_has_prefix (rule, "//"))
			continue;

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
		if (!g_output_stream_write (G_OUTPUT_STREAM (file_writer), output_line, size, NULL, error))
			goto out;
	} while (TRUE);

	ret = TRUE;
 out:
	if (local_error) {
		g_printerr ("%s\n", local_error->message);
		g_clear_error (&local_error);
	}
	g_free (rule);
	g_clear_object (&tlds_file);
	g_clear_object (&inc_file);
	g_clear_object (&file_reader);
	g_clear_object (&data_reader);
	g_clear_object (&file_writer);

	return ret ? 0 : 1;
}
