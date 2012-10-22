/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static GMainLoop *loop;
static int nlookups = 0;

static void
resolve_callback (SoupAddress *addr, guint status, gpointer data)
{
	if (status == SOUP_STATUS_OK) {
		g_print ("Name:    %s\n", soup_address_get_name (addr));
		g_print ("Address: %s\n", soup_address_get_physical (addr));
	} else {
		g_print ("Name:    %s\n", soup_address_get_name (addr));
		g_print ("Error:   %s\n", soup_status_get_phrase (status));
	}
	g_print ("\n");

	g_object_unref (addr);

	nlookups--;
	if (nlookups == 0)
		g_main_loop_quit (loop);
}

static void
usage (void)
{
	g_printerr ("Usage: dns hostname ...\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	SoupAddress *addr;
	int i;

	if (argc < 2)
		usage ();

	for (i = 1; i < argc; i++) {
		addr = soup_address_new (argv[i], 0);
		if (!addr) {
			g_printerr ("Could not parse address %s\n", argv[1]);
			exit (1);
		}

		soup_address_resolve_async (addr, NULL, NULL,
					    resolve_callback, NULL);
		nlookups++;
	}

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
