#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include "libsoup/soup-address.h"

GMainLoop *loop;

static void
resolve_callback (SoupAddress *addr, guint status, gpointer data)
{
	if (status != SOUP_STATUS_OK) {
		fprintf (stderr, "%s\n", soup_status_get_phrase (status));
		exit (1);
	}

	printf ("Name:    %s\n", soup_address_get_name (addr));
	printf ("Address: %s\n", soup_address_get_physical (addr));
	g_main_loop_quit (loop);
}

static void
usage (void)
{
	fprintf (stderr, "Usage: dns [hostname | -r IP]\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	SoupAddress *addr;

	if (argc != 2)
		usage ();

	g_type_init ();
	g_thread_init (NULL);

	addr = soup_address_new (argv[1], 0);
	if (!addr) {
		fprintf (stderr, "Could not parse address %s\n", argv[1]);
		exit (1);
	}

	soup_address_resolve_async (addr, resolve_callback, NULL);

	loop = g_main_loop_new (NULL, TRUE);
	g_main_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
