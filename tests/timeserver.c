#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libsoup/soup.h>

int
main (int argc, char **argv)
{
	SoupSocket *listener, *client;
	SoupAddress *addr;
	guint port;
	time_t now;
	char *timebuf;
	GIOChannel *chan;
	gsize wrote;

	g_type_init ();

	if (argc >=2 && !strcmp (argv[1], "-6")) {
		addr = soup_address_ipv6_any ();
		if (!addr) {
			fprintf (stderr, "No IPv6 support\n");
			exit (1);
		}
		argc--;
		argv++;
	} else
		addr = soup_address_ipv4_any ();

	if (argc > 2) {
		fprintf (stderr, "Usage: %s [-6] [port]\n", argv[0]);
		exit (1);
	}

	if (argc == 2)
		port = atoi (argv[1]);
	else
		port = SOUP_SERVER_ANY_PORT;
	listener = soup_socket_server_new (addr, port);
	g_object_unref (addr);
	if (!listener) {
		fprintf (stderr, "Could not create listening socket\n");
		exit (1);
	}
	printf ("Listening on port %d\n", soup_socket_get_port (listener));

	while ((client = soup_socket_server_accept (listener))) {
		addr = soup_socket_get_address (client);
		printf ("got connection from %s port %d\n",
			soup_address_get_name_sync (addr),
			soup_socket_get_port (client));
		g_object_unref (addr);

		now = time (NULL);
		timebuf = ctime (&now);

		chan = soup_socket_get_iochannel (client);
		g_io_channel_write (chan, timebuf, strlen (timebuf), &wrote);
		g_io_channel_unref (chan);

		g_object_unref (client);
	}

	g_object_unref (listener);
	return 0;
}
