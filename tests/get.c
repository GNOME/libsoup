#include <stdio.h>
#include <stdlib.h>
#include <libsoup/soup.h>

int
main (int argc, char **argv)
{
	SoupContext *ctx;
	SoupMessage *msg;

	if (argc != 2) {
		fprintf (stderr, "Usage: %s URL\n", argv[0]);
		exit (1);
	}

	ctx = soup_context_get (argv[1]);
	if (!ctx) {
		fprintf (stderr, "Could not parse '%s' as a URL\n", argv[1]);
		exit (1);
	}

	msg = soup_message_new (ctx, SOUP_METHOD_GET);
	soup_context_unref (ctx);

	soup_message_send (msg);

	printf ("%d %s\n", msg->errorcode, msg->errorphrase);
	if (SOUP_ERROR_IS_SUCCESSFUL (msg->errorcode)) {
		fwrite (msg->response.body, msg->response.length, 1, stdout);
		printf ("\n");
	}

	soup_message_free (msg);
	return 0;
}
