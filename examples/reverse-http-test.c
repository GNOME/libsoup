
#include "tests/test-utils.h"

#define APPLETV_IP   "192.168.0.42"
#define APPLETV_PORT "7000"
#define SESSION_ID "1bd6ceeb-fffd-456c-a09c-996053a7a080"

#define TEST_URL "http://192.168.0.33:12345/foo.mp4"
#define CONTENT_LOCATION_PARAM "Content-Location: " TEST_URL "\nStart-Position: 0.0\n"

static void
print_query (const char *key,
	     const char *value,
	     gpointer user_data)
{
	g_message ("%s = %s", key, value);
}

static void
server_cb (SoupServer *server,
	   SoupMessage *msg,
	   const char *path,
	   GHashTable *query,
	   SoupClientContext *client,
	   gpointer user_data)
{
	SoupMessageBody *body;

	g_message ("path: %s", path);
	if (query)
		g_hash_table_foreach (query, (GHFunc) print_query, NULL);

	g_object_get (G_OBJECT (msg), SOUP_MESSAGE_REQUEST_BODY, &body, NULL);
	g_message ("Server received: %s", body->data);
	soup_message_body_free (body);

	soup_message_set_status (msg, 200);
}

static void
revhttp_cb (GObject *object,
	    GAsyncResult *result,
	    gpointer user_data)
{
	SoupMessage *msg;
	SoupSession *session = SOUP_SESSION (object);
	GTimeVal date;
	char *date_str;

	SoupServer *server;
	GError *error = NULL;

	server = soup_session_reverse_http_connect_finish (session, result, &error);
	if (server == NULL) {
		g_warning ("Reverse HTTP failed: %s", error->message);
		return;
	}
	soup_server_add_handler (server, NULL, server_cb, NULL, NULL);

	session = soup_test_session_new (SOUP_TYPE_SESSION, SOUP_SESSION_MAX_CONNS_PER_HOST, 1, SOUP_SESSION_MAX_CONNS, 1, NULL);
	g_object_set (G_OBJECT (session), SOUP_SESSION_USER_AGENT, "Quicktime/7.2.0", NULL);

	msg = soup_message_new ("POST", "http://" APPLETV_IP ":" APPLETV_PORT "/play");
	soup_message_headers_append (msg->request_headers, "X-Apple-Session-ID", SESSION_ID);
	g_get_current_time (&date);
	date_str = g_time_val_to_iso8601 (&date);
	soup_message_headers_append (msg->request_headers, "X-Transmit-Date", date_str);
	g_free (date_str);
	soup_message_set_request (msg, "text/parameters", SOUP_MEMORY_STATIC, CONTENT_LOCATION_PARAM, strlen(CONTENT_LOCATION_PARAM));

	soup_session_send_message (session, msg);
	g_object_unref (msg);
}

int main (int argc, char **argv)
{
	SoupSession *session;
	SoupMessage *msg;
	GMainLoop *loop;

	test_init (argc, argv, NULL);

	loop = g_main_loop_new (NULL, TRUE);

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	g_object_set (G_OBJECT (session), SOUP_SESSION_USER_AGENT, "Quicktime/7.2.0", NULL);

	msg = soup_message_new ("POST", "http://" APPLETV_IP ":" APPLETV_PORT "/reverse");
	soup_message_headers_append (msg->request_headers, "X-Apple-Purpose", "event");
	soup_message_headers_append (msg->request_headers, "X-Apple-Session-ID", SESSION_ID);
	soup_session_reverse_http_connect_async (session, msg, NULL, revhttp_cb, NULL);

	g_main_loop_run (loop);

	return 0;
}
