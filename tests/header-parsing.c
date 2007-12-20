#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libsoup/soup-message.h"
#include "libsoup/soup-headers.h"

gboolean debug = FALSE;

static void
dprintf (const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	va_start (args, format);
	vprintf (format, args);
	va_end (args);
}

typedef struct {
	char *name, *value;
} Header;

struct RequestTest {
	char *description;
	char *request;
	int length;
	guint status;
	char *method, *path;
	SoupHTTPVersion version;
	Header headers[4];
} reqtests[] = {
	/**********************/
	/*** VALID REQUESTS ***/
	/**********************/

	{ "HTTP 1.0 request with no headers",
	  "GET / HTTP/1.0\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_0,
	  { { NULL } }
	},

	{ "Req w/ 1 header",
	  "GET / HTTP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, no leading whitespace",
	  "GET / HTTP/1.1\r\nHost:example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header including trailing whitespace",
	  "GET / HTTP/1.1\r\nHost: example.com \r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped",
	  "GET / HTTP/1.1\r\nFoo: bar\r\n baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped with additional whitespace",
	  "GET / HTTP/1.1\r\nFoo: bar \r\n  baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped with tab",
	  "GET / HTTP/1.1\r\nFoo: bar\r\n\tbaz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped before value",
	  "GET / HTTP/1.1\r\nFoo:\r\n bar baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header with empty value",
	  "GET / HTTP/1.1\r\nHost:\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "" },
	    { NULL }
	  }
	},

	{ "Req w/ 2 headers",
	  "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Connection", "close" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers",
	  "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nBlah: blah\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Connection", "close" },
	    { "Blah", "blah" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers, 1st wrapped",
	  "GET / HTTP/1.1\r\nFoo: bar\r\n baz\r\nConnection: close\r\nBlah: blah\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { "Connection", "close" },
	    { "Blah", "blah" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers, 2nd wrapped",
	  "GET / HTTP/1.1\r\nConnection: close\r\nBlah: blah\r\nFoo: bar\r\n baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Connection", "close" },
	    { "Blah", "blah" },
	    { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers, 3rd wrapped",
	  "GET / HTTP/1.1\r\nConnection: close\r\nBlah: blah\r\nFoo: bar\r\n baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Connection", "close" },
	    { "Blah", "blah" },
	    { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ same header multiple times",
	  "GET / HTTP/1.1\r\nFoo: bar\r\nFoo: baz\r\nFoo: quux\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar" },
	    { "Foo", "baz" },
	    { "Foo", "quux" },
	    { NULL }
	  }
	},

	/****************************/
	/*** RECOVERABLE REQUESTS ***/
	/****************************/

	/* RFC 2616 section 4.1 says we SHOULD accept this */

	{ "Spurious leading CRLF",
	  "\r\nGET / HTTP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	/* RFC 2616 section 3.1 says we MUST accept this */

	{ "HTTP/01.01 request",
	  "GET / HTTP/01.01\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	/* RFC 2616 section 19.3 says we SHOULD accept these */

	{ "LF instead of CRLF after header",
	  "GET / HTTP/1.1\nHost: example.com\nConnection: close\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Connection", "close" },
	    { NULL }
	  }
	},

	{ "LF instead of CRLF after Request-Line",
	  "GET / HTTP/1.1\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ incorrect whitespace in Request-Line",
	  "GET  /\tHTTP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ incorrect whitespace after Request-Line",
	  "GET / HTTP/1.1 \r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	/************************/
	/*** INVALID REQUESTS ***/
	/************************/

	{ "HTTP 0.9 request; not supported",
	  "GET /\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "HTTP 1.2 request (no such thing)",
	  "GET / HTTP/1.2\r\n", -1,
	  SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "HTTP 2000 request (no such thing)",
	  "GET / HTTP/2000.0\r\n", -1,
	  SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Non-HTTP request",
	  "GET / SOUP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Junk after Request-Line",
	  "GET / HTTP/1.1 blah\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL in Method",
	  "G\x00T / HTTP/1.1\r\nHost: example.com\r\n", 37,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL in Path",
	  "GET /\x00 HTTP/1.1\r\nHost: example.com\r\n", 38,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL in Header",
	  "GET / HTTP/1.1\r\nHost: example\x00com\r\n", 37,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Header line with no ':'",
	  "GET / HTTP/1.1\r\nHost example.com\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "No terminating CRLF",
	  "GET / HTTP/1.1\r\nHost: example.com", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Blank line before headers",
	  "GET / HTTP/1.1\r\n\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Blank line in headers",
	  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nConnection: close\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Blank line after headers",
	  "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

};
static const int num_reqtests = G_N_ELEMENTS (reqtests);

struct ResponseTest {
	char *description;
	char *response;
	int length;
	SoupHTTPVersion version;
	guint status_code;
	char *reason_phrase;
	Header headers[4];
} resptests[] = {
	/***********************/
	/*** VALID RESPONSES ***/
	/***********************/

	{ "HTTP 1.0 response w/ no headers",
	  "HTTP/1.0 200 ok\r\n", -1,
	  SOUP_HTTP_1_0, SOUP_STATUS_OK, "ok",
	  { { NULL } }
	},

	{ "HTTP 1.1 response w/ no headers",
	  "HTTP/1.1 200 ok\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { NULL } }
	},

	{ "Response w/ multi-word Reason-Phrase",
	  "HTTP/1.1 400 bad request\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_BAD_REQUEST, "bad request",
	  { { NULL } }
	},

	{ "Response w/ 1 header",
	  "HTTP/1.1 200 ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ 2 headers",
	  "HTTP/1.1 200 ok\r\nFoo: bar\r\nBaz: quux\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { "Baz", "quux" },
	    { NULL }
	  }
	},

	{ "Response w/ same header multiple times",
	  "HTTP/1.1 200 ok\r\nFoo: bar\r\nFoo: baz\r\nFoo: quux\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { "Foo", "baz" },
	    { "Foo", "quux" },
	    { NULL }
	  }
	},

	{ "Response w/ no reason phrase",
	  "HTTP/1.1 200 \r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	/*****************************/
	/*** RECOVERABLE RESPONSES ***/
	/*****************************/

	/* RFC 2616 section 3.1 says we MUST accept this */

	{ "HTTP/01.01 response",
	  "HTTP/01.01 200 ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	/* RFC 2616 section 19.3 says we SHOULD accept these */

	{ "Response w/ LF instead of CRLF after Status-Line",
	  "HTTP/1.1 200 ok\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ incorrect spacing in Status-Line",
	  "HTTP/1.1  200\tok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ no reason phrase or preceding SP",
	  "HTTP/1.1 200\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ no whitespace after status code",
	  "HTTP/1.1 200ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	/*************************/
	/*** INVALID RESPONSES ***/
	/*************************/

	{ "Invalid HTTP version",
	  "HTTP/1.2 200 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Non-HTTP response",
	  "SOUP/1.1 200 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Non-numeric status code",
	  "HTTP/1.1 XXX OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "No status code",
	  "HTTP/1.1 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "One-digit status code",
	  "HTTP/1.1 2 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Two-digit status code",
	  "HTTP/1.1 20 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Four-digit status code",
	  "HTTP/1.1 2000 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Status code < 100",
	  "HTTP/1.1 001 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Status code > 599",
	  "HTTP/1.1 600 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "NUL in Reason Phrase",
	  "HTTP/1.1 200 O\x00K\r\nFoo: bar\r\n", 28,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "NUL in Header",
	  "HTTP/1.1 200 OK\r\nFoo: b\x00ar\r\n", 28,
	  -1, 0, NULL,
	  { { NULL } }
	},
};
static const int num_resptests = G_N_ELEMENTS (resptests);

struct QValueTest {
	char *header_value;
	char *acceptable[7];
	char *unacceptable[2];
} qvaluetests[] = {
	{ "text/plain; q=0.5, text/html,\t  text/x-dvi; q=0.8, text/x-c",
	  { "text/html", "text/x-c", "text/x-dvi", "text/plain", NULL },
	  { NULL },
	},

	{ "text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5",
	  { "text/html;level=1", "text/html", "*/*", "text/html;level=2",
	    "text/*", NULL },
	  { NULL }
	},

	{ "gzip;q=1.0, identity; q=0.5, *;q=0",
	  { "gzip", "identity", NULL },
	  { "*", NULL },
	}
};
static const int num_qvaluetests = G_N_ELEMENTS (qvaluetests);

static void
print_header (const char *name, const char *value, gpointer data)
{
	dprintf ("              '%s': '%s'\n", name, value);
}

typedef struct {
	Header *headers;
	int i;
	gboolean ok;
} HeaderForeachData;

static void
check_header (const char *name, const char *value, gpointer data)
{
	HeaderForeachData *hfd = data;

	if (!hfd->headers[hfd->i].name)
		hfd->ok = FALSE;
	else if (strcmp (hfd->headers[hfd->i].name, name) != 0 ||
	    strcmp (hfd->headers[hfd->i].value, value) != 0)
		hfd->ok = FALSE;

	hfd->i++;
}

static gboolean
check_headers (Header *headers, SoupMessageHeaders *hdrs)
{
	HeaderForeachData hfd;

	hfd.headers = headers;
	hfd.i = 0;
	hfd.ok = TRUE;

	soup_message_headers_foreach (hdrs, check_header, &hfd);
	return hfd.ok;
}

static int
do_request_tests (void)
{
	int i, len, h, errors = 0;
	char *method, *path;
	SoupHTTPVersion version;
	SoupMessageHeaders *headers;
	guint status;

	dprintf ("Request tests\n");
	for (i = 0; i < 1; i++) {
		gboolean ok = TRUE;

		dprintf ("%2d. %s (%s): ", i + 1, reqtests[i].description,
			 soup_status_get_phrase (reqtests[i].status));

		headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
		method = path = NULL;

		if (reqtests[i].length == -1)
			len = strlen (reqtests[i].request);
		else
			len = reqtests[i].length;
		status = soup_headers_parse_request (reqtests[i].request, len,
						     headers, &method, &path,
						     &version);
		if (SOUP_STATUS_IS_SUCCESSFUL (status)) {
			if ((reqtests[i].method && strcmp (reqtests[i].method, method) != 0) || !reqtests[i].method)
				ok = FALSE;
			if ((reqtests[i].path && strcmp (reqtests[i].path, path) != 0) || !reqtests[i].path)
				ok = FALSE;
			if (reqtests[i].version != version)
				ok = FALSE;

			if (!check_headers (reqtests[i].headers, headers))
				ok = FALSE;
		} else {
			if (status != reqtests[i].status)
				ok = FALSE;
		}

		if (ok)
			dprintf ("OK!\n");
		else {
			dprintf ("BAD!\n");
			errors++;
			if (reqtests[i].method) {
				dprintf ("    expected: '%s' '%s' 'HTTP/1.%d'\n",
					 reqtests[i].method, reqtests[i].path,
					 reqtests[i].version);
				for (h = 0; reqtests[i].headers[h].name; h++) {
					dprintf ("              '%s': '%s'\n",
						 reqtests[i].headers[h].name,
						 reqtests[i].headers[h].value);
				}
			} else {
				dprintf ("    expected: %s\n",
					 soup_status_get_phrase (reqtests[i].status));
			}
			if (method) {
				dprintf ("         got: '%s' '%s' 'HTTP/1.%d'\n",
					method, path, version);
				soup_message_headers_foreach (headers, print_header, NULL);
			} else {
				dprintf ("         got: %s\n",
					 soup_status_get_phrase (status));
			}
		}

		g_free (method);
		g_free (path);
		soup_message_headers_free (headers);
	}
	dprintf ("\n");

	return errors;
}

static int
do_response_tests (void)
{
	int i, len, h, errors = 0;
	guint status_code;
	char *reason_phrase;
	SoupHTTPVersion version;
	SoupMessageHeaders *headers;

	dprintf ("Response tests\n");
	for (i = 0; i < num_resptests; i++) {
		gboolean ok = TRUE;

		dprintf ("%2d. %s (%s): ", i + 1, resptests[i].description,
			 resptests[i].reason_phrase ? "should parse" : "should NOT parse");

		headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
		reason_phrase = NULL;

		if (resptests[i].length == -1)
			len = strlen (resptests[i].response);
		else
			len = resptests[i].length;
		if (soup_headers_parse_response (resptests[i].response, len,
						 headers, &version,
						 &status_code, &reason_phrase)) {
			if (resptests[i].version != version)
				ok = FALSE;
			if (resptests[i].status_code != status_code)
				ok = FALSE;
			if ((resptests[i].reason_phrase && strcmp (resptests[i].reason_phrase, reason_phrase) != 0) || !resptests[i].reason_phrase)
				ok = FALSE;

			if (!check_headers (resptests[i].headers, headers))
				ok = FALSE;
		} else {
			if (resptests[i].reason_phrase)
				ok = FALSE;
		}

		if (ok)
			dprintf ("OK!\n");
		else {
			dprintf ("BAD!\n");
			errors++;
			if (resptests[i].reason_phrase) {
				dprintf ("    expected: 'HTTP/1.%d' '%03d' '%s'\n",
					 resptests[i].version,
					 resptests[i].status_code,
					 resptests[i].reason_phrase);
				for (h = 0; resptests[i].headers[h].name; h++) {
					dprintf ("              '%s': '%s'\n",
						 resptests[i].headers[h].name,
						 resptests[i].headers[h].value);
				}
			} else
				dprintf ("    expected: parse error\n");
			if (reason_phrase) {
				dprintf ("         got: 'HTTP/1.%d' '%03d' '%s'\n",
					 version, status_code, reason_phrase);
				soup_message_headers_foreach (headers, print_header, NULL);
			} else
				dprintf ("         got: parse error\n");
		}

		g_free (reason_phrase);
		soup_message_headers_free (headers);
	}
	dprintf ("\n");

	return errors;
}

static int
do_qvalue_tests (void)
{
	int i, j, errors = 0;
	GSList *acceptable, *unacceptable, *iter;
	gboolean wrong;

	dprintf ("qvalue tests\n");
	for (i = 0; i < num_qvaluetests; i++) {
		dprintf ("%2d. %s:\n", i + 1, qvaluetests[i].header_value);

		unacceptable = NULL;
		acceptable = soup_header_parse_quality_list (qvaluetests[i].header_value,
							     &unacceptable);

		dprintf ("    acceptable: ");
		wrong = FALSE;
		if (acceptable) {
			for (iter = acceptable, j = 0; iter; iter = iter->next, j++) {
				dprintf ("%s ", iter->data);
				if (!qvaluetests[i].acceptable[j] ||
				    strcmp (iter->data, qvaluetests[i].acceptable[j]) != 0)
					wrong = TRUE;
			}
			dprintf ("\n");
		} else
			dprintf ("(none)\n");
		if (wrong) {
			dprintf ("    WRONG! expected: ");
			for (j = 0; qvaluetests[i].acceptable[j]; j++)
				dprintf ("%s ", qvaluetests[i].acceptable[j]);
			dprintf ("\n");
			errors++;
		}

		dprintf ("  unacceptable: ");
		wrong = FALSE;
		if (unacceptable) {
			for (iter = unacceptable, j = 0; iter; iter = iter->next, j++) {
				dprintf ("%s ", iter->data);
				if (!qvaluetests[i].unacceptable[j] ||
				    strcmp (iter->data, qvaluetests[i].unacceptable[j]) != 0)
					wrong = TRUE;
			}
			dprintf ("\n");
		} else
			dprintf ("(none)\n");
		if (wrong) {
			dprintf ("    WRONG! expected: ");
			for (j = 0; qvaluetests[i].unacceptable[j]; j++)
				dprintf ("%s ", qvaluetests[i].unacceptable[j]);
			dprintf ("\n");
			errors++;
		}

		dprintf ("\n");
	}

	return errors;
}

int
main (int argc, char **argv)
{
	int opt, errors;

	while ((opt = getopt (argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			debug = TRUE;
			break;
		default:
			fprintf (stderr, "Usage: %s [-d]\n", argv[0]);
			return 1;
		}
	}

	errors = do_request_tests ();
	errors += do_response_tests ();
	errors += do_qvalue_tests ();

	dprintf ("\n");
	if (errors) {
		printf ("header-parsing: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("header-parsing: OK\n");
	return errors;
}
