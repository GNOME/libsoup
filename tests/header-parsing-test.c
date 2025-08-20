/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"

typedef struct {
	const char *name, *value;
} Header;

/* These are not C strings to ensure going one byte over is not safe. */
static char unterminated_http_version[] = {
        'G','E','T',' ','/',' ','H','T','T','P','/','1', '0', '0', '.'
};

static char only_newlines[] = {
        '\n', '\n', '\n', '\n'
};

static struct RequestTest {
	const char *description;
	const char *bugref;
	const char *request;
	int length;
	guint status;
	const char *method, *path;
	SoupHTTPVersion version;
	Header headers[10];
} reqtests[] = {
	/**********************/
	/*** VALID REQUESTS ***/
	/**********************/

	{ "HTTP 1.0 request with no headers", NULL,
	  "GET / HTTP/1.0\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_0,
	  { { NULL } }
	},

	{ "Req w/ 1 header", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, no leading whitespace", NULL,
	  "GET / HTTP/1.1\r\nHost:example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header including trailing whitespace", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com \r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped", NULL,
	  "GET / HTTP/1.1\r\nFoo: bar\r\n baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped with additional whitespace", NULL,
	  "GET / HTTP/1.1\r\nFoo: bar \r\n  baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped with tab", NULL,
	  "GET / HTTP/1.1\r\nFoo: bar\r\n\tbaz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header, wrapped before value", NULL,
	  "GET / HTTP/1.1\r\nFoo:\r\n bar baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 1 header with empty value", NULL,
	  "GET / HTTP/1.1\r\nHost:\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "" },
	    { NULL }
	  }
	},

	{ "Req w/ 2 headers", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Connection", "close" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nBlah: blah\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Connection", "close" },
	    { "Blah", "blah" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers, 1st wrapped", NULL,
	  "GET / HTTP/1.1\r\nFoo: bar\r\n baz\r\nConnection: close\r\nBlah: blah\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Connection", "close" },
            { "Foo", "bar baz" },
	    { "Blah", "blah" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers, 2nd wrapped", NULL,
	  "GET / HTTP/1.1\r\nConnection: close\r\nBlah: blah\r\nFoo: bar\r\n baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Connection", "close" },
	    { "Blah", "blah" },
	    { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ 3 headers, 3rd wrapped", NULL,
	  "GET / HTTP/1.1\r\nConnection: close\r\nBlah: blah\r\nFoo: bar\r\n baz\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Connection", "close" },
	    { "Blah", "blah" },
	    { "Foo", "bar baz" },
	    { NULL }
	  }
	},

	{ "Req w/ same header multiple times", NULL,
	  "GET / HTTP/1.1\r\nFoo: bar\r\nFoo: baz\r\nFoo: quux\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Foo", "bar, baz, quux" },
	    { NULL }
	  }
	},

	{ "Connection header on HTTP/1.0 message", NULL,
	  "GET / HTTP/1.0\r\nFoo: bar\r\nConnection: Bar, Quux\r\nBar: baz\r\nQuux: foo\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_0,
	  { { "Connection", "Bar, Quux" },
            { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "GET with full URI", "667637",
	  "GET http://example.com HTTP/1.1\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "http://example.com", SOUP_HTTP_1_1,
	  { { NULL } }
	},

	{ "GET with full URI in upper-case", "667637",
	  "GET HTTP://example.com HTTP/1.1\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "HTTP://example.com", SOUP_HTTP_1_1,
	  { { NULL } }
	},

	/* It's better for this to be passed through: this means a SoupServer
	 * could implement ftp-over-http proxying, for instance
	 */
	{ "GET with full URI of unrecognised scheme", "667637",
	  "GET AbOuT: HTTP/1.1\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "AbOuT:", SOUP_HTTP_1_1,
	  { { NULL } }
	},

	/****************************/
	/*** RECOVERABLE REQUESTS ***/
	/****************************/

	/* RFC 2616 section 4.1 says we SHOULD accept this */

	{ "Spurious leading CRLF", NULL,
	  "\r\nGET / HTTP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	/* RFC 2616 section 3.1 says we MUST accept this */

	{ "HTTP/01.01 request", NULL,
	  "GET / HTTP/01.01\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	/* RFC 2616 section 19.3 says we SHOULD accept these */

	{ "LF instead of CRLF after header", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com\nConnection: close\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Connection", "close" },
	    { NULL }
	  }
	},

	{ "LF instead of CRLF after Request-Line", NULL,
	  "GET / HTTP/1.1\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Mixed CRLF/LF", "666316",
	  "GET / HTTP/1.1\r\na: b\r\nc: d\ne: f\r\ng: h\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "a", "b" },
	    { "c", "d" },
	    { "e", "f" },
	    { "g", "h" },
	    { NULL }
	  }
	},

	{ "Req w/ incorrect whitespace in Request-Line", NULL,
	  "GET  /\tHTTP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	{ "Req w/ incorrect whitespace after Request-Line", "475169",
	  "GET / HTTP/1.1 \r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { NULL }
	  }
	},

	/* If the request/status line is parseable, then we
	 * just ignore any invalid-looking headers after that.
	 */

	{ "Req w/ mangled header", "579318",
	  "GET / HTTP/1.1\r\nHost: example.com\r\nFoo one\r\nBar: two\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "Bar", "two" },
	    { NULL }
	  }
	},

	{ "First header line is continuation", "666316",
	  "GET / HTTP/1.1\r\n b\r\nHost: example.com\r\nc: d\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example.com" },
	    { "c", "d" },
	    { NULL }
	  }
	},

	{ "Zero-length header name", "666316",
	  "GET / HTTP/1.1\r\na: b\r\n: example.com\r\nc: d\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "a", "b" },
	    { "c", "d" },
	    { NULL }
	  }
	},

	{ "CR in header name", "666316",
	  "GET / HTTP/1.1\r\na: b\r\na\rb: cd\r\nx\r: y\r\n\rz: w\r\nc: d\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "a", "b" },
	    { "c", "d" },
	    { NULL }
	  }
	},

	{ "CR in header value", "666316",
	  "GET / HTTP/1.1\r\na: b\r\nHost: example\rcom\r\np: \rq\r\ns: t\r\r\nc: d\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "Host", "example com" },  /* CR in the middle turns to space */
            { "a", "b" },
	    { "p", "q" },		/* CR at beginning is ignored */
	    { "s", "t" },		/* CR at end is ignored */
	    { "c", "d" },
	    { NULL }
	  }
	},

	{ "Tab in header name", "666316",
	  "GET / HTTP/1.1\r\na: b\r\na\tb: cd\r\nx\t: y\r\np: q\r\n\tz: w\r\nc: d\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "a", "b" },
	    /* Tab anywhere in the header name causes it to be
	     * ignored... except at beginning of line where it's a
	     * continuation line
	     */
	    { "p", "q z: w" },
	    { "c", "d" },
	    { NULL }
	  }
	},

	{ "Tab in header value", "666316",
	  "GET / HTTP/1.1\r\na: b\r\nab: c\td\r\nx: \ty\r\nz: w\t\r\nc: d\r\n", -1,
	  SOUP_STATUS_OK,
	  "GET", "/", SOUP_HTTP_1_1,
	  { { "a", "b" },
	    { "ab", "c\td" },	/* internal tab preserved */
	    { "x", "y" },	/* leading tab ignored */
	    { "z", "w" },	/* trailing tab ignored */
	    { "c", "d" },
	    { NULL }
	  }
	},

	/************************/
	/*** INVALID REQUESTS ***/
	/************************/

	{ "HTTP 0.9 request; not supported", NULL,
	  "GET /\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "HTTP 1.2 request (no such thing)", NULL,
	  "GET / HTTP/1.2\r\n", -1,
	  SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "HTTP 2000 request (no such thing)", NULL,
	  "GET / HTTP/2000.0\r\n", -1,
	  SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Long HTTP version terminating at missing minor version", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/404",
	  unterminated_http_version, sizeof (unterminated_http_version),
	  SOUP_STATUS_BAD_REQUEST,
           NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Non-HTTP request", NULL,
	  "GET / SOUP/1.1\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Junk after Request-Line", NULL,
	  "GET / HTTP/1.1 blah\r\nHost: example.com\r\n", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL in Method", NULL,
	  "G\x00T / HTTP/1.1\r\nHost: example.com\r\n", 37,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL at beginning of Method", "666316",
	  "\x00 / HTTP/1.1\r\nHost: example.com\r\n", 35,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL in Path", NULL,
	  "GET /\x00 HTTP/1.1\r\nHost: example.com\r\n", 38,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "No terminating CRLF", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com", -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Unrecognized expectation", NULL,
	  "GET / HTTP/1.1\r\nHost: example.com\r\nExpect: the-impossible\r\n", -1,
	  SOUP_STATUS_EXPECTATION_FAILED,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	// https://gitlab.gnome.org/GNOME/libsoup/-/issues/377
	{ "NUL in header name", NULL,
	  "GET / HTTP/1.1\r\nHost\x00: example.com\r\n", 36,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "NUL in header value", NULL,
	  "HTTP/1.1 200 OK\r\nFoo: b\x00" "ar\r\n", 28,
	  SOUP_STATUS_BAD_REQUEST,
           NULL, NULL, -1,
	  { { NULL } }
	},

	{ "CR and LF were incorrectly permitted within request URIs",
	  "https://gitlab.gnome.org/GNOME/libsoup/-/issues/380",
	  "GET /\r\n HTTP/1.1\r\nHost: example.com\r\n",
	  -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "CR and LF incorrectly allowed in request method",
	  "https://gitlab.gnome.org/GNOME/libsoup/-/issues/441",
	  "G\r\nET / HTTP/1.1\r\nHost: example.com\r\n",
	  -1,
	  SOUP_STATUS_BAD_REQUEST,
	  NULL, NULL, -1,
	  { { NULL } }
	},

	{ "Only newlines", NULL,
	  only_newlines, sizeof (only_newlines),
	  SOUP_STATUS_BAD_REQUEST,
           NULL, NULL, -1,
	  { { NULL } }
	}
};
static const int num_reqtests = G_N_ELEMENTS (reqtests);

static struct ResponseTest {
	const char *description;
	const char *bugref;
	const char *response;
	int length;
	SoupHTTPVersion version;
	guint status_code;
	const char *reason_phrase;
	Header headers[10];
} resptests[] = {
	/***********************/
	/*** VALID RESPONSES ***/
	/***********************/

	{ "HTTP 1.0 response w/ no headers", NULL,
	  "HTTP/1.0 200 ok\r\n", -1,
	  SOUP_HTTP_1_0, SOUP_STATUS_OK, "ok",
	  { { NULL } }
	},

	{ "HTTP 1.1 response w/ no headers", NULL,
	  "HTTP/1.1 200 ok\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { NULL } }
	},

	{ "Response w/ multi-word Reason-Phrase", NULL,
	  "HTTP/1.1 400 bad request\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_BAD_REQUEST, "bad request",
	  { { NULL } }
	},

	{ "Response w/ 1 header", NULL,
	  "HTTP/1.1 200 ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ 2 headers", NULL,
	  "HTTP/1.1 200 ok\r\nFoo: bar\r\nBaz: quux\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { "Baz", "quux" },
	    { NULL }
	  }
	},

	{ "Response w/ same header multiple times", NULL,
	  "HTTP/1.1 200 ok\r\nFoo: bar\r\nFoo: baz\r\nFoo: quux\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar, baz, quux" },
	    { NULL }
	  }
	},

	{ "Response w/ no reason phrase", NULL,
	  "HTTP/1.1 200 \r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ unknown status code", NULL,
	  "HTTP/1.1 999 Request denied\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, 999, "Request denied",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Connection header on HTTP/1.0 message", NULL,
	  "HTTP/1.0 200 ok\r\nFoo: bar\r\nConnection: Bar\r\nBar: quux\r\n", -1,
	  SOUP_HTTP_1_0, SOUP_STATUS_OK, "ok",
	  { { "Connection", "Bar" },
            { "Foo", "bar" },
	    { NULL }
	  }
	},

	/* Tests from Cockpit */

	{ "Response w/ 3 headers, check case-insensitivity", "722341",
	  "HTTP/1.0 200 ok\r\nHeader1: value3\r\nHeader2:  field\r\nHead3:  Another \r\n", -1,
	  SOUP_HTTP_1_0, SOUP_STATUS_OK, "ok",
	  { { "header1", "value3" },
	    { "Header2", "field" },
	    { "hEAD3", "Another" },
	    { "Something else", NULL },
	    { NULL }
	  }
	},

	/*****************************/
	/*** RECOVERABLE RESPONSES ***/
	/*****************************/

	/* RFC 2616 section 3.1 says we MUST accept this */

	{ "HTTP/01.01 response", NULL,
	  "HTTP/01.01 200 ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	/* RFC 2616 section 19.3 says we SHOULD accept these */

	{ "Response w/ LF instead of CRLF after Status-Line", NULL,
	  "HTTP/1.1 200 ok\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ incorrect spacing in Status-Line", NULL,
	  "HTTP/1.1  200\tok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ no reason phrase or preceding SP", NULL,
	  "HTTP/1.1 200\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ no whitespace after status code", NULL,
	  "HTTP/1.1 200ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	/* Shoutcast support */
	{ "Shoutcast server not-quite-HTTP", "502325",
	  "ICY 200 OK\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_0, SOUP_STATUS_OK, "OK",
	  { { "Foo", "bar" },
	    { NULL }
	  }
	},

	{ "Response w/ mangled header", "579318",
	  "HTTP/1.1 200 ok\r\nFoo: one\r\nBar two:2\r\nBaz: three\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "one" },
	    { "Baz", "three" },
	    { NULL }
	  }
	},

	{ "HTTP 1.1 response with leading line break", "602863",
	  "\nHTTP/1.1 200 ok\r\nFoo: bar\r\n", -1,
	  SOUP_HTTP_1_1, SOUP_STATUS_OK, "ok",
	  { { "Foo", "bar" },
	    { NULL } }
	},

	/********************************/
	/*** VALID CONTINUE RESPONSES ***/
	/********************************/

	/* Tests from Cockpit project */

	{ "Response w/ 101 Switching Protocols + spaces after new line", NULL,
	  "HTTP/1.0 101 Switching Protocols\r\n  \r\n", 38,
	  SOUP_HTTP_1_0, SOUP_STATUS_SWITCHING_PROTOCOLS, "Switching Protocols",
	  { { NULL } }
	},

	{ "Response w/ 101 Switching Protocols missing \\r + spaces", NULL,
	  "HTTP/1.0  101  Switching Protocols\r\n  \r\n", 40,
	  SOUP_HTTP_1_0, SOUP_STATUS_SWITCHING_PROTOCOLS, "Switching Protocols",
	  { { NULL } }
	},

	{ "Response w/ 101 Switching Protocols + spaces after & before new line", NULL,
	  "HTTP/1.1  101  Switching Protocols  \r\n  \r\n", 42,
	  SOUP_HTTP_1_1, SOUP_STATUS_SWITCHING_PROTOCOLS, "Switching Protocols",
	  { { NULL } }
	},

	/*************************/
	/*** INVALID RESPONSES ***/
	/*************************/

	{ "Invalid HTTP version", NULL,
	  "HTTP/1.2 200 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Non-HTTP response", NULL,
	  "SOUP/1.1 200 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Non-numeric status code", NULL,
	  "HTTP/1.1 XXX OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "No status code", NULL,
	  "HTTP/1.1 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "One-digit status code", NULL,
	  "HTTP/1.1 2 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Two-digit status code", NULL,
	  "HTTP/1.1 20 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Four-digit status code", NULL,
	  "HTTP/1.1 2000 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Status code < 100", NULL,
	  "HTTP/1.1 001 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Status code > 999", NULL,
	  "HTTP/1.1 1000 OK\r\nFoo: bar\r\n", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "NUL at start", "666316",
	  "\x00HTTP/1.1 200 OK\r\nFoo: bar\r\n", 28,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "NUL in Reason Phrase", NULL,
	  "HTTP/1.1 200 O\x00K\r\nFoo: bar\r\n", 28,
	  -1, 0, NULL,
	  { { NULL } }
	},

	/* Failing test from Cockpit */

	{ "Partial response stops after HTTP/", NULL,
	  "HTTP/", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Space before HTTP/", NULL,
	  " HTTP/1.0 101 Switching Protocols\r\n  ", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Missing reason", NULL,
	  "HTTP/1.0  101\r\n  ", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Response code containing alphabetic character", NULL,
	  "HTTP/1.1  1A01  Switching Protocols  \r\n  ", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "TESTONE\\r\\n", NULL,
	  "TESTONE\r\n  ", -1,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "Response w/ 3 headers truncated", NULL,
	  "HTTP/1.0 200 ok\r\nHeader1: value3\r\nHeader2:  field\r\nHead3:  Anothe", -1,
	  -1, 0, NULL,
	  { { NULL }
	  }
	},

	// https://gitlab.gnome.org/GNOME/libsoup/-/issues/377
	{ "NUL in header name", NULL,
	  "HTTP/1.1 200 OK\r\nF\x00oo: bar\r\n", 28,
	  -1, 0, NULL,
	  { { NULL } }
	},

	{ "NUL in header value", "760832",
	  "HTTP/1.1 200 OK\r\nFoo: b\x00" "ar\r\n", 28,
	  -1, 0, NULL,
	  { { NULL } }
	},
};
static const int num_resptests = G_N_ELEMENTS (resptests);

static struct QValueTest {
	const char *header_value;
	const char *acceptable[7];
	const char *unacceptable[2];
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

static struct ParamListTest {
	gboolean strict;
	const char *header_value;
	struct ParamListResult {
		const char * param;
		const char * value;
	} results[3];
} paramlisttests[] = {
	{ TRUE,
	  "UserID=JohnDoe; Max-Age=3600; Version=1",
	  { { "UserID", "JohnDoe" },
	    { "Max-Age", "3600" },
	    { "Version", "1" },
	  }
	},

	{ TRUE,
	  "form-data; name=\"fieldName\"; filename=\"filename.jpg\"",
	  { { "form-data", NULL },
	    { "name", "fieldName" },
	    { "filename", "filename.jpg" },
	  },
	},

	{ FALSE,
	  "form-data; form-data; filename=\"filename.jpg\"",
	  { { "form-data", NULL },
	    { "filename", "filename.jpg" },
	  },
	},

	{ FALSE,
	  "attachment; filename*=UTF-8''t%C3%A9st.txt; filename=\"test.txt\"",
	  { { "attachment", NULL },
	    { "filename", "t\xC3\xA9st.txt" },
	  },
	},

        /* This tests invalid UTF-8 data which *should* never be passed here but it was designed to be robust against it. */
        { TRUE,
              "invalid*=\x69\x27\x27\x93\x93\x93\x93\xff\x61\x61\x61\x61\x61\x61\x61\x62\x63\x64\x65\x0a; filename*=iso-8859-1''\x69\x27\x27\x93\x93\x93\x93\xff\x61\x61\x61\x61\x61\x61\x61\x62\x63\x64\x65\x0a; foo",
              {
                    { "filename", "i''\302\223\302\223\302\223\302\223\303\277aaaaaaabcde" },
                    { "invalid", "\302\223\302\223\302\223\302\223\303\277aaaaaaabcde" },
                    { "foo", NULL },

                },
        }
};
static const int num_paramlisttests = G_N_ELEMENTS (paramlisttests);

static void
check_headers (Header *headers, SoupMessageHeaders *hdrs)
{
	GSList *header_names, *h;
	SoupMessageHeadersIter iter;
	const char *name, *value;
	int i;

	header_names = NULL;
	soup_message_headers_iter_init (&iter, hdrs);
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		if (!g_slist_find_custom (header_names, name,
					  (GCompareFunc)strcmp))
			header_names = g_slist_append (header_names, (char *)name);
	}

	for (i = 0, h = header_names; headers[i].name && h; i++, h = h->next) {
		g_assert_true (g_ascii_strcasecmp (h->data, headers[i].name) == 0);

		value = soup_message_headers_get_list (hdrs, headers[i].name);
		g_assert_cmpstr (value, ==, headers[i].value);
	}
	/* If we have remaining fields to check, they should return NULL */
	for (; headers[i].name; i++) {
		value = soup_message_headers_get_list (hdrs, headers[i].name);
		g_assert_null (value);
	}
	g_assert_null (headers[i].name);
	g_assert_null (h);

	g_slist_free (header_names);
}

static void
do_request_tests (void)
{
	int i, len;
	char *method, *path;
	SoupHTTPVersion version;
	SoupMessageHeaders *headers;
	guint status;

	for (i = 0; i < num_reqtests; i++) {
		debug_printf (1, "%2d. %s (%s)\n", i + 1, reqtests[i].description,
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
		g_assert_cmpint (status, ==, reqtests[i].status);
		if (SOUP_STATUS_IS_SUCCESSFUL (status)) {
			g_assert_cmpstr (method, ==, reqtests[i].method);
			g_assert_cmpstr (path, ==, reqtests[i].path);
			g_assert_cmpint (version, ==, reqtests[i].version);

			check_headers (reqtests[i].headers, headers);
		}

		g_free (method);
		g_free (path);
		soup_message_headers_unref (headers);
	}
}

static void
do_response_tests (void)
{
	int i, len;
	guint status_code;
	char *reason_phrase;
	SoupHTTPVersion version;
	SoupMessageHeaders *headers;

	for (i = 0; i < num_resptests; i++) {
		debug_printf (1, "%2d. %s (%s)\n", i + 1, resptests[i].description,
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
			g_assert_cmpint (version, ==, resptests[i].version);
			g_assert_cmpint (status_code, ==, resptests[i].status_code);
			g_assert_cmpstr (reason_phrase, ==, resptests[i].reason_phrase);

			check_headers (resptests[i].headers, headers);
		} else
			g_assert_null (resptests[i].reason_phrase);

		g_free (reason_phrase);
		soup_message_headers_unref (headers);
	}
}

static void
do_qvalue_tests (void)
{
	int i, j;
	GSList *acceptable, *unacceptable, *iter;

	for (i = 0; i < num_qvaluetests; i++) {
		debug_printf (1, "%2d. %s:\n", i + 1, qvaluetests[i].header_value);

		unacceptable = NULL;
		acceptable = soup_header_parse_quality_list (qvaluetests[i].header_value,
							     &unacceptable);

		debug_printf (1, "    acceptable: ");
		if (acceptable) {
			/* Kludge to deal with the fact that the sort order of the first
			 * test is not fully specified.
			 */
			if (i == 0 && acceptable->next &&
			    !g_str_equal (acceptable->data, qvaluetests[i].acceptable[0]) &&
			    g_str_equal (acceptable->data, qvaluetests[i].acceptable[1])) {
				gpointer tmp = acceptable->data;
				acceptable->data = acceptable->next->data;
				acceptable->next->data = tmp;
			}

			for (iter = acceptable, j = 0; iter; iter = iter->next, j++) {
				debug_printf (1, "%s ", (char *)iter->data);
				g_assert_cmpstr (iter->data, ==, qvaluetests[i].acceptable[j]);
			}
			debug_printf (1, "\n");
			soup_header_free_list (acceptable);
		} else
			debug_printf (1, "(none)\n");

		debug_printf (1, "  unacceptable: ");
		if (unacceptable) {
			for (iter = unacceptable, j = 0; iter; iter = iter->next, j++) {
				debug_printf (1, "%s ", (char *)iter->data);
				g_assert_cmpstr (iter->data, ==, qvaluetests[i].unacceptable[j]);
			}
			debug_printf (1, "\n");
			soup_header_free_list (unacceptable);
		} else
			debug_printf (1, "(none)\n");
	}
}

static void
do_param_list_tests (void)
{
	int i, j, n_params;
	GHashTable* params;

	for (i = 0; i < num_paramlisttests; i++) {
		params = soup_header_parse_semi_param_list (paramlisttests[i].header_value);
		g_assert_nonnull (params);
		n_params = paramlisttests[i].strict ? 3 : 2;
		g_assert_cmpuint (g_hash_table_size (params), ==, n_params);
		for (j = 0; j < n_params; j++) {
			g_assert_cmpstr (g_hash_table_lookup (params, paramlisttests[i].results[j].param),
					 ==, paramlisttests[i].results[j].value);
		}
		soup_header_free_param_list (params);
	}

	for (i = 0; i < num_paramlisttests; i++) {
		params = soup_header_parse_semi_param_list_strict (paramlisttests[i].header_value);
		if (paramlisttests[i].strict) {
			g_assert_nonnull (params);
			n_params = 3;
			g_assert_cmpuint (g_hash_table_size (params), ==, n_params);
			for (j = 0; j < n_params; j++) {
				g_assert_cmpstr (g_hash_table_lookup (params, paramlisttests[i].results[j].param),
						 ==, paramlisttests[i].results[j].value);
			}
			soup_header_free_param_list (params);
		} else {
			g_assert_null (params);
		}
	}
}

#define RFC5987_TEST_FILENAME "t\xC3\xA9st.txt"
#define RFC5987_TEST_FALLBACK_FILENAME "test.txt"

#define RFC5987_TEST_HEADER_ENCODED  "attachment; filename*=UTF-8''t%C3%A9st.txt"

#define RFC5987_TEST_HEADER_UTF8     "attachment; filename*=UTF-8''t%C3%A9st.txt; filename=\"test.txt\""
#define RFC5987_TEST_HEADER_ISO      "attachment; filename=\"test.txt\"; filename*=iso-8859-1''t%E9st.txt"
#define RFC5987_TEST_HEADER_FALLBACK "attachment; filename*=Unknown''t%FF%FF%FFst.txt; filename=\"test.txt\""
#define RFC5987_TEST_HEADER_NO_TYPE  "filename=\"test.txt\""
#define RFC5987_TEST_HEADER_NO_TYPE_2  "filename=\"test.txt\"; foo=bar"
#define RFC5987_TEST_HEADER_EMPTY_FILENAME ";filename"

static void
do_content_disposition_tests (void)
{
	SoupMessageHeaders *hdrs;
	GHashTable *params;
	const char *header, *filename, *parameter2;
	char *disposition;
	GBytes *buffer;
	SoupMultipart *multipart;

	hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	params = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (params, "filename", RFC5987_TEST_FILENAME);
	soup_message_headers_set_content_disposition (hdrs, "attachment", params);
	g_hash_table_destroy (params);

	header = soup_message_headers_get_one (hdrs, "Content-Disposition");
	g_assert_cmpstr (header, ==, RFC5987_TEST_HEADER_ENCODED);

	/* UTF-8 decoding */
	soup_message_headers_clear (hdrs);
	soup_message_headers_append (hdrs, "Content-Disposition",
				     RFC5987_TEST_HEADER_UTF8);
	if (!soup_message_headers_get_content_disposition (hdrs,
							   &disposition,
							   &params)) {
		soup_test_assert (FALSE, "UTF-8 decoding FAILED");
		return;
	}
	g_free (disposition);

	filename = g_hash_table_lookup (params, "filename");
	g_assert_cmpstr (filename, ==, RFC5987_TEST_FILENAME);
	g_hash_table_destroy (params);

	/* ISO-8859-1 decoding */
	soup_message_headers_clear (hdrs);
	soup_message_headers_append (hdrs, "Content-Disposition",
				     RFC5987_TEST_HEADER_ISO);
	if (!soup_message_headers_get_content_disposition (hdrs,
							   &disposition,
							   &params)) {
		soup_test_assert (FALSE, "iso-8859-1 decoding FAILED");
		return;
	}
	g_free (disposition);

	filename = g_hash_table_lookup (params, "filename");
	g_assert_cmpstr (filename, ==, RFC5987_TEST_FILENAME);
	g_hash_table_destroy (params);

	/* Fallback */
	soup_message_headers_clear (hdrs);
	soup_message_headers_append (hdrs, "Content-Disposition",
				     RFC5987_TEST_HEADER_FALLBACK);
	if (!soup_message_headers_get_content_disposition (hdrs,
							   &disposition,
							   &params)) {
		soup_test_assert (FALSE, "fallback decoding FAILED");
		return;
	}
	g_free (disposition);

	filename = g_hash_table_lookup (params, "filename");
	g_assert_cmpstr (filename, ==, RFC5987_TEST_FALLBACK_FILENAME);
	g_hash_table_destroy (params);

        /* Invalid disposition with only a filename still works */
        soup_message_headers_clear (hdrs);
        soup_message_headers_append (hdrs, "Content-Disposition",
				     RFC5987_TEST_HEADER_NO_TYPE);
	if (!soup_message_headers_get_content_disposition (hdrs,
							   &disposition,
							   &params)) {
		soup_test_assert (FALSE, "filename-only decoding FAILED");
		return;
	}
        g_assert_null (disposition);
        filename = g_hash_table_lookup (params, "filename");
	g_assert_cmpstr (filename, ==, RFC5987_TEST_FALLBACK_FILENAME);
	g_hash_table_destroy (params);

        /* Invalid disposition with only two parameters still works */
        soup_message_headers_clear (hdrs);
        soup_message_headers_append (hdrs, "Content-Disposition",
				     RFC5987_TEST_HEADER_NO_TYPE_2);
	if (!soup_message_headers_get_content_disposition (hdrs,
							   &disposition,
							   &params)) {
		soup_test_assert (FALSE, "only two parameters decoding FAILED");
		return;
	}
        g_assert_null (disposition);
        filename = g_hash_table_lookup (params, "filename");
	g_assert_cmpstr (filename, ==, RFC5987_TEST_FALLBACK_FILENAME);
        parameter2 = g_hash_table_lookup (params, "foo");
        g_assert_cmpstr (parameter2, ==, "bar");
	g_hash_table_destroy (params);

        /* Empty filename */
        soup_message_headers_clear (hdrs);
        soup_message_headers_append (hdrs, "Content-Disposition",
				     RFC5987_TEST_HEADER_EMPTY_FILENAME);
	if (!soup_message_headers_get_content_disposition (hdrs,
							   &disposition,
							   &params)) {
		soup_test_assert (FALSE, "empty filename decoding FAILED");
		return;
	}
        g_free (disposition);
        g_assert_false (g_hash_table_contains (params, "filename"));
	g_hash_table_destroy (params);

	soup_message_headers_unref (hdrs);

	/* Ensure that soup-multipart always quotes filename */
	g_test_bug ("641280");
	multipart = soup_multipart_new (SOUP_FORM_MIME_TYPE_MULTIPART);
	buffer = g_bytes_new_static ("foo", 3);
	soup_multipart_append_form_file (multipart, "test", "token",
					 "text/plain", buffer);
	g_bytes_unref (buffer);

	hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	soup_multipart_to_message (multipart, hdrs, &buffer);
	soup_message_headers_unref (hdrs);
	soup_multipart_free (multipart);

	g_assert_nonnull (strstr (g_bytes_get_data (buffer, NULL), "filename=\"token\""));

	g_bytes_unref (buffer);
}

#define CONTENT_TYPE_TEST_MIME_TYPE "text/plain"
#define CONTENT_TYPE_TEST_ATTRIBUTE "charset"
#define CONTENT_TYPE_TEST_VALUE     "US-ASCII"
#define CONTENT_TYPE_TEST_HEADER    "text/plain; charset=US-ASCII"

#define CONTENT_TYPE_BAD_HEADER     "plain text, not text/html"

static void
do_content_type_tests (void)
{
	SoupMessageHeaders *hdrs;
	GHashTable *params;
	const char *header, *mime_type;

	g_test_bug ("576760");

	hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	params = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (params, CONTENT_TYPE_TEST_ATTRIBUTE,
			     CONTENT_TYPE_TEST_VALUE);
	soup_message_headers_set_content_type (hdrs, CONTENT_TYPE_TEST_MIME_TYPE, params);
	g_hash_table_destroy (params);

	header = soup_message_headers_get_one (hdrs, "Content-Type");
	g_assert_cmpstr (header, ==, CONTENT_TYPE_TEST_HEADER);

	soup_message_headers_clear (hdrs);
	soup_message_headers_append (hdrs, "Content-Type",
				     CONTENT_TYPE_TEST_MIME_TYPE);
	/* Add a second Content-Type header: should be ignored */
	soup_message_headers_append (hdrs, "Content-Type",
				     CONTENT_TYPE_TEST_MIME_TYPE);

	mime_type = soup_message_headers_get_content_type (hdrs, &params);
	g_assert_cmpstr (mime_type, ==, CONTENT_TYPE_TEST_MIME_TYPE);
	g_assert_cmpint (g_hash_table_size (params), ==, 0);
	if (params)
		g_hash_table_destroy (params);

	g_test_bug ("577630");

	soup_message_headers_clear (hdrs);
	soup_message_headers_append (hdrs, "Content-Type",
				     CONTENT_TYPE_BAD_HEADER);
	mime_type = soup_message_headers_get_content_type (hdrs, &params);
	g_assert_null (mime_type);

	soup_message_headers_unref (hdrs);
}

struct {
	const char *name, *value;
} test_params[] = {
	{ "one", "foo" },
	{ "two", "test with spaces" },
	{ "three", "test with \"quotes\" and \\s" },
	{ "four", NULL },
	{ "five", "test with \xC3\xA1\xC3\xA7\xC4\x89\xC3\xA8\xC3\xB1\xC5\xA3\xC5\xA1" },
	{ "six", "あ,い!#$&+-.^_`|~" },
	{ "seven", "あabc*'%123^_`|~" }
};

#define TEST_PARAMS_RESULT "one=foo, two=\"test with spaces\", three=\"test with \\\"quotes\\\" and \\\\s\", four, five*=UTF-8''test%20with%20%C3%A1%C3%A7%C4%89%C3%A8%C3%B1%C5%A3%C5%A1, six*=UTF-8''%E3%81%82%2C%E3%81%84!#$&+-.^_`|~, seven*=UTF-8''%E3%81%82abc%2A%27%25123^_`|~"

static void
do_append_param_tests (void)
{
	GString *params;
	int i;

	g_test_bug ("577728");

	params = g_string_new (NULL);
	for (i = 0; i < G_N_ELEMENTS (test_params); i++) {
		if (i > 0)
			g_string_append (params, ", ");
		soup_header_g_string_append_param (params,
						   test_params[i].name,
						   test_params[i].value);
	}
	g_assert_cmpstr (params->str, ==, TEST_PARAMS_RESULT);
	g_string_free (params, TRUE);
}

static const struct {
	const char *description, *name, *value;
} bad_headers[] = {
	{ "Empty name", "", "value" },
	{ "Name with spaces", "na me", "value" },
	{ "Name with colon", "na:me", "value" },
	{ "Name with CR", "na\rme", "value" },
	{ "Name with LF", "na\nme", "value" },
	{ "Name with tab", "na\tme", "value" },
	{ "Value with CR", "name", "val\rue" },
	{ "Value with LF", "name", "val\nue" },
	{ "Value with LWS", "name", "val\r\n ue" }
};

static void
do_bad_header_tests (void)
{
	SoupMessageHeaders *hdrs;
	int i;

	hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	for (i = 0; i < G_N_ELEMENTS (bad_headers); i++) {
		debug_printf (1, "  %s\n", bad_headers[i].description);

		g_test_expect_message ("libsoup", G_LOG_LEVEL_CRITICAL,
				       "*soup_message_headers_append*assertion*failed*");
		soup_message_headers_append (hdrs, bad_headers[i].name,
					     bad_headers[i].value);
		g_test_assert_expected_messages ();
	}
	soup_message_headers_unref (hdrs);
}

static const struct {
	const char *description, *name, *value;
} case_sensitive_headers[] = {
	{ "Sec-WebSocket-Protocol is case sensitive", "Sec-WebSocket-Protocol", "foo,bar,qux" },
};

static void
do_case_sensitive_header_tests (void)
{
	int i;

	const char* token = "foo";
	for (i = 0; i < G_N_ELEMENTS (case_sensitive_headers); i++) {
		const char* value = case_sensitive_headers[i].value;
		char* token_uppercase = g_ascii_strup (token, -1);

		g_assert_true (soup_header_contains (value, token));
		g_assert_true (soup_header_contains (value, token_uppercase));
		g_assert_true (soup_header_contains_case_sensitive (value, token));
		g_assert_false (soup_header_contains_case_sensitive (value, token_uppercase));

		g_free (token_uppercase);
	}
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/header-parsing/request", do_request_tests);
	g_test_add_func ("/header-parsing/response", do_response_tests);
	g_test_add_func ("/header-parsing/qvalue", do_qvalue_tests);
	g_test_add_func ("/header-parsing/param-list", do_param_list_tests);
	g_test_add_func ("/header-parsing/content-disposition", do_content_disposition_tests);
	g_test_add_func ("/header-parsing/content-type", do_content_type_tests);
	g_test_add_func ("/header-parsing/append-param", do_append_param_tests);
	g_test_add_func ("/header-parsing/bad", do_bad_header_tests);
	g_test_add_func ("/header-parsing/case-sensitive", do_case_sensitive_header_tests);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
