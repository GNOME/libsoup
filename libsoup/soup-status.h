/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-status.h: HTTP status code and status class definitions
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifndef SOUP_STATUS_H
#define SOUP_STATUS_H 1

typedef enum {
	SOUP_STATUS_CLASS_TRANSPORT_ERROR = 0,
	SOUP_STATUS_CLASS_INFORMATIONAL,
	SOUP_STATUS_CLASS_SUCCESS,
	SOUP_STATUS_CLASS_REDIRECT,
	SOUP_STATUS_CLASS_CLIENT_ERROR,
	SOUP_STATUS_CLASS_SERVER_ERROR,
} SoupStatusClass;

#define SOUP_STATUS_IS_TRANSPORT_ERROR(x) ((x) >  0   && (x) < 100)
#define SOUP_STATUS_IS_INFORMATIONAL(x)   ((x) >= 100 && (x) < 200)
#define SOUP_STATUS_IS_SUCCESSFUL(x)      ((x) >= 200 && (x) < 300)
#define SOUP_STATUS_IS_REDIRECTION(x)     ((x) >= 300 && (x) < 400)
#define SOUP_STATUS_IS_CLIENT_ERROR(x)    ((x) >= 400 && (x) < 500)
#define SOUP_STATUS_IS_SERVER_ERROR(x)    ((x) >= 500 && (x) < 600)

typedef enum {
	/* Transport Errors */
	SOUP_STATUS_CANCELLED                = 1,
	SOUP_STATUS_CANT_RESOLVE,
	SOUP_STATUS_CANT_RESOLVE_PROXY,
	SOUP_STATUS_CANT_CONNECT,
	SOUP_STATUS_CANT_CONNECT_PROXY,
	SOUP_STATUS_SSL_FAILED,
	SOUP_STATUS_IO_ERROR,
	SOUP_STATUS_MALFORMED,

	/* HTTP Status Codes */
	SOUP_STATUS_CONTINUE                        = 100,
	SOUP_STATUS_SWITCHING_PROTOCOLS             = 101,
	SOUP_STATUS_PROCESSING                      = 102, /* WebDAV */

	SOUP_STATUS_OK                              = 200,
	SOUP_STATUS_CREATED                         = 201,
	SOUP_STATUS_ACCEPTED                        = 202,
	SOUP_STATUS_NON_AUTHORITATIVE               = 203,
	SOUP_STATUS_NO_CONTENT                      = 204,
	SOUP_STATUS_RESET_CONTENT                   = 205,
	SOUP_STATUS_PARTIAL_CONTENT                 = 206,
	SOUP_STATUS_MULTI_STATUS                    = 207, /* WebDAV */

	SOUP_STATUS_MULTIPLE_CHOICES                = 300,
	SOUP_STATUS_MOVED_PERMANENTLY               = 301,
	SOUP_STATUS_FOUND                           = 302,
	SOUP_STATUS_MOVED_TEMPORARILY               = 302, /* RFC 2068 */
	SOUP_STATUS_SEE_OTHER                       = 303,
	SOUP_STATUS_NOT_MODIFIED                    = 304,
	SOUP_STATUS_USE_PROXY                       = 305,
	SOUP_STATUS_NOT_APPEARING_IN_THIS_PROTOCOL  = 306, /* (reserved) */
	SOUP_STATUS_TEMPORARY_REDIRECT              = 307,

	SOUP_STATUS_BAD_REQUEST                     = 400,
	SOUP_STATUS_UNAUTHORIZED                    = 401,
	SOUP_STATUS_PAYMENT_REQUIRED                = 402, /* (reserved) */
	SOUP_STATUS_FORBIDDEN                       = 403,
	SOUP_STATUS_NOT_FOUND                       = 404,
	SOUP_STATUS_METHOD_NOT_ALLOWED              = 405,
	SOUP_STATUS_NOT_ACCEPTABLE                  = 406,
	SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED   = 407,
	SOUP_STATUS_PROXY_UNAUTHORIZED              = SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED,
	SOUP_STATUS_REQUEST_TIMEOUT                 = 408,
	SOUP_STATUS_CONFLICT                        = 409,
	SOUP_STATUS_GONE                            = 410,
	SOUP_STATUS_LENGTH_REQUIRED                 = 411,
	SOUP_STATUS_PRECONDITION_FAILED             = 412,
	SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE        = 413,
	SOUP_STATUS_REQUEST_URI_TOO_LONG            = 414,
	SOUP_STATUS_UNSUPPORTED_MEDIA_TYPE          = 415,
	SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	SOUP_STATUS_INVALID_RANGE                   = SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE,
	SOUP_STATUS_EXPECTATION_FAILED              = 417,
	SOUP_STATUS_UNPROCESSABLE_ENTITY            = 422, /* WebDAV */
	SOUP_STATUS_LOCKED                          = 423, /* WebDAV */
	SOUP_STATUS_FAILED_DEPENDENCY               = 424, /* WebDAV */

	SOUP_STATUS_INTERNAL_SERVER_ERROR           = 500,
	SOUP_STATUS_NOT_IMPLEMENTED                 = 501,
	SOUP_STATUS_BAD_GATEWAY                     = 502,
	SOUP_STATUS_SERVICE_UNAVAILABLE             = 503,
	SOUP_STATUS_GATEWAY_TIMEOUT                 = 504,
	SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED      = 505,
	SOUP_STATUS_INSUFFICIENT_STORAGE            = 507, /* WebDAV search */
	SOUP_STATUS_NOT_EXTENDED                    = 510  /* RFC 2774 */
} SoupKnownStatusCode;

const char *soup_status_get_phrase (guint status_code);

#endif /* SOUP_STATUS_H */
