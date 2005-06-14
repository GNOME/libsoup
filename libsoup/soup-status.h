/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-status.h: HTTP status code and status class definitions
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifndef SOUP_STATUS_H
#define SOUP_STATUS_H 1

/**
 * SoupStatusClass:
 * @SOUP_STATUS_CLASS_TRANSPORT_ERROR: Network or Soup-level error
 * @SOUP_STATUS_CLASS_INFORMATIONAL: HTTP 1xx response providing
 * partial information about the state of a request
 * @SOUP_STATUS_CLASS_SUCCESS: HTTP 2xx successful response
 * @SOUP_STATUS_CLASS_REDIRECT: HTTP 3xx redirection response
 * @SOUP_STATUS_CLASS_CLIENT_ERROR: HTTP 4xx client error response
 * @SOUP_STATUS_CLASS_SERVER_ERROR: HTTP 5xx server error response
 *
 * The classes of HTTP and Soup status codes
 **/
typedef enum {
	SOUP_STATUS_CLASS_TRANSPORT_ERROR = 0,
	SOUP_STATUS_CLASS_INFORMATIONAL,
	SOUP_STATUS_CLASS_SUCCESS,
	SOUP_STATUS_CLASS_REDIRECT,
	SOUP_STATUS_CLASS_CLIENT_ERROR,
	SOUP_STATUS_CLASS_SERVER_ERROR
} SoupStatusClass;

/**
 * SOUP_STATUS_IS_TRANSPORT_ERROR:
 * @status: a status code
 *
 * Tests if @status is a libsoup transport error.
 *
 * Return value: %TRUE or %FALSE
 **/
/**
 * SOUP_STATUS_IS_INFORMATIONAL:
 * @status: an HTTP status code
 *
 * Tests if @status is an Informational (1xx) response.
 *
 * Return value: %TRUE or %FALSE
 **/
/**
 * SOUP_STATUS_IS_SUCCESSFUL:
 * @status: an HTTP status code
 *
 * Tests if @status is a Successful (2xx) response.
 *
 * Return value: %TRUE or %FALSE
 **/
/**
 * SOUP_STATUS_IS_REDIRECTION:
 * @status: an HTTP status code
 *
 * Tests if @status is a Redirection (3xx) response.
 *
 * Return value: %TRUE or %FALSE
 **/
/**
 * SOUP_STATUS_IS_CLIENT_ERROR:
 * @status: an HTTP status code
 *
 * Tests if @status is a Client Error (4xx) response.
 *
 * Return value: %TRUE or %FALSE
 **/
/**
 * SOUP_STATUS_IS_SERVER_ERROR:
 * @status: an HTTP status code
 *
 * Tests if @status is a Server Error (5xx) response.
 *
 * Return value: %TRUE or %FALSE
 **/

#define SOUP_STATUS_IS_TRANSPORT_ERROR(status) ((status) >  0   && (status) < 100)
#define SOUP_STATUS_IS_INFORMATIONAL(status)   ((status) >= 100 && (status) < 200)
#define SOUP_STATUS_IS_SUCCESSFUL(status)      ((status) >= 200 && (status) < 300)
#define SOUP_STATUS_IS_REDIRECTION(status)     ((status) >= 300 && (status) < 400)
#define SOUP_STATUS_IS_CLIENT_ERROR(status)    ((status) >= 400 && (status) < 500)
#define SOUP_STATUS_IS_SERVER_ERROR(status)    ((status) >= 500 && (status) < 600)

/**
 * SoupKnownStatusCode:
 * @SOUP_STATUS_NONE: No status available. (Eg, the message has not
 * been sent yet)
 * @SOUP_STATUS_CANCELLED: Message was cancelled locally
 * @SOUP_STATUS_CANT_RESOLVE: Unable to resolve destination host name
 * @SOUP_STATUS_CANT_RESOLVE_PROXY: Unable to resolve proxy host name
 * @SOUP_STATUS_CANT_CONNECT: Unable to connect to remote host
 * @SOUP_STATUS_CANT_CONNECT_PROXY: Unable to connect to proxy
 * @SOUP_STATUS_SSL_FAILED: SSL negotiation failed
 * @SOUP_STATUS_IO_ERROR: A network error occurred, or the other end
 * closed the connection unexpectedly
 * @SOUP_STATUS_MALFORMED: Malformed data (usually a programmer error)
 * @SOUP_STATUS_TRY_AGAIN: Try again. (Only returned in certain
 * specifically documented cases)
 * @SOUP_STATUS_CONTINUE: 100 Continue (HTTP)
 * @SOUP_STATUS_SWITCHING_PROTOCOLS: 101 Switching Protocols (HTTP)
 * @SOUP_STATUS_PROCESSING: 102 Processing (WebDAV)
 * @SOUP_STATUS_OK: 200 Success (HTTP). Also used by many lower-level
 * soup routines to indicate success.
 * @SOUP_STATUS_CREATED: 201 Created (HTTP)
 * @SOUP_STATUS_ACCEPTED: 202 Accepted (HTTP)
 * @SOUP_STATUS_NON_AUTHORITATIVE: 203 Non-Authoritative Information
 * (HTTP)
 * @SOUP_STATUS_NO_CONTENT: 204 No Content (HTTP)
 * @SOUP_STATUS_RESET_CONTENT: 205 Reset Content (HTTP)
 * @SOUP_STATUS_PARTIAL_CONTENT: 206 Partial Content (HTTP)
 * @SOUP_STATUS_MULTI_STATUS: 207 Multi-Status (WebDAV)
 * @SOUP_STATUS_MULTIPLE_CHOICES: 300 Multiple Choices (HTTP)
 * @SOUP_STATUS_MOVED_PERMANENTLY: 301 Moved Permanently (HTTP)
 * @SOUP_STATUS_FOUND: 302 Found (HTTP)
 * @SOUP_STATUS_MOVED_TEMPORARILY: 302 Moved Temporarily (old name,
 * RFC 2068)
 * @SOUP_STATUS_SEE_OTHER: 303 See Other (HTTP)
 * @SOUP_STATUS_NOT_MODIFIED: 304 Not Modified (HTTP)
 * @SOUP_STATUS_USE_PROXY: 305 Use Proxy (HTTP)
 * @SOUP_STATUS_NOT_APPEARING_IN_THIS_PROTOCOL: 306 [Unused] (HTTP)
 * @SOUP_STATUS_TEMPORARY_REDIRECT: 307 Temporary Redirect (HTTP)
 * @SOUP_STATUS_BAD_REQUEST: 400 Bad Request (HTTP)
 * @SOUP_STATUS_UNAUTHORIZED: 401 Unauthorized (HTTP)
 * @SOUP_STATUS_PAYMENT_REQUIRED: 402 Payment Required (HTTP)
 * @SOUP_STATUS_FORBIDDEN: 403 Forbidden (HTTP)
 * @SOUP_STATUS_NOT_FOUND: 404 Not Found (HTTP)
 * @SOUP_STATUS_METHOD_NOT_ALLOWED: 405 Method Not Allowed (HTTP)
 * @SOUP_STATUS_NOT_ACCEPTABLE: 406 Not Acceptable (HTTP)
 * @SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED: 407 Proxy Authentication
 * Required (HTTP)
 * @SOUP_STATUS_PROXY_UNAUTHORIZED: shorter alias for
 * %SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED
 * @SOUP_STATUS_REQUEST_TIMEOUT: 408 Request Timeout (HTTP)
 * @SOUP_STATUS_CONFLICT: 409 Conflict (HTTP)
 * @SOUP_STATUS_GONE: 410 Gone (HTTP)
 * @SOUP_STATUS_LENGTH_REQUIRED: 411 Length Required (HTTP)
 * @SOUP_STATUS_PRECONDITION_FAILED: 412 Precondition Failed (HTTP)
 * @SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE: 413 Request Entity Too Large
 * (HTTP)
 * @SOUP_STATUS_REQUEST_URI_TOO_LONG: 414 Request-URI Too Long (HTTP)
 * @SOUP_STATUS_UNSUPPORTED_MEDIA_TYPE: 415 Unsupported Media Type
 * (HTTP)
 * @SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE: 416 Requested Range
 * Not Satisfiable (HTTP)
 * @SOUP_STATUS_INVALID_RANGE: shorter alias for
 * %SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE
 * @SOUP_STATUS_EXPECTATION_FAILED: 417 Expectation Failed (HTTP)
 * @SOUP_STATUS_UNPROCESSABLE_ENTITY: 422 Unprocessable Entity
 * (WebDAV)
 * @SOUP_STATUS_LOCKED: 423 Locked (WebDAV)
 * @SOUP_STATUS_FAILED_DEPENDENCY: 424 Failed Dependency (WebDAV)
 * @SOUP_STATUS_INTERNAL_SERVER_ERROR: 500 Internal Server Error
 * (HTTP)
 * @SOUP_STATUS_NOT_IMPLEMENTED: 501 Not Implemented (HTTP)
 * @SOUP_STATUS_BAD_GATEWAY: 502 Bad Gateway (HTTP)
 * @SOUP_STATUS_SERVICE_UNAVAILABLE: 503 Service Unavailable (HTTP)
 * @SOUP_STATUS_GATEWAY_TIMEOUT: 504 Gateway Timeout (HTTP)
 * @SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED: 505 HTTP Version Not
 * Supported (HTTP)
 * @SOUP_STATUS_INSUFFICIENT_STORAGE: 507 Insufficient Storage
 * (WebDAV)
 * @SOUP_STATUS_NOT_EXTENDED: 510 Not Extended (RFC 2774)
 * 
 * These represent the known HTTP status code values, plus various
 * network and internal errors.
 **/
typedef enum {
	SOUP_STATUS_NONE,

	/* Transport Errors */
	SOUP_STATUS_CANCELLED                       = 1,
	SOUP_STATUS_CANT_RESOLVE,
	SOUP_STATUS_CANT_RESOLVE_PROXY,
	SOUP_STATUS_CANT_CONNECT,
	SOUP_STATUS_CANT_CONNECT_PROXY,
	SOUP_STATUS_SSL_FAILED,
	SOUP_STATUS_IO_ERROR,
	SOUP_STATUS_MALFORMED,
	SOUP_STATUS_TRY_AGAIN,

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
