/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-error.h: HTTP Errorcode and Errorclass definitions
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifndef SOUP_ERROR_H
#define SOUP_ERROR_H 1

typedef enum {
	SOUP_ERROR_CLASS_TRANSPORT = 1,
	SOUP_ERROR_CLASS_INFORMATIONAL,
	SOUP_ERROR_CLASS_SUCCESS,
	SOUP_ERROR_CLASS_REDIRECT,
	SOUP_ERROR_CLASS_CLIENT_ERROR,
	SOUP_ERROR_CLASS_SERVER_ERROR,
	SOUP_ERROR_CLASS_UNKNOWN,
	SOUP_ERROR_CLASS_HANDLER,
} SoupErrorClass;

#define SOUP_ERROR_IS_TRANSPORT(x)     ((x) > 0 && (x) < 100)
#define SOUP_ERROR_IS_INFORMATIONAL(x) ((x) >= 100 && (x) < 200)
#define SOUP_ERROR_IS_SUCCESSFUL(x)    ((x) >= 200 && (x) < 300)
#define SOUP_ERROR_IS_REDIRECTION(x)   ((x) >= 300 && (x) < 400)
#define SOUP_ERROR_IS_CLIENT_ERROR(x)  ((x) >= 400 && (x) < 500)
#define SOUP_ERROR_IS_SERVER_ERROR(x)  ((x) >= 500 && (x) < 600)
#define SOUP_ERROR_IS_UNKNOWN(x)       ((x) >= 600)

typedef enum {
	/*
	 * Transport Errors
	 */
	SOUP_ERROR_CANCELLED                = 1,
	SOUP_ERROR_CANT_CONNECT             = 2,
	SOUP_ERROR_CANT_CONNECT_PROXY       = 3,
	SOUP_ERROR_IO                       = 4,
	SOUP_ERROR_MALFORMED                = 5,
	SOUP_ERROR_CANT_AUTHENTICATE        = 6,
	SOUP_ERROR_CANT_AUTHENTICATE_PROXY  = 7,

	/*
	 * HTTP Response Codes
	 */
	SOUP_ERROR_CONTINUE                 = 100,
	SOUP_ERROR_PROTOCOL_SWITCH          = 101,
	SOUP_ERROR_DAV_PROCESSING           = 102,

	SOUP_ERROR_OK                       = 200,
	SOUP_ERROR_CREATED                  = 201,
	SOUP_ERROR_ACCEPTED                 = 202,
	SOUP_ERROR_NON_AUTHORITATIVE        = 203,
	SOUP_ERROR_NO_CONTENT               = 204,
	SOUP_ERROR_RESET_CONTENT            = 205,
	SOUP_ERROR_PARTIAL_CONTENT          = 206,
	SOUP_ERROR_DAV_MULTISTATUS          = 207,

	SOUP_ERROR_MULTIPLE_CHOICES         = 300,
	SOUP_ERROR_MOVED_PERMANANTLY        = 301,
	SOUP_ERROR_FOUND                    = 302,
	SOUP_ERROR_MOVED_TEMPORARILY        = SOUP_ERROR_FOUND,
	SOUP_ERROR_SEE_OTHER                = 303,
	SOUP_ERROR_NOT_MODIFIED             = 304,
	SOUP_ERROR_USE_PROXY                = 305,
	SOUP_ERROR_TEMPORARY_REDIRECT       = 307,

	SOUP_ERROR_BAD_REQUEST              = 400,
	SOUP_ERROR_UNAUTHORIZED             = 401,
	SOUP_ERROR_PAYMENT_REQUIRED         = 402,
	SOUP_ERROR_FORBIDDEN                = 403,
	SOUP_ERROR_NOT_FOUND                = 404,
	SOUP_ERROR_METHOD_NOT_ALLOWED       = 405,
	SOUP_ERROR_NOT_ACCEPTABLE           = 406,
	SOUP_ERROR_PROXY_UNAUTHORIZED       = 407,
	SOUP_ERROR_TIMED_OUT                = 408,
	SOUP_ERROR_CONFLICT                 = 409,
	SOUP_ERROR_GONE                     = 410,
	SOUP_ERROR_LENGTH_REQUIRED          = 411,
	SOUP_ERROR_PRECONDITION_FAILED      = 412,
	SOUP_ERROR_BODY_TOO_LARGE           = 413,
	SOUP_ERROR_URI_TOO_LARGE            = 414,
	SOUP_ERROR_UNKNOWN_MEDIA_TYPE       = 415,
	SOUP_ERROR_INVALID_RANGE            = 416,
	SOUP_ERROR_EXPECTATION_FAILED       = 417,
	SOUP_ERROR_DAV_UNPROCESSABLE        = 422,
	SOUP_ERROR_DAV_LOCKED               = 423,
	SOUP_ERROR_DAV_DEPENDENCY_FAILED    = 423,

	SOUP_ERROR_INTERNAL                 = 500,
	SOUP_ERROR_NOT_IMPLEMENTED          = 501,
	SOUP_ERROR_BAD_GATEWAY              = 502,
	SOUP_ERROR_SERVICE_UNAVAILABLE      = 503,
	SOUP_ERROR_GATEWAY_TIMEOUT          = 504,
	SOUP_ERROR_VERSION_UNSUPPORTED      = 505,
	SOUP_ERROR_DAV_OUT_OF_SPACE         = 507,
	SOUP_ERROR_NOT_EXTENDED             = 510,
} SoupKnownErrorCode;

const char     *soup_error_get_phrase (SoupKnownErrorCode  errcode);
SoupErrorClass  soup_error_get_class  (SoupKnownErrorCode  errcode);

#endif /*SOUP_ERROR_H*/
