/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-error.c: Errorcode description and class lookup
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#include <glib.h>

#include "soup-error.h"

struct {
	guint sc;
	const gchar *phrase;
} error_code_phrases [] = {
	/* 
	 * SOUP_ERROR_CLASS_TRANSPORT 
	 */
	{ SOUP_ERROR_CANCELLED,               "Cancelled" },
	{ SOUP_ERROR_CANT_CONNECT,            "Cannot connect to destination" },
	{ SOUP_ERROR_CANT_CONNECT_PROXY,      "Cannot connect to proxy" },
	{ SOUP_ERROR_IO,                      "Connection terminated "
	                                      "unexpectedly" },
	{ SOUP_ERROR_MALFORMED,               "Message Corrupt" },
	{ SOUP_ERROR_CANT_AUTHENTICATE,       "Authentication Failed" },
	{ SOUP_ERROR_CANT_AUTHENTICATE_PROXY, "Proxy Authentication Failed" },
	{ SOUP_ERROR_SSL_FAILED,              "SSL handshake failed" },

	/* 
	 * SOUP_ERROR_CLASS_INFORMATIONAL 
	 */
	{ SOUP_ERROR_CONTINUE,        "Continue" },
	{ SOUP_ERROR_PROTOCOL_SWITCH, "Protocol Switch" },
	{ SOUP_ERROR_DAV_PROCESSING,  "Processing" },

	/* 
	 * SOUP_ERROR_CLASS_SUCCESS 
	 */
	{ SOUP_ERROR_OK,                "OK" },
	{ SOUP_ERROR_CREATED,           "Created" },
	{ SOUP_ERROR_ACCEPTED,          "Accepted" },
	{ SOUP_ERROR_NON_AUTHORITATIVE, "Non-Authoritative" },
	{ SOUP_ERROR_NO_CONTENT,        "No Content" },
	{ SOUP_ERROR_RESET_CONTENT,     "Reset Content" },
	{ SOUP_ERROR_PARTIAL_CONTENT,   "Partial Content" },
	{ SOUP_ERROR_DAV_MULTISTATUS,   "Multi-Status" },

	/* 
	 * SOUP_ERROR_CLASS_REDIRECT 
	 */
	{ SOUP_ERROR_MULTIPLE_CHOICES,   "Multiple Choices" },
	{ SOUP_ERROR_MOVED_PERMANENTLY,  "Moved Permanently" },
	{ SOUP_ERROR_FOUND,              "Found" },
	{ SOUP_ERROR_SEE_OTHER,          "See Other" },
	{ SOUP_ERROR_NOT_MODIFIED,       "Not Modified" },
	{ SOUP_ERROR_USE_PROXY,          "Use Proxy" },
	{ SOUP_ERROR_TEMPORARY_REDIRECT, "Temporary Redirect" },

	/* 
	 * SOUP_ERROR_CLASS_CLIENT_ERROR 
	 */
	{ SOUP_ERROR_BAD_REQUEST,           "Bad Request" },
	{ SOUP_ERROR_UNAUTHORIZED,          "Unauthorized" },
	{ SOUP_ERROR_PAYMENT_REQUIRED,      "Payment Required" },
	{ SOUP_ERROR_FORBIDDEN,             "Forbidden" },
	{ SOUP_ERROR_NOT_FOUND,             "Not Found" },
	{ SOUP_ERROR_METHOD_NOT_ALLOWED,    "Method Not Allowed" },
	{ SOUP_ERROR_NOT_ACCEPTABLE,        "Not Acceptable" },
	{ SOUP_ERROR_PROXY_UNAUTHORIZED,    "Proxy Unauthorized" },
	{ SOUP_ERROR_TIMED_OUT,             "Timed Out" },
	{ SOUP_ERROR_CONFLICT,              "Conflict" },
	{ SOUP_ERROR_GONE,                  "Gone" },
	{ SOUP_ERROR_LENGTH_REQUIRED,       "Length Required" },
	{ SOUP_ERROR_PRECONDITION_FAILED,   "Precondition Failed" },
	{ SOUP_ERROR_BODY_TOO_LARGE,        "Entity Body Too Large" },
	{ SOUP_ERROR_URI_TOO_LARGE,         "Request-URI Too Large" },
	{ SOUP_ERROR_UNKNOWN_MEDIA_TYPE,    "Unknown Media Type" },
	{ SOUP_ERROR_INVALID_RANGE,         "Invalid Range" },
	{ SOUP_ERROR_EXPECTATION_FAILED,    "Expectation Failed" },
	{ SOUP_ERROR_DAV_UNPROCESSABLE,     "Unprocessable Entity" },
	{ SOUP_ERROR_DAV_LOCKED,            "Locked" },
	{ SOUP_ERROR_DAV_DEPENDENCY_FAILED, "Dependency Failed" },

	/* 
	 * SOUP_ERROR_CLASS_SERVER_ERROR 
	 */
	{ SOUP_ERROR_INTERNAL,            "Internal Server Error" },
	{ SOUP_ERROR_NOT_IMPLEMENTED,     "Not Implemented" },
	{ SOUP_ERROR_BAD_GATEWAY,         "Bad Gateway" },
	{ SOUP_ERROR_SERVICE_UNAVAILABLE, "Service Unavailable" },
	{ SOUP_ERROR_GATEWAY_TIMEOUT,     "Gateway Timeout" },
	{ SOUP_ERROR_VERSION_UNSUPPORTED, "Version Unsupported" },
	{ SOUP_ERROR_DAV_OUT_OF_SPACE,    "Out Of Space" },

	{ 0 }
};

const gchar *
soup_error_get_phrase (SoupKnownErrorCode errcode)
{
	gint i;

	for (i = 0; error_code_phrases [i].sc; i++) {
		if (error_code_phrases [i].sc == (guint) errcode)
			return error_code_phrases [i].phrase;
	}

	return "Unknown Error";
}

SoupErrorClass
soup_error_get_class (SoupKnownErrorCode errcode)
{
	if (errcode < 100) return SOUP_ERROR_CLASS_TRANSPORT;
	if (errcode < 200) return SOUP_ERROR_CLASS_INFORMATIONAL;
	if (errcode < 300) return SOUP_ERROR_CLASS_SUCCESS;
	if (errcode < 400) return SOUP_ERROR_CLASS_REDIRECT;
	if (errcode < 500) return SOUP_ERROR_CLASS_CLIENT_ERROR;
	if (errcode < 600) return SOUP_ERROR_CLASS_SERVER_ERROR;
	return SOUP_ERROR_CLASS_UNKNOWN;
}
