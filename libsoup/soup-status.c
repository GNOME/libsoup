/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-status.c: Status code descriptions
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <glib.h>

#include "soup-status.h"

struct {
	guint code;
	const char *phrase;
} reason_phrases [] = {
	/* Transport errors */
	{ SOUP_STATUS_CANCELLED,                  "Cancelled" },
	{ SOUP_STATUS_CANT_RESOLVE,               "Cannot resolve hostname" },
	{ SOUP_STATUS_CANT_RESOLVE_PROXY,         "Cannot resolve proxy hostname" },
	{ SOUP_STATUS_CANT_CONNECT,               "Cannot connect to destination" },
	{ SOUP_STATUS_CANT_CONNECT_PROXY,         "Cannot connect to proxy" },
	{ SOUP_STATUS_SSL_FAILED,                 "SSL handshake failed" },
	{ SOUP_STATUS_IO_ERROR,                   "Connection terminated unexpectedly" },
	{ SOUP_STATUS_MALFORMED,                  "Message Corrupt" },

	/* Informational */
	{ SOUP_STATUS_CONTINUE,                   "Continue" },
	{ SOUP_STATUS_SWITCHING_PROTOCOLS,        "Switching Protocols" },
	{ SOUP_STATUS_PROCESSING,                 "Processing" },

	/* Success */
	{ SOUP_STATUS_OK,                         "OK" },
	{ SOUP_STATUS_CREATED,                    "Created" },
	{ SOUP_STATUS_ACCEPTED,                   "Accepted" },
	{ SOUP_STATUS_NON_AUTHORITATIVE,          "Non-Authoritative Information" },
	{ SOUP_STATUS_NO_CONTENT,                 "No Content" },
	{ SOUP_STATUS_RESET_CONTENT,              "Reset Content" },
	{ SOUP_STATUS_PARTIAL_CONTENT,            "Partial Content" },
	{ SOUP_STATUS_MULTI_STATUS,               "Multi-Status" },

	/* Redirection */
	{ SOUP_STATUS_MULTIPLE_CHOICES,           "Multiple Choices" },
	{ SOUP_STATUS_MOVED_PERMANENTLY,          "Moved Permanently" },
	{ SOUP_STATUS_FOUND,                      "Found" },
	{ SOUP_STATUS_SEE_OTHER,                  "See Other" },
	{ SOUP_STATUS_NOT_MODIFIED,               "Not Modified" },
	{ SOUP_STATUS_USE_PROXY,                  "Use Proxy" },
	{ SOUP_STATUS_TEMPORARY_REDIRECT,         "Temporary Redirect" },

	/* Client error */
	{ SOUP_STATUS_BAD_REQUEST,                "Bad Request" },
	{ SOUP_STATUS_UNAUTHORIZED,               "Unauthorized" },
	{ SOUP_STATUS_PAYMENT_REQUIRED,           "Payment Required" },
	{ SOUP_STATUS_FORBIDDEN,                  "Forbidden" },
	{ SOUP_STATUS_NOT_FOUND,                  "Not Found" },
	{ SOUP_STATUS_METHOD_NOT_ALLOWED,         "Method Not Allowed" },
	{ SOUP_STATUS_NOT_ACCEPTABLE,             "Not Acceptable" },
	{ SOUP_STATUS_PROXY_UNAUTHORIZED,         "Proxy Authentication Required" },
	{ SOUP_STATUS_REQUEST_TIMEOUT,            "Request Timeout" },
	{ SOUP_STATUS_CONFLICT,                   "Conflict" },
	{ SOUP_STATUS_GONE,                       "Gone" },
	{ SOUP_STATUS_LENGTH_REQUIRED,            "Length Required" },
	{ SOUP_STATUS_PRECONDITION_FAILED,        "Precondition Failed" },
	{ SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,   "Request Entity Too Large" },
	{ SOUP_STATUS_REQUEST_URI_TOO_LONG,       "Request-URI Too Long" },
	{ SOUP_STATUS_UNSUPPORTED_MEDIA_TYPE,     "Unsupported Media Type" },
	{ SOUP_STATUS_INVALID_RANGE,              "Requested Range Not Satisfiable" },
	{ SOUP_STATUS_EXPECTATION_FAILED,         "Expectation Failed" },
	{ SOUP_STATUS_UNPROCESSABLE_ENTITY,       "Unprocessable Entity" },
	{ SOUP_STATUS_LOCKED,                     "Locked" },
	{ SOUP_STATUS_FAILED_DEPENDENCY,          "Failed Dependency" },

	/* Server error */
	{ SOUP_STATUS_INTERNAL_SERVER_ERROR,      "Internal Server Error" },
	{ SOUP_STATUS_NOT_IMPLEMENTED,            "Not Implemented" },
	{ SOUP_STATUS_BAD_GATEWAY,                "Bad Gateway" },
	{ SOUP_STATUS_SERVICE_UNAVAILABLE,        "Service Unavailable" },
	{ SOUP_STATUS_GATEWAY_TIMEOUT,            "Gateway Timeout" },
	{ SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported" },
	{ SOUP_STATUS_INSUFFICIENT_STORAGE,       "Insufficient Storage" },
	{ SOUP_STATUS_NOT_EXTENDED,               "Not Extended" },

	{ 0 }
};

const char *
soup_status_get_phrase (guint status_code)
{
	int i;

	for (i = 0; reason_phrases [i].code; i++) {
		if (reason_phrases [i].code == status_code)
			return reason_phrases [i].phrase;
	}

	return "Unknown Error";
}
