/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-method.c: HTTP Method related processing.
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#include <glib.h>

#include "soup-method.h"

/**
 * soup_method_get_id:
 * @method: an HTTP method
 *
 * Converts @method into a corresponding #SoupMethodId (possibly
 * %SOUP_METHOD_ID_UNKNOWN).
 *
 * Return value: the #SoupMethodId
 **/
SoupMethodId
soup_method_get_id (const char *method)
{
	g_return_val_if_fail (method != NULL, SOUP_METHOD_ID_UNKNOWN);

	switch (*method) {
        case 'H':
		if (g_strcasecmp (method, "HEAD") == 0)
			return SOUP_METHOD_ID_HEAD;
		break;
        case 'G':
		if (g_strcasecmp (method, "GET") == 0)
			return SOUP_METHOD_ID_GET;
		break;
        case 'P':
		if (g_strcasecmp (method, "POST") == 0)
			return SOUP_METHOD_ID_POST;
		if (g_strcasecmp (method, "PUT") == 0)
			return SOUP_METHOD_ID_PUT;
		if (g_strcasecmp (method, "PATCH") == 0)
			return SOUP_METHOD_ID_PATCH;
		if (g_strcasecmp (method, "PROPFIND") == 0)
			return SOUP_METHOD_ID_PROPFIND;
		if (g_strcasecmp (method, "PROPPATCH") == 0)
			return SOUP_METHOD_ID_PROPPATCH;
		break;
        case 'D':
		if (g_strcasecmp (method, "DELETE") == 0)
			return SOUP_METHOD_ID_DELETE;
		break;
        case 'C':
		if (g_strcasecmp (method, "CONNECT") == 0)
			return SOUP_METHOD_ID_CONNECT;
		if (g_strcasecmp (method, "COPY") == 0)
			return SOUP_METHOD_ID_COPY;
		break;
        case 'M':
		if (g_strcasecmp (method, "MKCOL") == 0)
			return SOUP_METHOD_ID_MKCOL;
		if (g_strcasecmp (method, "MOVE") == 0)
			return SOUP_METHOD_ID_MOVE;
		break;
        case 'O':
		if (g_strcasecmp (method, "OPTIONS") == 0)
			return SOUP_METHOD_ID_OPTIONS;
		break;
        case 'T':
		if (g_strcasecmp (method, "TRACE") == 0)
			return SOUP_METHOD_ID_TRACE;
		break;
        case 'L':
		if (g_strcasecmp (method, "LOCK") == 0)
			return SOUP_METHOD_ID_LOCK;
		break;
        case 'U':
		if (g_strcasecmp (method, "UNLOCK") == 0)
			return SOUP_METHOD_ID_UNLOCK;
		break;
	}

	return SOUP_METHOD_ID_UNKNOWN;
}

