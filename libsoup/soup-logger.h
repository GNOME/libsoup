/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_LOGGER (soup_logger_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupLogger, soup_logger, SOUP, LOGGER, GObject)

typedef enum {
	SOUP_LOGGER_LOG_NONE,
	SOUP_LOGGER_LOG_MINIMAL,
	SOUP_LOGGER_LOG_HEADERS,
	SOUP_LOGGER_LOG_BODY
} SoupLoggerLogLevel;

typedef SoupLoggerLogLevel (*SoupLoggerFilter)  (SoupLogger         *logger,
						 SoupMessage        *msg,
						 gpointer            user_data);

typedef void               (*SoupLoggerPrinter) (SoupLogger         *logger,
						 SoupLoggerLogLevel  level,
						 char                direction,
						 const char         *data,
						 gpointer            user_data);

SOUP_AVAILABLE_IN_ALL
SoupLogger *soup_logger_new                 (SoupLoggerLogLevel level);


SOUP_AVAILABLE_IN_ALL
void        soup_logger_set_request_filter  (SoupLogger        *logger,
					     SoupLoggerFilter   request_filter,
					     gpointer           filter_data,
					     GDestroyNotify     destroy);
SOUP_AVAILABLE_IN_ALL
void        soup_logger_set_response_filter (SoupLogger        *logger,
					     SoupLoggerFilter   response_filter,
					     gpointer           filter_data,
					     GDestroyNotify     destroy);

SOUP_AVAILABLE_IN_ALL
void        soup_logger_set_printer         (SoupLogger        *logger,
					     SoupLoggerPrinter  printer,
					     gpointer           printer_data,
					     GDestroyNotify     destroy);

SOUP_AVAILABLE_IN_ALL
void        soup_logger_set_max_body_size  (SoupLogger        *logger,
					     int                max_body_size);

SOUP_AVAILABLE_IN_ALL
int         soup_logger_get_max_body_size  (SoupLogger        *logger);

G_END_DECLS
