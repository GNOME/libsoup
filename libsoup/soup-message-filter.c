/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-filter-offset: 8 -*- */
/*
 * soup-message-filter.c: Interface for arbitrary message manipulation
 *
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-message-filter.h"

SOUP_MAKE_INTERFACE (soup_message_filter, SoupMessageFilter, NULL)

/**
 * soup_message_filter_setup_message:
 * @filter: an object that implements the #SoupMessageFilter interface
 * @msg: a #SoupMessage
 *
 * Performs some sort of processing on @msg in preparation for it
 * being sent. This will generally involve some combination of adding
 * headers, adding handlers, and connecting to signals.
 **/
void
soup_message_filter_setup_message (SoupMessageFilter *filter,
				   SoupMessage       *msg)
{
	SOUP_MESSAGE_FILTER_GET_CLASS (filter)->setup_message (filter, msg);
}
