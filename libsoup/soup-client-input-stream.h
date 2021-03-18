/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2010-2012 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-filter-input-stream.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CLIENT_INPUT_STREAM            (soup_client_input_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupClientInputStream, soup_client_input_stream, SOUP, CLIENT_INPUT_STREAM, SoupFilterInputStream)

GInputStream *soup_client_input_stream_new (GInputStream *base_stream,
					    SoupMessage  *msg);

G_END_DECLS

