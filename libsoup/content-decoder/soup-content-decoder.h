/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-message-body.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONTENT_DECODER            (soup_content_decoder_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupContentDecoder, soup_content_decoder, SOUP, CONTENT_DECODER, GObject)

G_END_DECLS
