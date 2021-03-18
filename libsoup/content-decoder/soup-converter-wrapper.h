/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2011 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONVERTER_WRAPPER (soup_converter_wrapper_get_type ())
G_DECLARE_FINAL_TYPE (SoupConverterWrapper, soup_converter_wrapper, SOUP, CONVERTER_WRAPPER, GObject)

GConverter *soup_converter_wrapper_new (GConverter  *base_converter,
					SoupMessage *msg);

G_END_DECLS
