/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SESSION_FEATURE (soup_session_feature_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_INTERFACE (SoupSessionFeature, soup_session_feature, SOUP, SESSION_FEATURE, GObject)

G_END_DECLS
