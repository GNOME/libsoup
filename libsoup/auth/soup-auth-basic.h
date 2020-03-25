/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-auth.h"

G_BEGIN_DECLS

#define SOUP_TYPE_AUTH_BASIC (soup_auth_basic_get_type ())
SOUP_AVAILABLE_IN_2_4
G_DECLARE_FINAL_TYPE (SoupAuthBasic, soup_auth_basic, SOUP, AUTH_BASIC, SoupAuth)

G_END_DECLS
