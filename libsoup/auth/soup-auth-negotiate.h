/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Guido Guenther <agx@sigxcpu.org>
 * Copyright (C) 2016 Red Hat, Inc.
 */

#pragma once

#include "soup-connection-auth.h"

G_BEGIN_DECLS

#define SOUP_TYPE_AUTH_NEGOTIATE (soup_auth_negotiate_get_type())
SOUP_AVAILABLE_IN_2_54
G_DECLARE_FINAL_TYPE (SoupAuthNegotiate, soup_auth_negotiate, SOUP, AUTH_NEGOTIATE, SoupConnectionAuth)

G_END_DECLS
