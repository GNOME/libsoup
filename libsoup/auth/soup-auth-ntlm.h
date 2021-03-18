/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-ntlm-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#pragma once

#include "soup-connection-auth.h"

G_BEGIN_DECLS

SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupAuthNTLM, soup_auth_ntlm, SOUP, AUTH_NTLM, SoupConnectionAuth)

G_END_DECLS
