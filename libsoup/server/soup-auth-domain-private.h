/*
 * Copyright (C) 2007 Novell, Inc.
 * Copyright (C) 2022 Igalia S.L.
 */

#pragma once

#include "soup-auth-domain.h"

gboolean    soup_auth_domain_try_generic_auth_callback (SoupAuthDomain    *domain,
							SoupServerMessage *msg,
							const char        *username);
