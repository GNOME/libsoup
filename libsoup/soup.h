/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_H__
#define __SOUP_H__ 1

#define __SOUP_H_INSIDE__

#include "auth/soup-auth.h"
#include "auth/soup-auth-manager.h"
#include "cache/soup-cache.h"
#include "content-decoder/soup-content-decoder.h"
#include "content-sniffer/soup-content-sniffer.h"
#include "cookies/soup-cookie.h"
#include "cookies/soup-cookie-jar.h"
#include "cookies/soup-cookie-jar-db.h"
#include "cookies/soup-cookie-jar-text.h"
#include "soup-date-utils.h"
#include "soup-enum-types.h"
#include "soup-form.h"
#include "soup-headers.h"
#include "hsts/soup-hsts-enforcer.h"
#include "hsts/soup-hsts-enforcer-db.h"
#include "hsts/soup-hsts-policy.h"
#include "soup-logger.h"
#include "soup-message.h"
#include "soup-message-metrics.h"
#include "soup-method.h"
#include "soup-multipart.h"
#include "soup-multipart-input-stream.h"
#include "server/soup-auth-domain.h"
#include "server/soup-auth-domain-basic.h"
#include "server/soup-auth-domain-digest.h"
#include "server/soup-server.h"
#include "server/soup-server-message.h"
#include "soup-session.h"
#include "soup-session-feature.h"
#include "soup-status.h"
#include "soup-tld.h"
#include "soup-uri-utils.h"
#include "soup-version.h"
#include "websocket/soup-websocket.h"
#include "websocket/soup-websocket-connection.h"
#include "websocket/soup-websocket-extension.h"
#include "websocket/soup-websocket-extension-deflate.h"
#include "websocket/soup-websocket-extension-manager.h"

#undef __SOUP_H_INSIDE__

#endif /* __SOUP_H__ */
