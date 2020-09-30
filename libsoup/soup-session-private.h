/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_SESSION_PRIVATE_H__
#define __SOUP_SESSION_PRIVATE_H__ 1

#include "soup-session.h"
#include "soup-message-private.h"

G_BEGIN_DECLS

/* "protected" methods for subclasses */
SoupMessageQueue     *soup_session_get_queue            (SoupSession          *session);



G_END_DECLS

#endif /* __SOUP_SESSION_PRIVATE_H__ */
