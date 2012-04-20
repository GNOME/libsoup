/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011 Igalia, S.L.
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef SOUP_URI_PRIVATE_H
#define SOUP_URI_PRIVATE_H 1

#include "soup-socket.h"

char *uri_decoded_copy (const char *str, int length);

guint soup_socket_handshake_sync  (SoupSocket         *sock,
				   GCancellable       *cancellable);
void  soup_socket_handshake_async (SoupSocket         *sock,
				   GCancellable       *cancellable,
				   SoupSocketCallback  callback,
				   gpointer            user_data);

GSocket       *soup_socket_get_gsocket       (SoupSocket *sock);
GIOStream     *soup_socket_get_iostream      (SoupSocket *sock);
GInputStream  *soup_socket_get_input_stream  (SoupSocket *sock);
GOutputStream *soup_socket_get_output_stream (SoupSocket *sock);

#endif /* SOUP_URI_PRIVATE_H */
