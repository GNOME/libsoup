/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005, Novell, Inc.
 */

#ifndef __SOUP_PORTABILITY_H__
#define __SOUP_PORTABILITY_H__

#include <libsoup/soup-types.h>

#ifdef G_OS_WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#else

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#endif

#endif /* __SOUP_PORTABILITY_H__ */
