/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-method.c: declarations of _SOUP_METHOD_* variables
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-method.h"

/* Explicit assignment to NULL is to help the OS X linker not be
 * stupid. #522957
 */
const char *_SOUP_METHOD_CONNECT = NULL;
const char *_SOUP_METHOD_COPY = NULL;
const char *_SOUP_METHOD_DELETE = NULL;
const char *_SOUP_METHOD_GET = NULL;
const char *_SOUP_METHOD_HEAD = NULL;
const char *_SOUP_METHOD_LOCK = NULL;
const char *_SOUP_METHOD_MKCOL = NULL;
const char *_SOUP_METHOD_MOVE = NULL;
const char *_SOUP_METHOD_OPTIONS = NULL;
const char *_SOUP_METHOD_POST = NULL;
const char *_SOUP_METHOD_PROPFIND = NULL;
const char *_SOUP_METHOD_PROPPATCH = NULL;
const char *_SOUP_METHOD_PUT = NULL;
const char *_SOUP_METHOD_TRACE = NULL;
const char *_SOUP_METHOD_UNLOCK = NULL;
