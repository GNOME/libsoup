/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#ifndef SOUP_DATE_H
#define SOUP_DATE_H 1

#include <time.h>

time_t  soup_mktime_utc         (struct tm *tm);
void    soup_gmtime             (const time_t *when, struct tm *tm);

time_t  soup_date_parse         (const char *timestamp);
char   *soup_date_generate      (time_t when);

time_t  soup_date_iso8601_parse (const char *timestamp);

#endif /* SOUP_DATE_H */
