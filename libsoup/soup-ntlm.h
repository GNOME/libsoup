/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-ntlm.h: Microsoft Windows NTLM authentication support
 *
 * Authors:
 *      Dan Winship (danw@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifndef NTLM_H
#define NTLM_H 1

#include <glib.h>

void  soup_ntlm_lanmanager_hash (const char *password, 
				 char        hash[21]);

void  soup_ntlm_nt_hash         (const char *password, 
				 char        hash[21]);

char *soup_ntlm_request         (void);

char *soup_ntlm_response        (const char *challenge, 
				 const char *user,
				 const char *lm_hash, 
				 const char *nt_hash,
				 const char *host, 
				 const char *domain);

#endif /* NTLM_H */
