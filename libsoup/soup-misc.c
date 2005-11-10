/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-misc.c: Miscellaneous functions

 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <ctype.h>
#include <string.h>

#include "soup-misc.h"

/**
 * soup_str_case_hash:
 * @key: ASCII string to hash
 *
 * Hashes @key in a case-insensitive manner.
 *
 * Return value: the hash code.
 **/
guint
soup_str_case_hash (gconstpointer key)
{
	const char *p = key;
	guint h = g_ascii_toupper(*p);

	if (h)
		for (p += 1; *p != '\0'; p++)
			h = (h << 5) - h + g_ascii_toupper(*p);

	return h;
}

/**
 * soup_str_case_equal:
 * @v1: an ASCII string
 * @v2: another ASCII string
 *
 * Compares @v1 and @v2 in a case-insensitive manner
 *
 * Return value: %TRUE if they are equal (modulo case)
 **/
gboolean
soup_str_case_equal (gconstpointer v1,
		     gconstpointer v2)
{
	const char *string1 = v1;
	const char *string2 = v2;

	return g_ascii_strcasecmp (string1, string2) == 0;
}

/* Base64 utils (straight from camel-mime-utils.c) */
#define d(x)

static char *base64_alphabet =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* 
 * call this when finished encoding everything, to
 * flush off the last little bit 
 */
int
soup_base64_encode_close (const guchar  *in, 
			  int            inlen, 
			  gboolean       break_lines, 
			  guchar        *out, 
			  int           *state, 
			  int           *save)
{
	int c1, c2;
	unsigned char *outptr = out;

	if (inlen > 0)
		outptr += soup_base64_encode_step (in, 
						   inlen, 
						   break_lines, 
						   outptr, 
						   state, 
						   save);

	c1 = ((unsigned char *) save) [1];
	c2 = ((unsigned char *) save) [2];
	
	d(printf("mode = %d\nc1 = %c\nc2 = %c\n",
		 (int)((char *) save) [0],
		 (int)((char *) save) [1],
		 (int)((char *) save) [2]));

	switch (((char *) save) [0]) {
	case 2:
		outptr [2] = base64_alphabet[ ( (c2 &0x0f) << 2 ) ];
		g_assert (outptr [2] != 0);
		goto skip;
	case 1:
		outptr[2] = '=';
	skip:
		outptr [0] = base64_alphabet [ c1 >> 2 ];
		outptr [1] = base64_alphabet [ c2 >> 4 | ( (c1&0x3) << 4 )];
		outptr [3] = '=';
		outptr += 4;
		break;
	}
	if (break_lines)
		*outptr++ = '\n';

	*save = 0;
	*state = 0;

	return outptr-out;
}

/*
 * performs an 'encode step', only encodes blocks of 3 characters to the
 * output at a time, saves left-over state in state and save (initialise to
 * 0 on first invocation).
 */
int
soup_base64_encode_step (const guchar  *in, 
			 int            len, 
			 gboolean       break_lines, 
			 guchar        *out, 
			 int           *state, 
			 int           *save)
{
	register guchar *outptr;
	register const guchar *inptr;

	if (len <= 0)
		return 0;

	inptr = in;
	outptr = out;

	d (printf ("we have %d chars, and %d saved chars\n", 
		   len, 
		   ((char *) save) [0]));

	if (len + ((char *) save) [0] > 2) {
		const guchar *inend = in+len-2;
		register int c1, c2, c3;
		register int already;

		already = *state;

		switch (((char *) save) [0]) {
		case 1:	c1 = ((unsigned char *) save) [1]; goto skip1;
		case 2:	c1 = ((unsigned char *) save) [1];
			c2 = ((unsigned char *) save) [2]; goto skip2;
		}
		
		/* 
		 * yes, we jump into the loop, no i'm not going to change it, 
		 * it's beautiful! 
		 */
		while (inptr < inend) {
			c1 = *inptr++;
		skip1:
			c2 = *inptr++;
		skip2:
			c3 = *inptr++;
			*outptr++ = base64_alphabet [ c1 >> 2 ];
			*outptr++ = base64_alphabet [ c2 >> 4 | 
						      ((c1&0x3) << 4) ];
			*outptr++ = base64_alphabet [ ((c2 &0x0f) << 2) | 
						      (c3 >> 6) ];
			*outptr++ = base64_alphabet [ c3 & 0x3f ];
			/* this is a bit ugly ... */
			if (break_lines && (++already)>=19) {
				*outptr++='\n';
				already = 0;
			}
		}

		((char *)save)[0] = 0;
		len = 2-(inptr-inend);
		*state = already;
	}

	d(printf("state = %d, len = %d\n",
		 (int)((char *)save)[0],
		 len));

	if (len>0) {
		register char *saveout;

		/* points to the slot for the next char to save */
		saveout = & (((char *)save)[1]) + ((char *)save)[0];

		/* len can only be 0 1 or 2 */
		switch(len) {
		case 2:	*saveout++ = *inptr++;
		case 1:	*saveout++ = *inptr++;
		}
		((char *)save)[0]+=len;
	}

	d(printf("mode = %d\nc1 = %c\nc2 = %c\n",
		 (int)((char *)save)[0],
		 (int)((char *)save)[1],
		 (int)((char *)save)[2]));

	return outptr-out;
}

/**
 * soup_base64_encode:
 * @text: the binary data to encode.
 * @len: the length of @text.
 *
 * Encode a sequence of binary data into it's Base-64 stringified
 * representation.
 *
 * Return value: The Base-64 encoded string representing @text.
 */
char *
soup_base64_encode (const char *text, int len)
{
        unsigned char *out;
        int state = 0, outlen;
        unsigned int save = 0;
        
        out = g_malloc (len * 4 / 3 + 5);
        outlen = soup_base64_encode_close (text, 
					   len, 
					   FALSE,
					   out, 
					   &state, 
					   &save);
        out[outlen] = '\0';
        return (char *) out;
}

static unsigned char camel_mime_base64_rank[256] = {
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
	 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
	255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

/**
 * base64_decode_step: decode a chunk of base64 encoded data
 * @in: input stream
 * @len: max length of data to decode
 * @out: output stream
 * @state: holds the number of bits that are stored in @save
 * @save: leftover bits that have not yet been decoded
 *
 * Decodes a chunk of base64 encoded data
 **/
int
soup_base64_decode_step (const guchar  *in, 
			 int            len, 
			 guchar        *out, 
			 int           *state, 
			 guint         *save)
{
	register const guchar *inptr;
	register guchar *outptr;
	const guchar *inend;
	guchar c;
	register unsigned int v;
	int i;

	inend = in+len;
	outptr = out;

	/* convert 4 base64 bytes to 3 normal bytes */
	v=*save;
	i=*state;
	inptr = in;
	while (inptr < inend) {
		c = camel_mime_base64_rank [*inptr++];
		if (c != 0xff) {
			v = (v<<6) | c;
			i++;
			if (i==4) {
				*outptr++ = v>>16;
				*outptr++ = v>>8;
				*outptr++ = v;
				i=0;
			}
		}
	}

	*save = v;
	*state = i;

	/* quick scan back for '=' on the end somewhere */
	/* fortunately we can drop 1 output char for each trailing = (upto 2) */
	i=2;
	while (inptr > in && i) {
		inptr--;
		if (camel_mime_base64_rank [*inptr] != 0xff) {
			if (*inptr == '=')
				outptr--;
			i--;
		}
	}

	/* if i!= 0 then there is a truncation error! */
	return outptr - out;
}

char *
soup_base64_decode (const char   *text,
		    int          *out_len)
{
	char *ret;
	int inlen, state = 0, save = 0;

	inlen = strlen (text);
	ret = g_malloc0 (inlen);

	*out_len = soup_base64_decode_step (text, inlen, ret, &state, &save);

	return ret; 
}

typedef struct {
	gpointer instance;
	guint    signal_id;
} SoupSignalOnceData;

static void
signal_once_object_destroyed (gpointer ssod, GObject *ex_object)
{
	g_free (ssod);
}

static void
signal_once_metamarshal (GClosure *closure, GValue *return_value,
			 guint n_param_values, const GValue *param_values,
			 gpointer invocation_hint, gpointer marshal_data)
{
	SoupSignalOnceData *ssod = marshal_data;

	closure->marshal (closure, return_value, n_param_values,
			  param_values, invocation_hint,
			  ((GCClosure *)closure)->callback);

	if (g_signal_handler_is_connected (ssod->instance, ssod->signal_id))
		g_signal_handler_disconnect (ssod->instance, ssod->signal_id);
	g_object_weak_unref (G_OBJECT (ssod->instance), signal_once_object_destroyed, ssod);
	g_free (ssod);
}

/**
 * soup_signal_connect_once:
 * @instance: an object
 * @detailed_signal: "signal-name" or "signal-name::detail" to connect to
 * @c_handler: the #GCallback to connect
 * @data: data to pass to @c_handler calls
 *
 * Connects a #GCallback function to a signal as with
 * g_signal_connect(), but automatically removes the signal handler
 * after its first invocation.
 *
 * Return value: the signal handler id
 **/
guint
soup_signal_connect_once (gpointer instance, const char *detailed_signal,
			  GCallback c_handler, gpointer data)
{
	SoupSignalOnceData *ssod;
	GClosure *closure;

	g_return_val_if_fail (G_TYPE_CHECK_INSTANCE (instance), 0);
	g_return_val_if_fail (detailed_signal != NULL, 0);
	g_return_val_if_fail (c_handler != NULL, 0);

	ssod = g_new0 (SoupSignalOnceData, 1);
	ssod->instance = instance;
	g_object_weak_ref (G_OBJECT (instance), signal_once_object_destroyed, ssod);

	closure = g_cclosure_new (c_handler, data, NULL);
	g_closure_set_meta_marshal (closure, ssod, signal_once_metamarshal);

	ssod->signal_id = g_signal_connect_closure (instance, detailed_signal,
						    closure, FALSE);
	return ssod->signal_id;
}

/**
 * soup_add_io_watch:
 * @async_context: the #GMainContext to dispatch the I/O watch in, or
 * %NULL for the default context
 * @chan: the #GIOChannel to watch
 * @condition: the condition to watch for
 * @function: the callback to invoke when @condition occurs
 * @data: user data to pass to @function
 *
 * Adds an I/O watch as with g_io_add_watch(), but using the given
 * @async_context.
 *
 * Return value: a #GSource, which can be removed from @async_context
 * with g_source_destroy().
 **/
GSource *
soup_add_io_watch (GMainContext *async_context,
		   GIOChannel *chan, GIOCondition condition,
		   GIOFunc function, gpointer data)
{
	GSource *watch = g_io_create_watch (chan, condition);
	g_source_set_callback (watch, (GSourceFunc) function, data, NULL);
	g_source_attach (watch, async_context);
	g_source_unref (watch);
	return watch;
}

/**
 * soup_add_idle:
 * @async_context: the #GMainContext to dispatch the idle event in, or
 * %NULL for the default context
 * @function: the callback to invoke at idle time
 * @data: user data to pass to @function
 *
 * Adds an idle event as with g_idle_add(), but using the given
 * @async_context.
 *
 * Return value: a #GSource, which can be removed from @async_context
 * with g_source_destroy().
 **/
GSource *
soup_add_idle (GMainContext *async_context,
	       GSourceFunc function, gpointer data)
{
	GSource *source = g_idle_source_new ();
	g_source_set_callback (source, function, data, NULL);
	g_source_attach (source, async_context);
	g_source_unref (source);
	return source;
}

/**
 * soup_add_timeout:
 * @async_context: the #GMainContext to dispatch the timeout in, or
 * %NULL for the default context
 * @interval: the timeout interval, in milliseconds
 * @function: the callback to invoke at timeout time
 * @data: user data to pass to @function
 *
 * Adds a timeout as with g_timeout_add(), but using the given
 * @async_context.
 *
 * Return value: a #GSource, which can be removed from @async_context
 * with g_source_destroy().
 **/
GSource *
soup_add_timeout (GMainContext *async_context,
		  guint interval,
		  GSourceFunc function, gpointer data)
{
	GSource *source = g_timeout_source_new (interval);
	g_source_set_callback (source, function, data, NULL);
	g_source_attach (source, async_context);
	g_source_unref (source);
	return source;
}

