/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-compression-dictionary-request.c
 *
 * Copyright (C) 2025 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-compression-dictionary-request.h"
#include "soup-compression-dictionary-request-private.h"
#include "soup-message.h"
#include "soup-session.h"
#include "soup-session-private.h"

/**
 * SoupCompressionDictionaryRequest:
 *
 * Represents a pending request for a compression dictionary.
 *
 * An instance is emitted with the [signal@Message::request-compression-dictionary]
 * signal. The handler should either call
 * [method@CompressionDictionaryRequest.set_dictionary] (synchronously or after
 * ref-ing the object and completing asynchronously) or call
 * [method@CompressionDictionaryRequest.cancel], then return %TRUE. Return %FALSE
 * to let other signal handlers run; if no handler returns %TRUE the request is
 * treated as cancelled.
 *
 * Since: 3.8
 */

struct _SoupCompressionDictionaryRequest {
	GObject parent_instance;

	SoupSession *session; /* unowned */
	GWeakRef     msg;

	GBytes  *dictionary;
	SoupCompressionDictionaryDecoder *decoder; /* the decoder waiting for the dictionary */
	gboolean cancelled;
	gboolean completed;
	gboolean paused;
};

enum {
	PROP_0,
	PROP_DICTIONARY,
	PROP_CANCELLED,
	N_PROPS
};

static GParamSpec *props[N_PROPS];

G_DEFINE_FINAL_TYPE (SoupCompressionDictionaryRequest, soup_compression_dictionary_request, G_TYPE_OBJECT)

static void
soup_compression_dictionary_request_finalize (GObject *object)
{
	SoupCompressionDictionaryRequest *self = SOUP_COMPRESSION_DICTIONARY_REQUEST (object);

	g_weak_ref_clear (&self->msg);
	g_clear_pointer (&self->dictionary, g_bytes_unref);
	g_clear_object (&self->decoder);

	G_OBJECT_CLASS (soup_compression_dictionary_request_parent_class)->finalize (object);
}

static void
soup_compression_dictionary_request_get_property (GObject    *object,
						   guint       prop_id,
						   GValue     *value,
						   GParamSpec *pspec)
{
	SoupCompressionDictionaryRequest *self = SOUP_COMPRESSION_DICTIONARY_REQUEST (object);

	switch (prop_id) {
	case PROP_DICTIONARY:
		g_value_set_boxed (value, self->dictionary);
		break;
	case PROP_CANCELLED:
		g_value_set_boolean (value, self->cancelled);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
soup_compression_dictionary_request_class_init (SoupCompressionDictionaryRequestClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize     = soup_compression_dictionary_request_finalize;
	object_class->get_property = soup_compression_dictionary_request_get_property;

	/**
	 * SoupCompressionDictionaryRequest:dictionary:
	 *
	 * The raw dictionary bytes provided to resolve the request, or %NULL
	 * if none has been set yet.
	 *
	 * Set with [method@CompressionDictionaryRequest.set_dictionary].
	 *
	 * Since: 3.8
	 */
	props[PROP_DICTIONARY] =
		g_param_spec_boxed ("dictionary", NULL, NULL,
				    G_TYPE_BYTES,
				    G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	/**
	 * SoupCompressionDictionaryRequest:cancelled:
	 *
	 * Whether the request has been cancelled.
	 *
	 * Set to %TRUE by [method@CompressionDictionaryRequest.cancel].
	 *
	 * Since: 3.8
	 */
	props[PROP_CANCELLED] =
		g_param_spec_boolean ("cancelled", NULL, NULL,
				      FALSE,
				      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, N_PROPS, props);
}

static void
soup_compression_dictionary_request_init (SoupCompressionDictionaryRequest *self)
{
}

void
soup_compression_dictionary_request_set_paused (SoupCompressionDictionaryRequest *request)
{
	request->paused = TRUE;
}

SoupCompressionDictionaryRequest *
soup_compression_dictionary_request_new (SoupSession *session,
					  SoupMessage *msg)
{
	SoupCompressionDictionaryRequest *self;

	self = g_object_new (SOUP_TYPE_COMPRESSION_DICTIONARY_REQUEST, NULL);
	self->session = session;
	g_weak_ref_init (&self->msg, msg);
	return self;
}

static void unpause_message(SoupCompressionDictionaryRequest *request)
{
	if (request->paused) {
		SoupMessage *msg = g_weak_ref_get (&request->msg);
		if (msg) {
			soup_session_unpause_message (request->session, msg);
			g_object_unref (msg);
		}
	}
}

/**
 * soup_compression_dictionary_request_set_dictionary:
 * @request: a #SoupCompressionDictionaryRequest
 * @dictionary: (transfer none): the raw dictionary bytes
 *
 * Provides the dictionary bytes for a pending
 * [signal@Message::request-compression-dictionary] request.
 *
 * This can be called synchronously inside the signal handler or asynchronously
 * after ref-ing @request and returning %TRUE from the handler.
 *
 * Since: 3.8
 */
void
soup_compression_dictionary_request_set_dictionary (SoupCompressionDictionaryRequest *request,
						     GBytes                           *dictionary)
{
	g_return_if_fail (SOUP_IS_COMPRESSION_DICTIONARY_REQUEST (request));
	g_return_if_fail (dictionary != NULL);
	g_return_if_fail (!request->completed);

	request->completed = TRUE;
	request->dictionary = g_bytes_ref (dictionary);
	g_object_notify_by_pspec (G_OBJECT (request), props[PROP_DICTIONARY]);

	if (request->decoder)
		soup_compression_dictionary_decoder_set_dictionary (request->decoder, dictionary);

	g_debug("contend-decoder: Unpausing message after compression-dictionary set");
	unpause_message (request);
}

/**
 * soup_compression_dictionary_request_cancel:
 * @request: a #SoupCompressionDictionaryRequest
 *
 * Cancels a pending [signal@Message::request-compression-dictionary] request,
 * causing the response to fail.
 *
 * This can be called synchronously inside the signal handler or asynchronously
 * after ref-ing @request and returning %TRUE from the handler.
 *
 * Since: 3.8
 */
void
soup_compression_dictionary_request_cancel (SoupCompressionDictionaryRequest *request)
{
	g_return_if_fail (SOUP_IS_COMPRESSION_DICTIONARY_REQUEST (request));
	g_return_if_fail (!request->completed);

	request->completed = TRUE;
	request->cancelled = TRUE;
	g_object_notify_by_pspec (G_OBJECT (request), props[PROP_CANCELLED]);
	g_debug("contend-decoder: Unpausing message after compression-dictionary request canceled");
	unpause_message (request);
}

GBytes *
soup_compression_dictionary_request_get_dictionary (SoupCompressionDictionaryRequest *request)
{
	return request->dictionary;
}

void
soup_compression_dictionary_request_set_decoder (SoupCompressionDictionaryRequest *request,
						 SoupCompressionDictionaryDecoder *decoder)
{
	if (!g_set_object (&request->decoder, decoder))
		return;

	if (decoder && request->dictionary)
		soup_compression_dictionary_decoder_set_dictionary (decoder, request->dictionary);
}

SoupCompressionDictionaryDecoder *
soup_compression_dictionary_request_get_decoder (SoupCompressionDictionaryRequest *request)
{
	return request->decoder;
}

gboolean
soup_compression_dictionary_request_is_completed (SoupCompressionDictionaryRequest *request)
{
	return request->completed;
}
