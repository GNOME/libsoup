/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia, S.L.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONTENT_PROCESSOR (soup_content_processor_get_type ())
G_DECLARE_INTERFACE (SoupContentProcessor, soup_content_processor, SOUP, CONTENT_PROCESSOR, GObject)

typedef enum {
	SOUP_STAGE_INVALID,

	SOUP_STAGE_MESSAGE_BODY,      /* Raw network data */
	SOUP_STAGE_TRANSFER_ENCODING, /* SoupBodyInputStream is here */
	SOUP_STAGE_ENTITY_BODY,       /* Has Transfer-Encoding removed */
	SOUP_STAGE_CONTENT_ENCODING,  /* SoupContentDecoder works here */
	SOUP_STAGE_BODY_DATA          /* Actual body data */
} SoupProcessingStage;

struct _SoupContentProcessorInterface {
	GTypeInterface parent;

	SoupProcessingStage processing_stage;

	/* methods */
	GInputStream*       (*wrap_input)             (SoupContentProcessor *processor,
						       GInputStream         *base_stream,
						       SoupMessage          *msg,
						       GError              **error);
};

GInputStream       *soup_content_processor_wrap_input           (SoupContentProcessor *processor,
								 GInputStream         *base_stream,
								 SoupMessage          *msg,
								 GError              **error);

SoupProcessingStage soup_content_processor_get_processing_stage (SoupContentProcessor *processor);

G_END_DECLS
