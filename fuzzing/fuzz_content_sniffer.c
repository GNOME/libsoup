#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        fuzz_set_logging_func ();

        /* Each content type has a different code path so lets test them all. */
        static const char* content_types[] = {
                NULL,
                "application/unknown",
                "text/plain",
                "text/html",
                "text/xml",
                "image/something",
                "video/something",
        };

        GBytes *bytes = g_bytes_new (data, size);
        SoupContentSniffer *sniffer = soup_content_sniffer_new ();

        for (unsigned i = 0; i < G_N_ELEMENTS(content_types); i++) {
                SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://example.org");
                if (content_types[i])
                        soup_message_headers_set_content_type (soup_message_get_response_headers(msg), content_types[i], NULL);

                char *content_type = soup_content_sniffer_sniff (sniffer, msg, bytes, NULL);

                g_object_unref (msg);
                g_free (content_type);
        }

        g_bytes_unref (bytes);
        g_object_unref (sniffer);

        return 0;
}