#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        fuzz_set_logging_func ();

        GBytes *bytes = g_bytes_new (data, size);
        SoupContentSniffer *sniffer = soup_content_sniffer_new ();
        SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "https://example.org");
        char *content_type = soup_content_sniffer_sniff (sniffer, msg, bytes, NULL);

        g_bytes_unref (bytes);
        g_object_unref (sniffer);
        g_object_unref (msg);
        g_free (content_type);

        return 0;
}