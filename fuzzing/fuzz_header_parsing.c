#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        GHashTable *elements;

        // We only accept NUL terminated strings
        if (!size || data[size - 1] != '\0')
                return 0;

        fuzz_set_logging_func ();

        elements = soup_header_parse_param_list((char*)data);

        g_hash_table_unref(elements);

        return 0;
}