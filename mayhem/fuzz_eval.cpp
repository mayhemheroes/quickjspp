#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "quickjspp.hpp"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString(1000);

    qjs::Runtime runtime;
    qjs::Context context(runtime);
    try
    {
        context.eval(str);
    }
    catch (qjs::exception)
    {
    }

    return 0;
}