#pragma once

#include <yara.h>

namespace libyaraNET {

    // TODO: this is a bad idea, not threadsafe
    // Maybe this should be singleton

    public ref class YaraContext
    {
    public:
        YaraContext()
        {
            auto result = yr_initialize();
        }

        ~YaraContext()
        {
            auto result = yr_finalize();
        }
    };
}
