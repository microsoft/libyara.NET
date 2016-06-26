#pragma once

#include <yara.h>

namespace libyaraNET {

    public ref class YaraThreadContext
    {
    public:
        YaraThreadContext() { }

        ~YaraThreadContext()
        {
            yr_finalize_thread();
        }
    };
}
