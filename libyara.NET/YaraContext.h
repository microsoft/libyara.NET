#pragma once

#include <yara.h>

namespace libyaraNET {

    /// <summary>
    /// RAII wrapper for calls to yr_initialize and yr_finalize.
    /// In C# use a using statement to ensure yara is properly
    /// finalized. All yara operations must take place with the
    /// scope of a YaraContext. One YaraContext object should be
    /// created per process and it should be created on the main thread.
    /// </summary>
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
