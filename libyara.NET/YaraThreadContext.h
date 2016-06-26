#pragma once

#include <yara.h>

namespace libyaraNET {

    /// <summary>
    /// RAII wrapper that calls yr_finalize_thread when
    /// the object is disposed. Any thread other than the
    /// main thread that interacts with yara must use this
    /// object. In C# use a using statement to ensure the
    /// thread is properly finalized.
    /// </summary>
    public ref class YaraThreadContext sealed
    {
    public:
        ~YaraThreadContext()
        {
            yr_finalize_thread();
        }
    };
}
