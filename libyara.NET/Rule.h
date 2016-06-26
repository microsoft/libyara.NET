#pragma once

#include <yara.h>

using namespace System;
using namespace System::Collections::Generic;

namespace libyaraNET {

    // TODO: this is a bad idea, not threadsafe
    // Maybe this should be singleton

    public ref class Rule
    {
    public:
        property String^ Identifier;
        property List<String^>^ Tags;


        Rule()
        {
            auto result = yr_initialize();
        }

        ~Rule()
        {
            auto result = yr_finalize();
        }
    };
}
