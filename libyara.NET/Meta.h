#pragma once

#include <yara.h>

using namespace System;

namespace libyaraNET {

    public ref class Meta sealed
    {
    public:
        property String^ Identifier;
        property String^ Value;

        /// <summary>
        /// Create an empty match. Useful for testing.
        /// </summary>
        Meta()
        {
            Identifier = nullptr;
            Value = nullptr;
        }

        Meta(String^ identifier, String^ value)
        {
            Identifier = identifier;
            Value = value;
        }
    };
}
