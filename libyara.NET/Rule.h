#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <yara.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace msclr::interop;

namespace libyaraNET {

    public ref class Rule sealed
    {
    public:
        property String^ Identifier;
        property List<String^>^ Tags;

        /// <summary>
        /// Create an empty Rule. Useful for testing.
        /// </summary>
        Rule()
        {
            Identifier = nullptr;
            Tags = gcnew List<String^>();
        }

        Rule(YR_RULE* rule)
        {
            Identifier = marshal_as<String^>(rule->identifier);
            Tags = gcnew List<String^>();

            const char* tag = nullptr;

            yr_rule_tags_foreach(rule, tag)
            {
                Tags->Add(marshal_as<String^>(tag));
            }
        }
    };
}
