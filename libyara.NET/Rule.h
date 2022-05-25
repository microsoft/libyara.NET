#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <yara.h>
#include "Meta.h"

using namespace System;
using namespace System::Collections::Generic;
using namespace msclr::interop;

namespace libyaraNET {

    public ref class Rule sealed
    {
    public:
        property String^ Identifier;
        property List<String^>^ Tags;
        property List<Meta^>^ Metas;

        /// <summary>
        /// Create an empty Rule. Useful for testing.
        /// </summary>
        Rule()
        {
            Identifier = nullptr;
            Tags = gcnew List<String^>();
            Metas = gcnew List<Meta^>();
        }

        Rule(YR_RULE* rule)
        {
            Identifier = marshal_as<String^>(rule->identifier);
            Tags = gcnew List<String^>();
            Metas = gcnew List<Meta^>();

            const char* tag = nullptr;

            yr_rule_tags_foreach(rule, tag)
            {
                Tags->Add(marshal_as<String^>(tag));
            }

            const YR_META* meta = nullptr;

            yr_rule_metas_foreach(rule, meta)
            {
                Meta^ storeme =
                    gcnew Meta(
                        marshal_as<String^>(meta->identifier),
                        marshal_as<String^>(meta->string));
                Metas->Add(storeme);
            }
        }
    };
}
