#pragma once

#include <yara.h>

using namespace System;

namespace libyaraNET {

    public ref class Rules
    {
        initonly YR_RULES* rules;

    public:
        Rules(YR_RULES* rules)
            : rules(rules)
        { }

        ~Rules()
        {
            if (rules) yr_rules_destroy(rules);
        }

        operator YR_RULES*()
        {
            return rules;
        }
    };
}
