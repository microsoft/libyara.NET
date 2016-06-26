#pragma once

#include <yara.h>

using namespace System;

namespace libyaraNET {

    /// <summary>
    /// A container for compiled yara rules.
    /// </summary>
    public ref class Rules sealed
    {
        YR_RULES* rules;

    public:
        /// <summary>
        /// Wrap native YR_RULES pointer.
        /// </summary>
        Rules(YR_RULES* rules)
            : rules(rules)
        { }

        ~Rules()
        {
            if (rules) yr_rules_destroy(rules);
        }

        /// <summary>
        /// Allow for implicit cast to a YR_RULES*
        /// </summary>
        operator YR_RULES*()
        {
            return rules;
        }

        /// <summary>
        /// Release management of the underlying YR_RULES*
        /// allowing another object to own the resource.
        /// </summary>
        YR_RULES* Release()
        {
            auto temp = rules;
            rules = nullptr;

            return temp;
        }
    };
}
