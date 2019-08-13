#pragma once

#include "Rule.h"

#include <yara.h>

using namespace System;
using namespace System::Collections::Generic;

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

        /// <summary>
        /// Split the compiled Rules set(i.e. YR_RULES) to
        /// get a list of compiled Rule objects(i.e. YR_RULE)
        /// </summary>
        List<Rule^>^ GetRules()
        {
            auto results = gcnew List<Rule^>();

            YR_RULE* rule;
            yr_rules_foreach(rules, rule)
            {
                results->Add(gcnew Rule(rule));
            }

            return results;
        }
    };
}
