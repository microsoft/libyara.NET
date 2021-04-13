#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include "Rule.h"
#include "Match.h"

#include <yara.h>

using namespace System::Collections::Generic;
using namespace msclr::interop;

namespace libyaraNET {

    /// <summary>
    /// A matching rule and its matches collected during a scan.
    /// </summary>
    public ref class ScanResult sealed
    {
    public:
        property Rule^ MatchingRule;
        property Dictionary<String^, List<Match^>^>^ Matches;

        /// <summary>
        /// Create an empty scan result. Useful for testing.
        /// </summary>
        ScanResult()
        {
            MatchingRule = nullptr;
            Matches = gcnew Dictionary<String^, List<Match^>^>();
        }

        ScanResult(YR_SCAN_CONTEXT* context, YR_RULE* matchingRule)
        {
            MatchingRule = gcnew Rule(matchingRule);
            Matches = gcnew Dictionary<String^, List<Match^>^>();

            YR_STRING* string;
            YR_MATCH* match;

            yr_rule_strings_foreach(matchingRule, string)
            {
                auto identifier = marshal_as<String^>(string->identifier);

                yr_string_matches_foreach(context, string, match)
                {
                    if (!Matches->ContainsKey(identifier))
                        Matches->Add(identifier, gcnew List<Match^>());

                    Matches[identifier]->Add(gcnew Match(match));
                }
            }
        }
    };
}
