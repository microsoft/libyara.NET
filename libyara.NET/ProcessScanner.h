#pragma once

#include <cstdint>

#include "Compiler.h"
#include "Rules.h"
#include "YaraContext.h"

using namespace System;
using namespace System::Collections::Generic;
using namespace System::Runtime::InteropServices;

namespace libyaraNET {

    [UnmanagedFunctionPointer(CallingConvention::Cdecl)]
    delegate int YaraCallback(int message, void* data, void* context);


    public ref class ProcessScanner
    {
        YaraCallback^ callback;
        List<String^>^ matches;

    public:
        ProcessScanner()
        { }

        ~ProcessScanner()
        { }

        IList<String^>^ Scan(int processId)
        {
            auto ctx = gcnew YaraContext();
            auto compiler = gcnew Compiler();

            compiler->AddRuleFile("C:\\Users\\kylereed\\Desktop\\PE\\test_yara.txt");

            auto rules = compiler->GetRules();

            callback = gcnew YaraCallback(this, &ProcessScanner::HandleMessage);
            auto funcPtr = static_cast<YR_CALLBACK_FUNC>(
                Marshal::GetFunctionPointerForDelegate(callback).ToPointer());

            matches = gcnew List<String^>();

            yr_rules_scan_proc(
                rules,
                processId,
                0,
                funcPtr,
                nullptr,
                10000);

            return matches;
        }

    private:
        int HandleMessage(int message, void* data, void* context)
        {
            if (message == CALLBACK_MSG_RULE_MATCHING)
            {
                auto rule = (YR_RULE*)data;

                YR_STRING* string;

                yr_rule_strings_foreach(rule, string)
                {
                    YR_MATCH* match;

                    yr_string_matches_foreach(string, match)
                    {
                        matches->Add(Marshal::PtrToStringAnsi(IntPtr(match->data)));
                    }
                }
            }

            return 0;
        }
    };
}
