#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>
#include <string>
#include <yara.h>

#include "Rules.h"

using namespace System;
using namespace msclr::interop;

namespace libyaraNET {

    public ref class Compiler
    {
        YR_COMPILER* compiler;

    public:
        Compiler()
        {
            YR_COMPILER* temp;
            auto result = yr_compiler_create(&temp);
            compiler = temp;
        }

        ~Compiler()
        {
            if (compiler) yr_compiler_destroy(compiler);
        }

        void AddRuleFile(String^ rulesPath)
        {
            FILE* rulesFile;
            auto nativePath = marshal_as<std::string>(rulesPath);

            fopen_s(&rulesFile, nativePath.c_str(), "r");
            yr_compiler_add_file(compiler, rulesFile, nullptr, nativePath.c_str());
            fclose(rulesFile);
        }

        Rules^ GetRules()
        {
            YR_RULES* rules;
            auto result = yr_compiler_get_rules(compiler, &rules);

            return gcnew Rules(rules);
        }

        static Rules^ FromFile(String^ rulesPath)
        {
            auto compiler = gcnew Compiler();
            compiler->AddRuleFile(rulesPath);

            return compiler->GetRules();
        }
    };
}
