#pragma once

#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include "FileWrapper.h"
#include "Exceptions.h"
#include "Rules.h"
#include "YaraTypes.h"

#include <yara.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::ComponentModel;
using namespace msclr::interop;

namespace libyaraNET {

    /// <summary>
    /// Compiles yara rule files into Rules for scanning.
    /// This class is not thread safe and should only be
    /// called on the main thread.
    /// </summary>
    public ref class Compiler sealed
    {
        initonly YR_COMPILER* compiler;
        initonly List<String^>^ compilationErrors;
        initonly YaraCompilerCallback^ compilerCallback;

    public:
        /// <summary>
        /// Create a new compiler.
        /// </summary>
        Compiler()
        {
            YR_COMPILER* temp;
            ErrorUtility::ThrowOnError(yr_compiler_create(&temp));
            compiler = temp;

            compilationErrors = gcnew List<String^>();

            compilerCallback = gcnew YaraCompilerCallback(this, &Compiler::HandleError);
            auto funcPtr = Marshal::GetFunctionPointerForDelegate(compilerCallback).ToPointer();
            yr_compiler_set_callback(compiler, static_cast<YR_COMPILER_CALLBACK_FUNC>(funcPtr), nullptr);
        }

        ~Compiler()
        {
            if (compiler) yr_compiler_destroy(compiler);
        }

        /// <summary>
        /// Add rules from plain-text yara rule file.
        /// </summary>
        void AddRuleFile(String^ path)
        {
            compilationErrors->Clear();
            auto nativePath = marshal_as<std::string>(path);

            try
            {
                FileWrapper fw(nativePath.c_str(), "r");
                auto errors = yr_compiler_add_file(
                    compiler,
                    fw,
                    nullptr,
                    nativePath.c_str());

                if (errors)
                    throw gcnew CompilationException(compilationErrors);
            }
            catch (const file_error& err)
            {
                throw gcnew Win32Exception(err.error());
            }
        }

        /// <summary>
        /// Add rules from a string.
        /// </summary>
        void AddRuleString(String^ rule)
        {
            compilationErrors->Clear();
            auto nativeRule = marshal_as<std::string>(rule);

            auto errors = yr_compiler_add_string(
                compiler,
                nativeRule.c_str(),
                nullptr);

            if (errors)
                throw gcnew CompilationException(compilationErrors);
        }

        /// <summary>
        /// Get the compiled Rules object.
        /// </summary>
        Rules^ GetRules()
        {
            YR_RULES* rules;

            ErrorUtility::ThrowOnError(
                yr_compiler_get_rules(compiler, &rules));

            return gcnew Rules(rules);
        }

        /// <summary>
        /// Get the compiled Rules for the specified yara rules file.
        /// </summary>
        static Rules^ CompileRulesFile(String^ path)
        {
            Compiler c;
            c.AddRuleFile(path);

            return c.GetRules();
        }

        /// <summary>
        /// Get the compiled Rules for the specified yara rules string.
        /// </summary>
        static Rules^ CompileRulesString(String^ rule)
        {
            Compiler c;
            c.AddRuleString(rule);

            return c.GetRules();
        }

    private:
        void HandleError(
            int errorLevel,
            const char* fileName,
            int lineNumber,
            const YR_RULE* rule,
            const char* message,
            void* userData)
        {
            UNREFERENCED_PARAMETER(errorLevel);
            UNREFERENCED_PARAMETER(userData);

            auto msg = String::Format("{0} on line {1} in file: {2}",
                marshal_as<String^>(message),
                lineNumber,
                fileName ? marshal_as<String^>(fileName) : "[none]");

            compilationErrors->Add(msg);
        }
    };
}
