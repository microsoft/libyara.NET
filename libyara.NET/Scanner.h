#pragma once

#include "Exceptions.h"
#include "Rules.h"
#include "ScanResult.h"
#include "YaraTypes.h"

#include <yara.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::IO;
using namespace System::Runtime::InteropServices;

namespace libyaraNET {

    /// <summary>
    /// Wraps the yara scanning functions to scan processes or files.
    /// This calls to the scanning functions is threadsafe.
    /// </summary>
    public ref class Scanner sealed
    {
        // TODO make parameters
        const int DefaultScanFlags = (int)ScanFlags::None;
        const int TimeoutSeconds = 10000;

        YR_CALLBACK_FUNC callbackPtr;
        YaraScanCallback^ scanCallback;

    public:
        /// <summary>
        /// Create a new scanner that can scan processes or files.
        /// </summary>
        Scanner()
        {
            scanCallback = gcnew YaraScanCallback(this, &Scanner::HandleMessage);
            auto funcPtr = Marshal::GetFunctionPointerForDelegate(scanCallback).ToPointer();
            callbackPtr = static_cast<YR_CALLBACK_FUNC>(funcPtr);
        }

        /// <summary>
        /// Scan a file with the specified rules.
        /// </summary>
        List<ScanResult^>^ ScanFile(String^ path, Rules^ rules)
        {
            if (!File::Exists(path))
                throw gcnew FileNotFoundException(path);

            auto results = gcnew List<ScanResult^>();
            auto resultsHandle = GCHandle::Alloc(results);
            auto nativePath = marshal_as<std::string>(path);

            ErrorUtility::ThrowOnError(
                yr_rules_scan_file(
                    rules,
                    nativePath.c_str(),
                    DefaultScanFlags,
                    callbackPtr,
                    GCHandle::ToIntPtr(resultsHandle).ToPointer(),
                    TimeoutSeconds));

            return results;
        }

        /// <summary>
        /// Scan a process's memory with the specified rules.
        /// </summary>
        List<ScanResult^>^ ScanProcess(int processId, Rules^ rules)
        {
            auto results = gcnew List<ScanResult^>();
            auto resultsHandle = GCHandle::Alloc(results);

            ErrorUtility::ThrowOnError(
                yr_rules_scan_proc(
                    rules,
                    processId,
                    DefaultScanFlags,
                    callbackPtr,
                    GCHandle::ToIntPtr(resultsHandle).ToPointer(),
                    TimeoutSeconds));

            return results;
        }

    private:
        int HandleMessage(int message, void* data, void* context)
        {
            if (message == CALLBACK_MSG_RULE_MATCHING)
            {
                auto resultsHandle = GCHandle::FromIntPtr(IntPtr(context));
                auto results = (List<ScanResult^>^)resultsHandle.Target;

                results->Add(gcnew ScanResult((YR_RULE*)data));
            }

            return (int)CallbackResult::Continue;
        }
    };
}
