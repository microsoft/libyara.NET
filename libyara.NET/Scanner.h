#pragma once

#include "Exceptions.h"
#include "GCHandleWrapper.h"
#include "Rules.h"
#include "ScanResult.h"
#include "YaraTypes.h"

#include <yara.h>

using namespace System;
using namespace System::Collections::Generic;
using namespace System::IO;
using namespace System::Runtime::InteropServices;

namespace libyaraNET {

    public interface class IScanner
    {
        List<ScanResult^>^ ScanFile(String^ path, Rules^ rules);
        List<ScanResult^>^ ScanFile(String^ path, Rules^ rules, ScanFlags flags);

        List<ScanResult^>^ ScanProcess(int processId, Rules^ rules);
        List<ScanResult^>^ ScanProcess(int processId, Rules^ rules, ScanFlags flags);

        List<ScanResult^>^ ScanMemory(array<uint8_t>^ buffer, Rules^ rules);
        List<ScanResult^>^ ScanMemory(array<uint8_t>^ buffer, Rules^ rules, ScanFlags flags);
        List<ScanResult^>^ ScanMemory(IntPtr buffer, int length, Rules^ rules);
        List<ScanResult^>^ ScanMemory(IntPtr buffer, int length,  Rules^ rules, ScanFlags flags);
    };

    /// <summary>
    /// Wraps the yara scanning functions to scan processes or files.
    /// This calls to the scanning functions is threadsafe.
    /// </summary>
    public ref class Scanner sealed : IScanner
    {
        // TODO make parameter
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
        virtual List<ScanResult^>^ ScanFile(String^ path, Rules^ rules)
        {
            return ScanFile(path, rules, ScanFlags::None);
        }

        /// <summary>
        /// Scan a file with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanFile(
            String^ path,
            Rules^ rules,
            ScanFlags flags)
        {
            if (!File::Exists(path))
                throw gcnew FileNotFoundException(path);

            auto results = gcnew List<ScanResult^>();
            auto nativePath = marshal_as<std::wstring>(path);
            auto fd = CreateFile(nativePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);

            GCHandleWrapper resultsHandle(results);

            ErrorUtility::ThrowOnError(
                yr_rules_scan_fd(
                    rules,
                    fd,
                    (int)flags,
                    callbackPtr,
                    resultsHandle.GetPointer(),
                    TimeoutSeconds));

            return results;
        }

        /// <summary>
        /// Scan a process's memory with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanProcess(int processId, Rules^ rules)
        {
            return ScanProcess(processId, rules, ScanFlags::None);
        }

        /// <summary>
        /// Scan a process's memory with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanProcess(
            int processId,
            Rules^ rules,
            ScanFlags flags)
        {
            auto results = gcnew List<ScanResult^>();
            GCHandleWrapper resultsHandle(results);

            ErrorUtility::ThrowOnError(
                yr_rules_scan_proc(
                    rules,
                    processId,
                    (int)flags,
                    callbackPtr,
                    resultsHandle.GetPointer(),
                    TimeoutSeconds));

            return results;
        }

        /// <summary>
        /// Scan a byte array with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanMemory(array<uint8_t>^ buffer, Rules^ rules)
        {
            return ScanMemory(buffer, rules, ScanFlags::None);
        }

        /// <summary>
        /// Scan a byte array with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanMemory(
            array<uint8_t>^ buffer,
            Rules^ rules,
            ScanFlags flags)
        {
            if (buffer == nullptr || buffer->Length == 0)
                return gcnew List<ScanResult^>();

            pin_ptr<uint8_t> pinned = &buffer[0];
            return ScanMemory(pinned, buffer->Length, rules, flags);
        }

        /// <summary>
        /// Scan a memory block with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanMemory(
            IntPtr buffer,
            int length,
            Rules^ rules)
        {
            return ScanMemory(buffer, length, rules, ScanFlags::None);
        }

        /// <summary>
        /// Scan a memory block with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanMemory(
            IntPtr buffer,
            int length,
            Rules^ rules,
            ScanFlags flags)
        {
            return ScanMemory((uint8_t*)buffer.ToPointer(), length, rules, flags);
        }

        /// <summary>
        /// Scan a memory block with the specified rules.
        /// </summary>
        virtual List<ScanResult^>^ ScanMemory(
            uint8_t* buffer,
            int length,
            Rules^ rules,
            ScanFlags flags)
        {
            auto results = gcnew List<ScanResult^>();
            GCHandleWrapper resultsHandle(results);

            ErrorUtility::ThrowOnError(
                yr_rules_scan_mem(
                    rules,
                    buffer,
                    length,
                    (int)flags,
                    callbackPtr,
                    resultsHandle.GetPointer(),
                    TimeoutSeconds));

            return results;
        }

    private:
        int HandleMessage(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
        {
            if (message == CALLBACK_MSG_RULE_MATCHING)
            {
                auto resultsHandle = GCHandle::FromIntPtr(IntPtr(user_data));
                auto results = (List<ScanResult^>^)resultsHandle.Target;

                results->Add(gcnew ScanResult(context, (YR_RULE*)message_data));
            }

            return (int)CallbackResult::Continue;
        }
    };
}
