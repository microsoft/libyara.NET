#pragma once

#include <yara.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace libyaraNET {

    // YR_CALLBACK_FUNC
    [UnmanagedFunctionPointer(CallingConvention::Cdecl)]
    delegate int YaraScanCallback(
        int message,
        void* data,
        void* context);

    // YR_COMPILER_CALLBACK_FUNC
    [UnmanagedFunctionPointer(CallingConvention::Cdecl)]
    delegate void YaraCompilerCallback(
        int error_level,
        const char* fileName,
        int lineNumber,
        const char* message,
        void* userData);

    /// <summary>
    /// Return values for scan callbacks.
    /// </summary>
    public enum class CallbackResult
    {
        Continue = CALLBACK_CONTINUE,
        Abort = CALLBACK_ABORT,
        Error = CALLBACK_ERROR
    };

    /// <summary>
    /// Options flags for scanners.
    /// </summary>
    [Flags]
    public enum class ScanFlags
    {
        None = 0,
        Fast = SCAN_FLAGS_FAST_MODE
    };

    /// <summary>
    /// Message type sent to callback
    /// </summary>
    public enum class CallbackMessage
    {
        RuleMatching = CALLBACK_MSG_RULE_MATCHING,
        RuleNotMatching = CALLBACK_MSG_RULE_NOT_MATCHING,
        ScanFinished = CALLBACK_MSG_SCAN_FINISHED,
        ImportModule = CALLBACK_MSG_IMPORT_MODULE,
        ModuleImported = CALLBACK_MSG_MODULE_IMPORTED
    };
}
