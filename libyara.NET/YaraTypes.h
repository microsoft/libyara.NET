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
}
