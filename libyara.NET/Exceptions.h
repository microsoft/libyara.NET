#pragma once

#include <yara\error.h>

using namespace System;
using namespace System::Collections::Generic;

namespace libyaraNET {

    /// <summary>
    /// A generic yara error.
    /// See http://yara.readthedocs.io/en/v3.4.0/capi.html
    // for more information on yara error codes.
    /// </summary>
    public ref class YaraException sealed : public Exception
    {
    public:
        YaraException(int error)
            : Exception(String::Format("Yara error code {0}", error))
        { }

        // TODO: map error codes to nice strings
    };


    /// <summary>
    /// Represents a yara compilation error.
    /// </summary>
    public ref class CompilationException sealed : public Exception
    {
    public:
        property List<String^>^ Errors;

        CompilationException(List<String^>^ errors)
            : Exception(String::Format(
                "Error compiling rules.\n{0}", String::Join("\n", errors)))
        {
            // copy the list so other callers can't mess with it
            Errors = gcnew List<String^>(errors);
        }
    };


    /// <summary>
    /// Error handling utilities
    /// </summary>
    public ref class ErrorUtility abstract sealed
    {
    public:

        /// <summary>
        /// Throw the appropriate exception for the given yara error
        /// </summary>
        static void ThrowOnError(int error)
        {
            switch (error)
            {
            case ERROR_SUCCESS:
                return;

            case ERROR_INSUFICIENT_MEMORY:
                throw gcnew OutOfMemoryException();

            default:
                throw gcnew YaraException(error);
            }
        }
    };

}
