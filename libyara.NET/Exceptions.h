#pragma once

#include <yara\error.h>

using namespace System;
using namespace System::Collections::Generic;

namespace libyaraNET {

    public ref class CompilationException : public Exception
    {
    public:
        property List<String^>^ Errors;

        CompilationException(List<String^>^ errors)
            : Exception("Error compiling rules. See Errors property for details.")
        {
            // copy the list so other callers can't mess with it
            Errors = gcnew List<String^>(errors);
        }
    };

    public ref class ErrorUtility abstract sealed
    {
    public:
        static void ThrowOnError(int error)
        {
            switch (error)
            {
            case ERROR_SUCCESS:
                return;

            case ERROR_INSUFICIENT_MEMORY:
                throw gcnew OutOfMemoryException();

            default:
                break;
            }
        }
    };

}
