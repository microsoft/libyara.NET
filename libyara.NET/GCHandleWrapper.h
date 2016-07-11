#pragma once

#include <stdexcept>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace libyaraNET {

    /// <summary>
    /// RAII wrapper for a GCHandle that frees the handle on scope exit.
    /// </summary>
    ref class GCHandleWrapper
    {
        GCHandle handle;

    public:
        /// <summary>
        /// Create a GCHandle that points to the specified object.
        /// </summary>
        GCHandleWrapper(Object^ value)
        {
            handle = GCHandle::Alloc(value);
        }

        ~GCHandleWrapper()
        {
            handle.Free();
        }

        /// <summary>
        /// Get the underlying GCHandle
        /// </summary>
        GCHandle^ GetHandle()
        {
            return handle;
        }

        /// <summary>
        /// Get the underlying GCHandle as a void*
        /// </summary>
        void* GetPointer()
        {
            return GCHandle::ToIntPtr(handle).ToPointer();
        }
    };
}
