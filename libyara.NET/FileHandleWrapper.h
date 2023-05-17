#pragma once

#include <Windows.h>

namespace libyaraNET {

    struct file_handle
    {
    private:
        HANDLE handle_;

    public:
        // has to be explicit otherwise this binds better than the move ctor
        template <typename... Args>
        explicit file_handle(Args&&... args)
            : handle_(CreateFile(std::forward<Args>(args)...)) { }

        // wrap existing handle
        file_handle(HANDLE handle)
            : handle_(handle) { }

        // hide cctor
        file_handle(const file_handle&) = delete;

        // hide assignment
        file_handle& operator=(const file_handle& other) = delete;

        // move ctor to prevent closing handle with copies
        file_handle(file_handle&& other)
            : handle_(other.handle_)
        {
            other.handle_ = INVALID_HANDLE_VALUE;
        }

        ~file_handle()
        {
            if (is_invalid()) return;

            CloseHandle(handle_);
        }

        operator HANDLE() const { return handle_; }

        bool is_invalid() const { return handle_ == INVALID_HANDLE_VALUE; }
    };
}
