#pragma once

#include <stdexcept>

namespace libyaraNET {

    /// <summary>
    /// Exception that wraps errors encounted when opening files.
    /// </summary>
    class file_error : public std::runtime_error
    {
        const errno_t error_;

    public:
        file_error(errno_t error, const char* message)
            : runtime_error(message)
            , error_(error)
        { }

        errno_t error() const { return error_; }
    };

    /// <summary>
    /// RAII wrapper for accessing a FILE*.
    /// </summary>
    class FileWrapper
    {
        FILE* file;

    public:
        FileWrapper(const char* path, const char* mode)
        {
            auto error = fopen_s(&file, path, mode);

            if (error)
                throw file_error(error, "Error opening file");
        }

        ~FileWrapper()
        {
            if (file) fclose(file);
        }

        /// <summary>
        /// Allow for implicit conversion to FILE*
        /// </summary>
        operator FILE*() const
        {
            return file;
        }
    };
}
