#pragma once

#include "YaraContext.h"
#include "GCHandleWrapper.h"
#include "Compiler.h"
#include "Scanner.h"
#include "ScanResult.h"

#include <yara.h>

using namespace System::Collections::Generic;

namespace libyaraNET {

    /// <summary>
    /// Helper class that makes scanning easy. All resources
    /// are properly initialized and free'd after the scan.
    /// </summary>
    public ref class QuickScan abstract sealed
    {
    public:
        /// <summary>
        /// Scan a process's memory with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ Process(int processId, String^ rulesPath)
        {
            return Process(processId, rulesPath, ScanFlags::None);
        }

        /// <summary>
        /// Scan a process's memory with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ Process(
            int processId,
            String^ rulesPath,
            ScanFlags flags)
        {
            YaraContext ctx;
            Rules rules(Compiler::CompileRulesFile(rulesPath)->Release());
            Scanner scanner;

            return scanner.ScanProcess(processId, %rules, flags);
        }

        /// <summary>
        /// Scan a file with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ File(String^ path, String^ rulesPath)
        {
            return File(path, rulesPath, ScanFlags::None);
        }

        /// <summary>
        /// Scan a file with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ File(
            String^ path,
            String^ rulesPath,
            ScanFlags flags)
        {
            YaraContext ctx;
            Rules rules(Compiler::CompileRulesFile(rulesPath)->Release());
            Scanner scanner;

            return scanner.ScanFile(path, %rules, flags);
        }

        /// <summary>
        /// Scan a byte array with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ Memory(array<uint8_t>^ buffer, String^ rulesPath)
        {
            return Memory(buffer, rulesPath, ScanFlags::None);
        }

        /// <summary>
        /// Scan a byte array with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ Memory(
            array<uint8_t>^ buffer,
            String^ rulesPath,
            ScanFlags flags)
        {
            if (buffer == nullptr || buffer->Length == 0)
                return gcnew List<ScanResult^>();

            pin_ptr<uint8_t> pinned = &buffer[0];

            return Memory(IntPtr(pinned), buffer->Length, rulesPath, flags);
        }

        /// <summary>
        /// Scan a memory block with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ Memory(IntPtr buffer, int length, String^ rulesPath)
        {
            return Memory(buffer, length, rulesPath, ScanFlags::None);
        }

        /// <summary>
        /// Scan a memory block with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ Memory(
            IntPtr buffer,
            int length,
            String^ rulesPath,
            ScanFlags flags)
        {
            YaraContext ctx;
            Rules rules(Compiler::CompileRulesFile(rulesPath)->Release());
            Scanner scanner;

            return scanner.ScanMemory(buffer, length, %rules, flags);
        }
    };
}
