#pragma once

#include "YaraContext.h"
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
            YaraContext ctx;
            Rules rules(Compiler::CompileRulesFile(rulesPath)->Release());
            Scanner scanner;

            return scanner.ScanProcess(processId, %rules);
        }

        /// <summary>
        /// Scan a file with the specified rules file.
        /// </summary>
        static List<ScanResult^>^ File(String^ path, String^ rulesPath)
        {
            YaraContext ctx;
            Rules rules(Compiler::CompileRulesFile(rulesPath)->Release());
            Scanner scanner;

            return scanner.ScanFile(path, %rules);
        }
    };
}
