using libyaraNET;

using System;

namespace TestApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Use the QuickScan class when you don't need to reuse rules
            // or other yara objects. QuickScan handles all of the resource
            // management including the YaraContext.

            // var results = QuickScan.File(".\\SampleFile.txt", ".\\HelloWorldRules.yara");

            // When you need to reuse yara objects (e.g. when scanning multiple files) it's
            // more efficient to use the pattern below. Note that all yara operations must
            // take place within the scope of a YaraContext.
            using (var ctx = new YaraContext())
            {
                Rules rules = null;

                try
                {
                    Console.WriteLine("Compiling rules in HelloWorldRules.yara");
                    // Rules and Compiler objects must be disposed.
                    using (var compiler = new Compiler())
                    {
                        compiler.AddRuleFile(".\\HelloWorldRules.yara");
                        rules = compiler.GetRules();
                    }

                    // Scanner and ScanResults do not need to be disposed.
                    var scanner = new Scanner();
                    Console.WriteLine("Scanning file: SampleFile.txt");
                    var results = scanner.ScanFile(".\\SampleFile.txt", rules);
                    var found = results.Count > 0 ? "yes" : "no";
                    Console.WriteLine($"Matches found as a result of the scan: {found}");
                }
                finally
                {
                    // Rules and Compiler objects must be disposed.
                    if (rules != null) rules.Dispose();
                }
            }
        }
    }
}
