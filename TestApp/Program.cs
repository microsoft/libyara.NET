using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using libyaraNET;

namespace TestApp
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var ctx = new YaraContext())
            {
                var rules = Compiler.CompileRulesFile(".\\HelloWorldRules.yara");

            }
        }
    }
}
