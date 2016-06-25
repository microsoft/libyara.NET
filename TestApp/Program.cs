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
                var scanner = new ProcessScanner();
                var results = scanner.Scan(20328);

                foreach (var r in results)
                {
                    Console.WriteLine(r);
                }
            }
        }
    }
}
