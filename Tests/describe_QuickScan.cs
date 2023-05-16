using libyaraNET;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Text;

namespace Tests
{
    [TestClass]
    public class describe_QuickScan
    {
        private readonly string _rulesPath = ".\\Content\\BasicRule.yara";
        private readonly string _testPath = ".\\Content\\HelloWorld.txt";
        private readonly string _unicodeTestPath = ".\\Content\\菜单模块.txt";

        [TestMethod]
        public void it_should_scan_files()
        {
            var results = QuickScan.File(_testPath, _rulesPath);

            Assert.AreEqual(1, results.Count);
            Assert.AreEqual(1, results[0].Matches.Count);
            Assert.AreEqual(2, results[0].Matches["$hw"].Count);
            Assert.AreEqual(0x1eUL, results[0].Matches["$hw"][0].Offset);
        }

        [TestMethod]
        public void it_should_scan_files_with_unicode_filenames()
        {
            var results = QuickScan.File(_unicodeTestPath, _rulesPath);

            Assert.AreEqual(1, results.Count);
            Assert.AreEqual(1, results[0].Matches.Count);
            Assert.AreEqual(2, results[0].Matches["$hw"].Count);
            Assert.AreEqual(0x1eUL, results[0].Matches["$hw"][0].Offset);
        }

        [TestMethod]
        public void it_should_scan_memory()
        {
            var str = "hello world ! hello world";
            var data = Encoding.ASCII.GetBytes(str);

            var results = QuickScan.Memory(data, _rulesPath);

            Assert.AreEqual(1, results.Count);
            Assert.AreEqual(1, results[0].Matches.Count);
            Assert.AreEqual(2, results[0].Matches["$hw"].Count);
            Assert.AreEqual(0UL, results[0].Matches["$hw"][0].Offset);
        }

        [TestMethod]
        public void fast_memory_scan_should_only_return_one_result()
        {
            var str = "hello world ! hello world";
            var data = Encoding.ASCII.GetBytes(str);

            var results = QuickScan.Memory(data, _rulesPath, ScanFlags.Fast);

            Assert.AreEqual(1, results.Count);
            Assert.AreEqual(1, results[0].Matches.Count);
            Assert.AreEqual(1, results[0].Matches["$hw"].Count);
            Assert.AreEqual(0UL, results[0].Matches["$hw"][0].Base);
        }
    }
}
