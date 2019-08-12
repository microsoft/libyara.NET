using Microsoft.VisualStudio.TestTools.UnitTesting;

using libyaraNET;

namespace Tests
{
    [TestClass]
    public class describe_Rules
    {
        Compiler compiler;
        YaraContext ctx;

        [TestInitialize]
        public void before_each()
        {
            ctx = new YaraContext();
            compiler = new Compiler();
        }

        [TestCleanup]
        public void after_each()
        {
            ctx.Dispose();
        }

        [TestMethod]
        public void it_should_split_ruleset()
        {
            using (var ruleset = GetRuleSet(".\\Content\\CombinedRules.yara"))
            {
                var rules = ruleset.GetRules();
                Assert.AreEqual(2, rules.Count);
                Assert.AreEqual("ExampleRule1", rules[0].Identifier);
                Assert.AreEqual("ExampleRule2", rules[1].Identifier);
            }
        }

        private Rules GetRuleSet(string rulePath)
        {
            compiler.AddRuleFile(rulePath);
            return compiler.GetRules();
        }
    }
}
