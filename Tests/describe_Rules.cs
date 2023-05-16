using libyaraNET;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests
{
    [TestClass]
    public class describe_Rules
    {
        private Compiler _compiler;
        private YaraContext _ctx;

        [TestInitialize]
        public void before_each()
        {
            _ctx = new YaraContext();
            _compiler = new Compiler();
        }

        [TestCleanup]
        public void after_each()
        {
            _ctx.Dispose();
        }

        [TestMethod]
        public void it_should_split_ruleset_when_one_rule_in_one_file()
        {
            using (var ruleset = GetRuleSet(".\\Content\\BasicRule.yara"))
            {
                var rules = ruleset.GetRules();

                Assert.AreEqual(1, rules.Count);
                Assert.AreEqual("BasicRule", rules[0].Identifier);
                Assert.AreEqual(0, rules[0].Tags.Count);
            }
        }

        [TestMethod]
        public void it_should_split_ruleset_when_multiple_rules_in_one_file()
        {
            using (var ruleset = GetRuleSet(".\\Content\\CombinedRules.yara"))
            {
                var rules = ruleset.GetRules();

                Assert.AreEqual(2, rules.Count);
                Assert.AreEqual("ExampleRule1", rules[0].Identifier);
                Assert.AreEqual(1, rules[0].Tags.Count);
                Assert.AreEqual("ExampleRule2", rules[1].Identifier);
                Assert.AreEqual(2, rules[1].Tags.Count);
            }
        }

        [TestMethod]
        public void it_should_iterate_meta_fields()
        {
            using (var ruleset = GetRuleSet(".\\Content\\BasicRule.yara"))
            {
                var rules = ruleset.GetRules();

                Assert.AreEqual(1, rules[0].Metas.Count);
                Assert.AreEqual("description", rules[0].Metas[0].Identifier);
                Assert.AreEqual("This is a meta field", rules[0].Metas[0].Value);
            }
        }

        private Rules GetRuleSet(string rulePath)
        {
            _compiler.AddRuleFile(rulePath);
            return _compiler.GetRules();
        }
    }
}
