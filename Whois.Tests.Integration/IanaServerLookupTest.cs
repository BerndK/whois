using System;
using NUnit.Framework;
using Whois.Net;
using Whois.Servers;

namespace Whois
{
    [TestFixture]
    public class IanaServerLookupTest
    {
        private IanaServerLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new IanaServerLookup { TcpReaderFactory = new TcpReaderFactory() };
        }

        [Test]
        public void TestLookupCom()
        {
            var result = lookup.Lookup("google.be");

            Assert.AreEqual("", result);
        }

        [TestCase("google.com")]
        [TestCase("google.de")]
        [TestCase("172.217.22.67")] //google.com
        [TestCase("216.58.208.35")] //google.de
        [TestCase("216.58.208.35")] //google.fr???
        [TestCase("46.29.100.76")] //telekom.de
        [TestCase("2a00:1450:4001:81c::200e")]
        [TestCase("google.be")]
        [TestCase("google.fr")]
        [TestCase("google.jp")]
        [TestCase("google.ch")]
        [TestCase("google.cn")]
        [TestCase("google.af")]
        [TestCase("telekom.de")]
        public void BkTests(string hostnameOrIp)
        {
            //var result = lookup.Lookup(hostnameOrIp);
            var result2 = new WhoisLookup().Lookup(hostnameOrIp);
            Console.WriteLine($"{hostnameOrIp} : {result2.Registrant?.Organization}\r\n\r\n{result2.Text}");

            Assert.AreNotEqual(null, result2.Registrant?.Organization);
        }

    }
}
