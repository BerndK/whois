using System;
using System.Collections.Generic;
using System.IO;
using Whois.Net;
using Tokens;

namespace Whois.Servers
{
    /// <summary>
    /// Class to lookup a WHOIS server for a given domain name.
    /// </summary>
    public class IanaServerLookup : IWhoisServerLookup
    {
        /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>
        /// The TCP reader factory.
        /// </value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="IanaServerLookup"/> class.
        /// </summary>
        public IanaServerLookup()
        {
            TcpReaderFactory = new TcpReaderFactory();
        }

        /// <summary>
        /// Gets the TLD for a given domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        public string GetTld(string domain)
        {
            var tld = domain;

            if (!string.IsNullOrEmpty(domain))
            {
                var parts = domain.Split('.');

                if (parts.Length > 1) tld = parts[parts.Length - 1];
            }

            return tld;
        }

        /// <summary>
        /// Gets the pattern used to decode IANA WHOIS server reponses.
        /// </summary>
        /// <value>
        /// The pattern.
        /// </value>
        public string Pattern
        {
            get
            {
                var reader = new EmbeddedPatternReader();
                
                return reader.Read(GetType().Assembly, "Whois.Patterns.Servers.Iana.txt");
            }
        }

        /// <summary>
        /// Lookups the WHOIS server for the specified domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        public IWhoisServer Lookup(string domain)
        {
            //var tld = GetTld(domain);
            //var text = GetWhoisServerResponse(tld);

            //this will also handle IP addresses and the result is almost identical (just a additional refer, e.g. "refer:        whois.denic.de")
            var text = GetWhoisServerResponse(domain);

            var tokenizer = new Tokenizer();
            tokenizer.Options.ThrowExceptionOnMissingProperty = true;

            var record = tokenizer.Parse<WhoisServerRecord>(Pattern, text);

            record.Value.RawResponse = text;

            ParseServerUrlSecondChance(record, text);

            return record.Value;
        }

        private static void ParseServerUrlSecondChance(TokenResult<WhoisServerRecord> record, string text)
        {
            if (record.Value != null && record.Value.Url == null)
            {
                var lines = text.ToLines();
                foreach (var line in lines)
                {
                    if (line.StartsWith("whois:", StringComparison.OrdinalIgnoreCase))
                    {
                        var url = line.Remove(0, "whois:".Length).Trim();
                        record.Value.Url = url;
                    }
                }
            }
        }

        /// <summary>
        /// Queries the WHOIS server with the given TLD.
        /// </summary>
        /// <param name="tld">The TLD.</param>
        /// <returns></returns>
        private string GetWhoisServerResponse(string tld)
        {
            using (var tcpReader = TcpReaderFactory.Create())
            {
                return tcpReader.Read("whois.iana.org", 43, tld.ToUpper());
            }
        }
    }
}