using System.Collections.Generic;
using System.Linq;
using System.Text;
using Tokens;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses WHOIS data and extracts data into structured objects
    /// </summary>
    public class PatternExtractorVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding Encoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PatternExtractorVisitor" /> class.
        /// </summary>
        public PatternExtractorVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PatternExtractorVisitor" /> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public PatternExtractorVisitor(Encoding encoding)
        {
            Encoding = encoding;
        }

        /// <summary>
        /// Gets all the embdedded patterns in the assembly.
        /// </summary>
        /// <returns></returns>
        public IList<EmbeddedResource> GetEmbeddedPatterns()
        {
            var reader = new EmbeddedPatternReader();

            return reader.ReadNamespaceWithName(GetType().Assembly, "Whois.Patterns.Domains");
        } 

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            var results = MatchPatterns(record);

            if (results.Any())
            {
                record = results.First().Value.Value;
                record.PatternFile = results.First().Name;
            }

            return record;
        }

        public IList<TokenizerResult> MatchPatterns(WhoisRecord record)
        {
            var results = new List<TokenizerResult>();

            var patterns = GetEmbeddedPatterns();

            foreach (var pattern in patterns)
            {
                var tokenizer = new Tokenizer();

                var clone = record.Clone() as WhoisRecord;

                var result = tokenizer.Parse(clone, pattern.Value, record.Text);

                results.Add(new TokenizerResult {Name = pattern.Name, Value = result });
            }

            return results.OrderByDescending(r => r.Value.Replacements.Count).ToList();
        }

        public class TokenizerResult
        {
            public string Name { get; set; }
            public TokenResult<WhoisRecord> Value { get; set; }
        }
    }
}