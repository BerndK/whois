using System.Text;
using Whois.Servers;

namespace Whois.Visitors
{
    /// <summary>
    /// Gets the WHOIS server for a given domain.
    /// </summary>
    public class WhoisServerVisitor : VisitorBase
    {
        /// <summary>
        /// Gets or sets the whois server lookup.
        /// </summary>
        /// <value>The whois server lookup.</value>
        public IWhoisServerLookup WhoisServerLookup { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerVisitor"/> class.
        /// </summary>
        public WhoisServerVisitor() 
        {
            WhoisServerLookup = new IanaServerLookup();
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public override WhoisRecord Visit(WhoisRecord record)
        {
            var server = WhoisServerLookup.Lookup(record.Domain);

            // TODO: Validation on server

            record.Server = server;

            return record;
        }
    }
}