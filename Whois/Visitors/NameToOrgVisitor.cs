using System.Text;
using Whois.Net;
using Tokens;

namespace Whois.Visitors
{
    /// <summary>
    /// Visitor to set Registrant Name to Org
    /// </summary>
    public class NameToOrgVisitor : VisitorBase
    {
        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public override WhoisRecord Visit(WhoisRecord record)
        {
            if (record.Registrant?.Name != null && record.Registrant?.Organization == null)
                record.Registrant.Organization = record.Registrant?.Name;
            if (record.Domain != null && record.Registrant?.Organization == null)
            {
                if (record.Registrant == null)
                    record.Registrant = new Contact();
                record.Registrant.Organization = record.Domain;
            }
            return record;
        }
    }
}