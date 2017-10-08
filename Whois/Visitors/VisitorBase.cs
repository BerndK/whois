using System.Text;

namespace Whois.Visitors
{
    public abstract class VisitorBase : IWhoisVisitor
    {
        protected VisitorBase()
        {
            Encoding = Encoding.UTF8;
        }

        /// <summary>
        /// Gets the current character encoding that the current TcpReader
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current reader.</returns>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public abstract WhoisRecord Visit(WhoisRecord record);
    }
}