using System;
using System.Linq;
using System.Text;
using Tokens;
using Whois.Net;

namespace Whois.Visitors
{
    /// <summary>
    /// Downloads WHOIS information from the specified WHOIS server
    /// </summary>
    public class DownloadVisitor : VisitorBase
    {
        /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>The TCP reader factory.</value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DownloadVisitor"/> class.
        /// </summary>
        public DownloadVisitor()
        {
            TcpReaderFactory = new TcpReaderFactory();
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public override WhoisRecord Visit(WhoisRecord record)
        {
            if (record.Server == null)
            {
                throw new ArgumentException("Given WhoisRecord does not have the Server property set");
            }

            string url;
            do
            {
                url = record.Server.Url;
                if (url == null)
                    return record;
                Download(record);
                CheckForEnglishVersion(record);
                CheckForNewWhoIsServer(record);
            } while (url != record.Server.Url);
            
            return record;
        }

        private void Download(WhoisRecord record, string domainSuffix = null)
        {
            using (var tcpReader = TcpReaderFactory.Create(Encoding))
            {
                record.Text = tcpReader.Read(record.Server.Url, 43, record.Domain + domainSuffix);
            }
        }

        private void CheckForEnglishVersion(WhoisRecord record)
        {
            if (record.Text.Contains("add'/e'") && !record.Server.Url.EndsWith("/e"))
            {
                Download(record, "/e");
            }
        }

        private void CheckForNewWhoIsServer(WhoisRecord record)
        {
            var lines = record.Text.ToLines().Select(l => l.Trim());
            var line = lines.FirstOrDefault(l => l.StartsWith("Registrar WHOIS Server:", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var url = line.Remove(0, "Registrar WHOIS Server:".Length).Trim();
                record.Server.Url = url;
            }
        }
    }
}