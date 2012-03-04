using System;
using System.Net;
using System.Net.Sockets;


namespace Rds.Web.Modules.Honeypot
{
	public class HoneypotService
	{
		readonly String _AccessKey;
		readonly Boolean _TestFailure;


		public HoneypotService(String accessKey, Boolean testFailure = false)
		{
			_AccessKey = accessKey;
			_TestFailure = testFailure;
		}

		public Response Lookup(String address)
		{
			IPAddress ip;

			// If invalid/malformed ip address, assume malicious intent and disallow
			if (!IPAddress.TryParse(address, out ip))
				return new Response {
					ThreatScore = Int16.MaxValue
				};

			return Lookup(ip);
		}

		/// <summary>
		/// Project Honeypot DNS lookup on the provided IP address.
		/// </summary>
		/// <remarks>
		/// As of Jan 2012, Project Honeypot only supports IPv4 (and not IPv6).  As a result, if we
		/// have an address of anything other than IPv4, assume ok.
		/// </remarks>
		/// <param name="address">The IP address to verify.</param>
		/// <returns>The verification result.</returns>
		public Response Lookup(IPAddress ip)
		{
			if (ip.AddressFamily != AddressFamily.InterNetwork)
				return CreateAllowableIpResponse(ip);

			var ipBytes = ip.GetAddressBytes();
			var lookupName = String.Format("{0}.{1}.{2}.{3}.{4}.dnsbl.httpbl.org", _AccessKey, ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]);

			IPAddress[] lookupResult;

			try {
				lookupResult = _TestFailure ? CreateTestFailResult() : Dns.GetHostAddresses(lookupName);

			} catch (SocketException) {
				// As per Honeypot Project API docs, this is likely a valid address
				return CreateAllowableIpResponse(ip);
			}

			if (lookupResult == null || lookupResult.Length == 0)
				return CreateAllowableIpResponse(ip);

			return InitializeResponse(ip, lookupResult[0]);
		}


		private static IPAddress[] CreateTestFailResult()
		{
			var rnd = new Random(DateTime.Now.Millisecond);
			var lastActivity = (Byte)rnd.Next(1, 256);
			var threatScore = (Byte)rnd.Next(1, 256);
			var visitorType = (Byte)rnd.Next(1, 4);

			return new IPAddress[] { new IPAddress(new Byte[] { 127, lastActivity, threatScore, visitorType }) };
		}

		private static Response CreateAllowableIpResponse(IPAddress ip)
		{
			return new Response {
				IpAddress = ip,
				LastActivity = 0,
				ThreatScore = 0,
				VisitorType = VisitorTypes.UnknownOrSafe
			};
		}

		private static Response InitializeResponse(IPAddress ip, IPAddress result)
		{
			var resBytes = result.GetAddressBytes();

			if (resBytes[0] != 127)
				throw new ArgumentException(String.Format("Honeypot lookup result appears invalid.  ({0})", result));

			return new Response {
				IpAddress = ip,
				LastActivity = resBytes[1],
				ThreatScore = resBytes[2],
				VisitorType = (VisitorTypes)resBytes[3]
			};
		}
	}
}
