using System;

namespace Rds.Web.Modules.Honeypot
{
	public class Response
	{
		public Response()
		{
			VisitorType = VisitorTypes.UnknownOrSafe;
			LastActivity = -1;
			ThreatScore = -1;
		}

		public String IpAddress { get; set; }
		public Boolean Allow { get; set; }
		public VisitorTypes VisitorType { get; set; }
		public Int16 LastActivity { get; set; }
		public Int16 ThreatScore { get; set; }
	}
}
