using System;
using System.Collections.Generic;
using System.Linq;

namespace Rds.Web.Modules.Honeypot
{
	[Flags]
	public enum VisitorTypes
	{
		SearchEngine = 0,
		Suspicious = 1,
		Harvester = 2,
		CommentSpammer = 4,
		Reserved1 = 8,
		Reserved2 = 16,
		Reserved3 = 32,
		Reserved4 = 64,
		Reserved5 = 128,
		UnknownOrSafe = 256		// Note: this is not an Http:BL enum value
	}
}
