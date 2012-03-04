using System;

namespace Rds.Web.Modules.Honeypot
{
	[Flags]
	public enum VisitorTypes
	{
		// Can't treat this as typical flag, cause it will always be considered included!
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
