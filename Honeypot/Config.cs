using System;
using System.Configuration;


namespace Rds.Web.Modules.Honeypot
{
	public class Config : ConfigurationSection
	{
		const String SECTION_NAME = "honeypot";
		const String ACCESS_KEY = "accessKey";
		const String TEST_FAILURE = "testFailure";
		const String DISALLOWED_VISITOR_TYPES = "disallowedVisitorTypes";

		readonly VisitorTypes DEFAULT_DISALLOWED_VISITOR_TYPES = 
			VisitorTypes.CommentSpammer | 
			VisitorTypes.Harvester |
			VisitorTypes.Suspicious | 
			VisitorTypes.Reserved1 | 
			VisitorTypes.Reserved2 | 
			VisitorTypes.Reserved3 |
			VisitorTypes.Reserved4 | 
			VisitorTypes.Reserved5;

		public static Config GetConfig()
		{
			return (Config)ConfigurationManager.GetSection(SECTION_NAME);
		}


		public Config()
		{
			DisallowedVisitorTypes = DEFAULT_DISALLOWED_VISITOR_TYPES;
		}

		[ConfigurationProperty(ACCESS_KEY)]
		public String AccessKey
		{
			get { return (String)this[ACCESS_KEY]; }
			set { this[ACCESS_KEY] = value; }
		}

		[ConfigurationProperty(TEST_FAILURE)]
		public Boolean TestFailure
		{
			get { return (Boolean)this[TEST_FAILURE]; }
			set { this[TEST_FAILURE] = value; }
		}

		[ConfigurationProperty(DISALLOWED_VISITOR_TYPES)]
		public VisitorTypes DisallowedVisitorTypes
		{
			get { return (VisitorTypes)this[DISALLOWED_VISITOR_TYPES]; }
			set { this[DISALLOWED_VISITOR_TYPES] = value; }
		}
	}
}
