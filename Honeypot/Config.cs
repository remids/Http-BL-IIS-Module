using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;


namespace Rds.Web.Modules.Honeypot
{
	public class Config : ConfigurationSection
	{
		const String SECTION_NAME = "honeypot";
		const String ACCESS_KEY = "accessKey";
		const String TEST_FAILURE = "testFailure";

		public static Config GetConfig()
		{
			return (Config)ConfigurationManager.GetSection(SECTION_NAME);
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
	}
}
