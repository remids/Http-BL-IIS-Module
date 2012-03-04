using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Timers;
using System.Web;

using Rds.Web.Modules.Honeypot;


namespace Rds.Web.Modules
{
	/// <summary>
	/// A module to check IP addresses against the Project Honeypot blacklist (http://projecthoneypot.org).
	/// </summary>
	/// <remarks>
	/// Each request is a DNS query.  To minimize this module's performance impact against site requests, 
	/// two tactics are taken:
	/// 
	///		1.	Since a given IP's status isn't likely to change from one minute to the next, we're going to
	///			cache results (pass or fail) and on subsequent calls from the same IP we'll check the
	///			cached result.  A cache result will be ejected after EXPIRATION_INTERVAL_IN_MINUTES minutes.
	///		2.	The verification is going to be done asyncronously, so the module does not need to worry about
	///			how fast the DNS checks are.  This means the first request from an IP will always go through,
	///			but if the IP is flagged, the second one should be stopped.
	/// 
	/// Uses .Net 4, due to the ConcurrentDictionary and System.Threading.Tasks for async fun.  Can be pulled 
	/// back if you take care of locking access to the dictionary yourself and use ThreadPool instead of TPL.
	/// 
	/// To use, add the following section in your configSections block (swap out {dll name} for yours):
	/// 
	///		&lt; configSections &gt;
	///			&lt; section name="honeypot" type="Rds.Web.Modules.ProjectHoneypotModule.Config" /&gt;
	///		&lt;/ configSections &gt;
	///
	/// You can then add the configuration section:
	/// 
	///		&lt; honeypot accessKey="{your key}" testFailure="true|false" /&gt;
	/// 
	/// The testFailure defaults to false, and is provided if you want to generate blocked requests to confirm
	/// it's working.  Don't use this in production - all requests are blocked.
	/// 
	/// There is no option currently to specify a threat threshold value, or to ignore search engines. Anything
	/// that returns a threat level, however insignificant, will be blocked.
	/// </remarks>
	public class ProjectHoneypotModule : IHttpModule
	{
		#region IpLookupResult struct

		struct IpLookupResult
		{
			public IpLookupResult(Boolean allowed, DateTime expiresOn, Boolean canRequery)
			{
				_Allowed = allowed;
				_ExpiresOn = expiresOn;
				_CanRequery = canRequery;
			}

			private readonly Boolean _Allowed;
			public Boolean Allowed
			{
				get { return _Allowed; }
			}

			private readonly DateTime _ExpiresOn;
			public DateTime ExpiresOn
			{
				get { return _ExpiresOn; }
			}

			private readonly Boolean _CanRequery;
			public Boolean CanRequery
			{
				get
				{
					return _CanRequery;
				}
			}
		}

		#endregion

		#region IHttpModule

		public void Dispose()
		{
			// Nothing to dispose
		}

		public void Init(HttpApplication context)
		{
			var cfg = Config.GetConfig();
			_HoneypotService = new HoneypotService(cfg.AccessKey, cfg.TestFailure); 
			
			context.BeginRequest += BeginRequest;
		}

		#endregion


		const Int32 EXPIRATION_INTERVAL_IN_MINUTES = 60;
		const Int32 CAN_REQUIRY_INTERVAL_IN_MINUTES = 10;
		const Int32 REVIEW_ADDRESS_LIST_INTERVAL = 5 * 60 * 1000;	// 5 minutes
		const Int32 HTTP_FORBIDDEN = 403;

		static readonly ConcurrentDictionary<String, IpLookupResult> _IpAdresses = new ConcurrentDictionary<String, IpLookupResult>();
		static readonly Timer _ReviewAddressListTimer = CreateTimer();

		private HoneypotService _HoneypotService;


		private void BeginRequest(object sender, EventArgs e)
		{
			var app = (HttpApplication)sender;
			var ipAddr = app.Request.ServerVariables["REMOTE_ADDR"];

			IpLookupResult info;

			if (!_IpAdresses.TryGetValue(ipAddr, out info)) {
				StartAsyncIpVerification(ipAddr);

			} else {
				if (info.CanRequery)
					StartAsyncIpVerification(ipAddr);

				if (!info.Allowed) {
					var resp = HttpContext.Current.Response;

					resp.StatusCode = HTTP_FORBIDDEN;
					resp.SuppressContent = true;
					resp.End();
				}
			}
		}


		private void StartAsyncIpVerification(String ipAddr)
		{
			Task.Factory.StartNew(() => {
				var honeypotResp = _HoneypotService.Lookup(ipAddr);
				_IpAdresses[ipAddr] = new IpLookupResult(AllowAccess(honeypotResp), DateTime.Now.AddMinutes(EXPIRATION_INTERVAL_IN_MINUTES), false);
			});
		}


		/// <summary>
		/// Verify response and determine whether we want to allow access or not.
		/// </summary>
		private static bool AllowAccess(Response resp)
		{
			if (resp.VisitorType != VisitorTypes.UnknownOrSafe && resp.VisitorType != VisitorTypes.SearchEngine)
				return false;

			return 0 == resp.ThreatScore;
		}


		/// <summary>
		/// Creates the timer that substract a request
		/// from the _IpAddress dictionary.
		/// </summary>
		private static Timer CreateTimer()
		{
			var timer = new Timer() { Interval = REVIEW_ADDRESS_LIST_INTERVAL };
			timer.Elapsed += TimerElapsed;
			timer.Start();

			return timer;
		}

		/// <summary>
		/// When an IP is checked, the result is cached for EXPIRATION_INTERVAL_IN_MINUTES minutes.  Every
		/// REVIEW_ADDRESS_LIST_INTERVAL milliseconds, this method will review the list of cached results and
		/// clear out those that should be reviewed.
		/// </summary>
		private static void TimerElapsed(object sender, ElapsedEventArgs e)
		{
			IpLookupResult ignore;
			var now = DateTime.Now;
			var canRequeryTimeStamp = DateTime.Now.AddMinutes(CAN_REQUIRY_INTERVAL_IN_MINUTES);

			foreach (var entry in _IpAdresses) {
				if (now < entry.Value.ExpiresOn) {
					_IpAdresses.TryRemove(entry.Key, out ignore);

				} else if (entry.Value.ExpiresOn < canRequeryTimeStamp && !entry.Value.Allowed) {
					// This entry is going to expire soon, if we get another request, it can be requeried so 
					// no additional requests from this address will slip unecessarily be allowed through.
					// Don't bother with safe IPs - they'll expire, and be requeried afterwards, same result.
					_IpAdresses[entry.Key] = new IpLookupResult(entry.Value.Allowed, entry.Value.ExpiresOn, true);
				}
			}
		}
	}
}
