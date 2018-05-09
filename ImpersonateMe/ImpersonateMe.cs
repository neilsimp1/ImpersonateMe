using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ImpersonateMe {
    public static class ImpersonateMe {

		public static void RunAs(string domain, string username, string password, Action action) {
			const int LOGON32_PROVIDER_DEFAULT = 0;
			const int LOGON32_LOGON_INTERACTIVE = 2;

			bool isLogonSuccess = LogonUser(
				username,
				domain,
				password,
				LOGON32_LOGON_INTERACTIVE,
				LOGON32_PROVIDER_DEFAULT,
				out SafeAccessTokenHandle safeAccessTokenHandle
			);

			if (isLogonSuccess) {
				WindowsIdentity.RunImpersonated(safeAccessTokenHandle, () => { action(); });
			}
			else {
				int ret = Marshal.GetLastWin32Error();
				throw new System.ComponentModel.Win32Exception(ret);
			}
		}

		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] // Locks onto the windows logon DLL in .NET Framework 4.6+
		private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);
		//[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] // Locks onto the windows logon DLL in .NET Framework 4.6+
		//private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

	}
}
