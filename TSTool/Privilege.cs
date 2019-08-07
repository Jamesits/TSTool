using System;
using System.Runtime.InteropServices;

namespace TSTool
{

    public class Privileges
    {
        public const int SE_PRIVILEGE_ENABLED = 2;
        public const int TOKEN_ADJUST_PRIVILEGES = 32;
        public const int TOKEN_QUERY = 8;

        public static void SetPrivilege(string privilege)
        {
            int i1 = 0;
            var luid = new LUID();
            var token_PRIVILEGES = new TOKEN_PRIVILEGES();
            int i2 = OpenProcessToken(GetCurrentProcess(), 40, ref i1);
            if (i2 == 0)
                throw new Exception("OpenProcessToken For Privilege <" + privilege + "> Failed");
            i2 = LookupPrivilegeValue(null, privilege, ref luid);
            if (i2 == 0)
                throw new Exception("LookupPrivilegeValue For Privilege <" + privilege + "> Failed");
            token_PRIVILEGES.PrivilegeCount = 1;
            token_PRIVILEGES.Attributes = 2;
            token_PRIVILEGES.Luid = luid;
            i2 = AdjustTokenPrivileges(i1, 0, ref token_PRIVILEGES, 1024, 0, 0);
            if (i2 == 0)
                throw new Exception("AdjustTokenPrivileges For Privilege <" + privilege + "> Failed");
        }

        public static void GetAllPrivileges()
        {
            SetPrivilege("SeChangeNotifyPrivilege");
            SetPrivilege("SeSecurityPrivilege");
            SetPrivilege("SeBackupPrivilege");
            SetPrivilege("SeRestorePrivilege");
            SetPrivilege("SeSystemtimePrivilege");
            SetPrivilege("SeShutdownPrivilege");
            SetPrivilege("SeRemoteShutdownPrivilege");
            SetPrivilege("SeTakeOwnershipPrivilege");
            SetPrivilege("SeDebugPrivilege");
            SetPrivilege("SeSystemEnvironmentPrivilege");
            SetPrivilege("SeSystemProfilePrivilege");
            SetPrivilege("SeProfileSingleProcessPrivilege");
            SetPrivilege("SeIncreaseBasePriorityPrivilege");
            SetPrivilege("SeLoadDriverPrivilege");
            SetPrivilege("SeCreatePagefilePrivilege");
            SetPrivilege("SeIncreaseQuotaPrivilege");
            SetPrivilege("SeUndockPrivilege");
            SetPrivilege("SeManageVolumePrivilege");
            SetPrivilege("SeAssignPrimaryTokenPrivilege");
            SetPrivilege("SeAuditPrivilege");
            SetPrivilege("SeCreateGlobalPrivilege");
            SetPrivilege("SeCreatePermanentPrivilege");
            SetPrivilege("SeCreateSymbolicLinkPrivilege");
            SetPrivilege("SeCreateTokenPrivilege");
            SetPrivilege("SeEnableDelegationPrivilege");
            SetPrivilege("SeImpersonatePrivilege");
            SetPrivilege("SeIncreaseWorkingSetPrivilege");
            SetPrivilege("SeLockMemoryPrivilege");
            SetPrivilege("SeMachineAccountPrivilege");
            SetPrivilege("SeRelabelPrivilege");
            SetPrivilege("SeSecurityPrivilege");
            SetPrivilege("SeSyncAgentPrivilege");
            SetPrivilege("SeTcbPrivilege");
            SetPrivilege("SeTimeZonePrivilege");
            SetPrivilege("SeTrustedCredManAccessPrivilege");
            SetPrivilege("SeUnsolicitedInputPrivilege");
        }


        [PreserveSig]
        [DllImport("advapi32.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto)]
        public static extern int AdjustTokenPrivileges(int tokenhandle, int disableprivs,
                                                       [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES Newstate,
                                                       int bufferlength, int PreivousState, int Returnlength);

        [PreserveSig]
        [DllImport("kernel32.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto)]
        public static extern int GetCurrentProcess();

        [PreserveSig]
        [DllImport("advapi32.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto)]
        public static extern int LookupPrivilegeValue(string lpsystemname, string lpname,
                                                      [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

        [PreserveSig]
        [DllImport("advapi32.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto)]
        public static extern int OpenProcessToken(int ProcessHandle, int DesiredAccess, ref int tokenhandle);

        [PreserveSig]
        [DllImport("advapi32.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto,
            SetLastError = true)]
        public static extern int RegLoadKey(uint hKey, string lpSubKey, string lpFile);

        [PreserveSig]
        [DllImport("advapi32.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Auto,
            SetLastError = true)]
        public static extern int RegUnLoadKey(uint hKey, string lpSubKey);

        #region Nested type: LUID

        public struct LUID
        {
            public int HighPart;
            public int LowPart;
        }

        #endregion

        #region Nested type: TOKEN_PRIVILEGES

        public struct TOKEN_PRIVILEGES
        {
            public int Attributes;
            public LUID Luid;
            public int PrivilegeCount;
        }

        #endregion
    }
    
}
