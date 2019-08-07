using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Principal;
using ProcessPrivileges;

namespace TSTool
{
    public static class TerminalService
    {
        private const string TimeBombRegistryKeyName = "System\\CurrentControlSet\\Control\\Terminal Server\\RCM\\GracePeriod";
        private const string TimeBombRegistryValueNameGA = "L$RTMTIMEBOMB_1320153D-8DA3-4e8e-B27B-0D888223A588";
        private const string TimeBombRegistryValueNameBeta = "L$GracePeriodTimeBomb_1320153D-8DA3-4e8e-B27B-0D888223A588";

        private const string TermServLicensingKeyName = "SOFTWARE\\Microsoft\\TermServLicensing";
        private const string TermServLicensingValueName = "RunAsRTM";

        private static string TimeBombRegistryValueName =>
            TLSIsBetaNTServer() ? TimeBombRegistryValueNameBeta : TimeBombRegistryValueNameGA;

        // ReSharper disable once InconsistentNaming
        /// <summary>
        /// TLSIsBetaNTServer in mstlsapi.dll
        /// </summary>
        /// <returns></returns>
        public static bool TLSIsBetaNTServer()
        {
            int RunAsRtm =
                Convert.ToInt32(Registry.GetValue("HKEY_LOCAL_MACHINE\\" + TermServLicensingKeyName, TermServLicensingValueName, -1));
            Debug.Print($"TLSIsBetaNTServer got {RunAsRtm}");
            return RunAsRtm == 4;
        }

        public static int GetGracePeriod(out long GracePeriodDays)
        {
            GracePeriodDays = 0;
            string path = null;
            try
            {
                var searcher = new ManagementObjectSearcher("root\\CIMV2\\TerminalServices", "SELECT * FROM Win32_TerminalServiceSetting");

                foreach (var o in searcher.Get())
                {
                    var queryObj = (ManagementObject) o;
                    path = queryObj["__PATH"].ToString().Split(":".ToCharArray(), 2)[1];
                    break;
                }
            }
            catch (ManagementException e)
            {
                Console.WriteLine("An error occurred while querying for WMI data Win32_TerminalServiceSetting: " + e.Message);
                return -1;
            }

            try
            {
                var classInstance = new ManagementObject("root\\CIMV2\\TerminalServices", path, null);
                var outParams = classInstance.InvokeMethod("GetGracePeriodDays", null, null);

                GracePeriodDays = Convert.ToInt64(outParams["DaysLeft"]);
                return Convert.ToInt32(outParams["ReturnValue"]);
            }
            catch (ManagementException err)
            {
                Console.WriteLine("An error occurred while trying to execute WMI method GetGracePeriodDays: " + err.Message);
                return -1;
            }
        }

        /// <summary>
        /// Get raw unencrypted Time Bomb data
        /// GetGracePeriodVal in mstlsapi.dll
        /// Requires Administrator privilege
        /// </summary>
        /// <returns>a FILETIME object (Int64)</returns>
        public static byte[] GetGracePeriodValRaw()
        {
            var value = (byte[])Registry.GetValue("HKEY_LOCAL_MACHINE\\" + TimeBombRegistryKeyName, TimeBombRegistryValueName, null);
            var ret = ProtectedData.Unprotect(value, null, DataProtectionScope.LocalMachine);
            Debug.Print($"GetGracePeriodVal returned raw data: {Utils.ByteArrayToString(ret)}");
            if (ret.Length > 8)
            {
                throw new InvalidDataException("Returned decrypted data size > 8 bytes");
            }

            return ret;
        }

        /// <summary>
        /// Set raw unencrypted Time Bomb data
        /// </summary>
        /// <param name="data">a FILETIME object (Int64)</param>
        public static void SetGracePeriodVal(byte[] data)
        {
            var p = ProtectedData.Protect(data, null, DataProtectionScope.LocalMachine);
            Registry.SetValue("HKEY_LOCAL_MACHINE\\" + TimeBombRegistryKeyName, TimeBombRegistryValueName, p);
        }

        /// <summary>
        /// Delete the registry key so we can start over from 120 days
        /// </summary>
        public static void ResetGracePeriodVal()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, true))
            {
                if (key == null)
                {
                    Console.WriteLine("The registry key doesn't exist yet");
                }
                else
                {
                    key.DeleteValue(TimeBombRegistryValueName);
                }
            }
        }

        private static readonly RegistryAccessRule AdminWritableRegistryAccessRule = new RegistryAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), 
            //Environment.UserDomainName + "\\" + Environment.UserName,
            // "Administrators",
            RegistryRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

        private static readonly RegistryAccessRule NwSvcWritableRegistryAccessRule = new RegistryAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
            RegistryRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

        private static readonly RegistryAccessRule NwSvcReadonlyRegistryAccessRule = new RegistryAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
            RegistryRights.ReadKey | RegistryRights.ReadPermissions | RegistryRights.EnumerateSubKeys | RegistryRights.QueryValues | RegistryRights.Notify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

        /// <summary>
        /// Bypass ACL by allowing Administrator to write to the key
        /// </summary>
        public static void SetGracePeriodRegistryKeyPermission()
        {
            RegistryKey key;
            RegistrySecurity rs;

            Process process = Process.GetCurrentProcess();
            using (new PrivilegeEnabler(process, new[]{ Privilege.TakeOwnership}))
            {
                Console.WriteLine("{0} => {1}", Privilege.TakeOwnership, process.GetPrivilegeState(Privilege.TakeOwnership));

                // first set owner to our own account
                key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
                rs = key.GetAccessControl();
                rs.SetOwner(new NTAccount(Environment.UserDomainName, Environment.UserName));
                key.SetAccessControl(rs);
                key.Close();

                // then add full control permission to Administrators
                key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions);
                rs = key.GetAccessControl();
                rs.AddAccessRule(AdminWritableRegistryAccessRule);
                key.SetAccessControl(rs);
                key.Close();
            }
        }

        /// <summary>
        /// Reset ACL
        /// </summary>
        public static void ResetGracePeriodRegistryKeyPermission()
        {
            using (new PrivilegeEnabler(Process.GetCurrentProcess(), Privilege.TakeOwnership))
            {
                // Privileges.SetPrivilege("SeBackupPrivilege");
                Privileges.SetPrivilege("SeRestorePrivilege");

                var key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions | RegistryRights.TakeOwnership);
                var rs = key.GetAccessControl();
                // the original owner is "NETWORK SERVICE" but I can't set owner to that
                rs.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
                // rs.RemoveAccessRule(NwSvcWritableRegistryAccessRule);
                // rs.RemoveAccessRule(AdminWritableRegistryAccessRule);
                // rs.AddAccessRule(NwSvcReadonlyRegistryAccessRule);
                key.SetAccessControl(rs);
                key.Close();
            }
        }

        /// <summary>
        /// Set Time Bomb data to N days after today
        /// </summary>
        /// <param name="days"></param>
        public static void SetGracePeriodVal(long days)
        {
            var endDate = DateTime.Now.AddDays(days);
            var endDateFileTime = endDate.ToFileTime();
            SetGracePeriodVal(BitConverter.GetBytes(endDateFileTime));
        }

        public static void RestartServices()
        {
            Utils.RestartWindowsService("SessionEnv");
            Utils.RestartWindowsService("TermService");
        }
    }
}
