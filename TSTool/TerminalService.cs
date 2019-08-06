using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;
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

        private static readonly string user = Environment.UserDomainName + "\\" + Environment.UserName;

        private static readonly RegistryAccessRule AdminWritableRegistryAccessRule = new RegistryAccessRule(
            // new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), 
            "Administrators", 
            RegistryRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

        private static RegistrySecurity previousACL;
        // private static IdentityReference previousOwner;

        /// <summary>
        /// Bypass ACL by allowing Administrator to write to the key
        /// </summary>
        public static void SetGracePeriodRegistryKeyPermission()
        {
            Process process = Process.GetCurrentProcess();
            using (new PrivilegeEnabler(process, Privilege.TakeOwnership))
            {
                Debug.WriteLine("{0} => {1}", Privilege.TakeOwnership, process.GetPrivilegeState(Privilege.TakeOwnership));

                var key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, false);
                previousACL = key.GetAccessControl();
                // previousOwner = previousACL.GetOwner(typeof(System.Security.Principal.SecurityIdentifier));
                key.Close();
                key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
                var rs = key.GetAccessControl();
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
                var key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership);
                key.SetAccessControl(previousACL);
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
            var endDateFileTime = endDate.ToFileTimeUtc();
            SetGracePeriodVal(BitConverter.GetBytes(endDateFileTime));
        }

        public static void RestartServices()
        {
            Utils.RestartWindowsService("SessionEnv");
            Utils.RestartWindowsService("TermService");
        }
    }
}
