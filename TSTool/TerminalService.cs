using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Principal;

namespace TSTool
{
    public static class TerminalService
    {
        private const string TimeBombRegistryKeyName = @"System\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod";
        private const string TimeBombRegistryValueNameGa = "L$RTMTIMEBOMB_1320153D-8DA3-4e8e-B27B-0D888223A588";
        private const string TimeBombRegistryValueNameBeta = "L$GracePeriodTimeBomb_1320153D-8DA3-4e8e-B27B-0D888223A588";

        private const string TermServiceLicensingKeyName = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\TermServLicensing";
        private const string TermServiceLicensingValueName = "RunAsRTM";

        private const string TerminalServicesWimScope = @"root\CIMV2\TerminalServices";

        private static string TimeBombRegistryValueName =>
            TLSIsBetaNTServer() ? TimeBombRegistryValueNameBeta : TimeBombRegistryValueNameGa;

        // ReSharper disable once InconsistentNaming
        /// <summary>
        /// TLSIsBetaNTServer in mstlsapi.dll
        /// </summary>
        /// <returns></returns>
        public static bool TLSIsBetaNTServer()
        {
            var runAsRtm =
                Convert.ToInt32(Registry.GetValue(TermServiceLicensingKeyName, TermServiceLicensingValueName, -1));
            Debug.Print($"TLSIsBetaNTServer got {runAsRtm}");
            return runAsRtm == 4;
        }

        public static int GetGracePeriod(out long gracePeriodDays)
        {
            gracePeriodDays = 0;
            string path = null;
            try
            {
                var searcher = new ManagementObjectSearcher(TerminalServicesWimScope, "SELECT * FROM Win32_TerminalServiceSetting");

                foreach (var o in searcher.Get())
                {
                    var queryObj = (ManagementObject)o;
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
                var classInstance = new ManagementObject(TerminalServicesWimScope, path, null);
                var outParams = classInstance.InvokeMethod("GetGracePeriodDays", null, null);
                Debug.Assert(outParams != null, nameof(outParams) + " != null");

                gracePeriodDays = Convert.ToInt64(outParams["DaysLeft"]);
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
            var key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryRights.ReadKey);
            var value = (byte[])key.GetValue(TimeBombRegistryValueName, null);
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
            using (var key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, true))
            {
                key?.SetValue(TimeBombRegistryValueName, p, RegistryValueKind.Binary);
            }
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

        /// <summary>
        /// Bypass ACL by allowing Administrator to write to the key
        /// Returns the old ACL
        /// </summary>
        public static RegistrySecurity SetGracePeriodRegistryKeyPermission()
        {
            Privileges.SetPrivilege("SeTakeOwnershipPrivilege");
            Privileges.SetPrivilege("SeBackupPrivilege");
            Privileges.SetPrivilege("SeRestorePrivilege");

            var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var account = sid.Translate(typeof(NTAccount)) as NTAccount;

            RegistrySecurity oldRs;

            // compatibility hell(?)
            // https://docs.microsoft.com/en-us/windows/win32/winprog64/registry-redirector?redirectedfrom=MSDN
            // https://stackoverflow.com/questions/2464358/why-is-opensubkey-returning-null-on-my-windows-7-64-bit-system/16698274
            // var registryLocalMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var registryLocalMachine = Registry.LocalMachine;

            // first, back up old ACL
            using (RegistryKey rk = registryLocalMachine.OpenSubKey(TimeBombRegistryKeyName, false))
            {
                oldRs = rk?.GetAccessControl(AccessControlSections.All);
            }

            // then get owner
            using (RegistryKey rk = registryLocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership))
            {
                RegistrySecurity rs = rk?.GetAccessControl(AccessControlSections.All);
                rs?.SetOwner(account ?? throw new InvalidOperationException());
                rk?.SetAccessControl(rs ?? throw new InvalidOperationException());
            }

            using (RegistryKey rk = registryLocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions))
            {
                RegistrySecurity rs = rk?.GetAccessControl(AccessControlSections.All);
                Debug.Assert(account != null, nameof(account) + " != null");
                RegistryAccessRule rar = new RegistryAccessRule(
                    account.ToString(),
                    RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow);

                rs?.AddAccessRule(rar);
                rk?.SetAccessControl(rs ?? throw new InvalidOperationException());
            }

            return oldRs;
        }

        /// <summary>
        /// Reset ACL
        /// </summary>
        public static void SetGracePeriodRegistryKeyPermission(RegistrySecurity rs)
        {
            Privileges.SetPrivilege("SeTakeOwnershipPrivilege");
            Privileges.SetPrivilege("SeBackupPrivilege");
            Privileges.SetPrivilege("SeRestorePrivilege");

            var key = Registry.LocalMachine.OpenSubKey(TimeBombRegistryKeyName, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions | RegistryRights.TakeOwnership);
            if (key == null) return; // FIXME: should throw exception here
            key.SetAccessControl(rs);
            key.Close();
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
