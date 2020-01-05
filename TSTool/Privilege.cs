using System;
using System.Runtime.InteropServices;

namespace TSTool
{

    public class Privileges
    {

        public static bool SetPrivilege(string privilege)
        {
            UInt64 privilegeId = 0;
            if (!LookupPrivilegeValue(null, privilege, ref privilegeId))
                throw new Exception("LookupPrivilegeValue For Privilege <" + privilege + "> Failed");

            var enabled = false;

            RtlAdjustPrivilege(privilegeId, true, false, ref enabled);

            return enabled;
        }

        [DllImport("advapi32.dll")]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref UInt64 lpLuid);

        [DllImport("ntdll.dll", EntryPoint = "RtlAdjustPrivilege")]
        public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);

    }
    
}
