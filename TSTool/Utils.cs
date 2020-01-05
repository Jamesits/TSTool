using System;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;

namespace TSTool
{
    public static class Utils
    {
        public static string ByteArrayToString(byte[] data)
        {
            return "{ 0x" + BitConverter.ToString(data).Replace("-", ", 0x") + " }";
        }

        public static void RestartWindowsService(string serviceName, bool waitForStart=false)
        {
            ServiceController serviceController = new ServiceController(serviceName);
            try
            {
                if ((serviceController.Status.Equals(ServiceControllerStatus.Running)) || (serviceController.Status.Equals(ServiceControllerStatus.StartPending)))
                {
                    serviceController.Stop();
                }
                serviceController.WaitForStatus(ServiceControllerStatus.Stopped);
                serviceController.Start();
                if (waitForStart) serviceController.WaitForStatus(ServiceControllerStatus.Running);
                Console.WriteLine($"Service {serviceName} restarted");
            }
            catch
            {
                Console.WriteLine($"Service {serviceName} failed to restart");
            }
        }

        public static void PrintRegistrySecurity(RegistrySecurity security)
        {
            Console.WriteLine("\r\nCurrent access rules:\r\n");

            foreach (RegistryAccessRule ar in security.GetAccessRules(true, true, typeof(NTAccount)))
            {
                Console.WriteLine("        User: {0}", ar.IdentityReference);
                Console.WriteLine("        Type: {0}", ar.AccessControlType);
                Console.WriteLine("      Rights: {0}", ar.RegistryRights);
                Console.WriteLine(" Inheritance: {0}", ar.InheritanceFlags);
                Console.WriteLine(" Propagation: {0}", ar.PropagationFlags);
                Console.WriteLine("   Inherited? {0}", ar.IsInherited);
                Console.WriteLine();
            }
        }

        public static bool HasAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
