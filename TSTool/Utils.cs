using System;
using System.ServiceProcess;

namespace TSTool
{
    public static class Utils
    {
        public static string ByteArrayToString(byte[] data)
        {
            return "{ 0x" + BitConverter.ToString(data).Replace("-", ", 0x") + " }";
        }

        public static void RestartWindowsService(string serviceName)
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
                serviceController.WaitForStatus(ServiceControllerStatus.Running);
                Console.WriteLine($"Service {serviceName} restarted");
            }
            catch
            {
                Console.WriteLine($"Service {serviceName} failed to restart");
            }
        }
    }
}
