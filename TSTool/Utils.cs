using System;

namespace TSTool
{
    public static class Utils
    {
        public static string ByteArrayToString(byte[] data)
        {
            return "{ 0x" + BitConverter.ToString(data).Replace("-", ", 0x") + " }";
        }
    }
}
