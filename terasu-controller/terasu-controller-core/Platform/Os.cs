using System.Runtime.InteropServices;

namespace Terasu.Controller.Core.Platform
{
    public static class Os
    {
        public static bool IsWindows
        {
            get => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }
        public static bool IsMacOS
        {
            get => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }
        public static bool IsLinux
        {
            get => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }
    }
}
