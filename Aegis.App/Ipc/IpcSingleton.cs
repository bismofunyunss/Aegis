using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.App.Ipc
{
    public static class AppServices
    {
        public static IpcClient IpcClient { get; } =
            new IpcClient();
        public static Core.VaultClientService Core { get; } = new(IpcClient);
    }
}
