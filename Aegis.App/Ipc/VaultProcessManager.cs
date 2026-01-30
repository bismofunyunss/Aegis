using System.Diagnostics;

namespace Aegis.App.Ipc
{
    internal sealed class VaultProcessManager
    {
        private Process? _vaultProcess;

        public void Start()
        {
            if (_vaultProcess != null && !_vaultProcess.HasExited)
                return;

            var startInfo = new ProcessStartInfo
            {
                FileName = "Aegis.Core.exe", // your separate process
                Arguments = "",
                UseShellExecute = false,
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Normal,
                RedirectStandardInput = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };

            _vaultProcess = Process.Start(startInfo);
        }

        public void Stop()
        {
            try
            {
                if (_vaultProcess != null && !_vaultProcess.HasExited)
                {
                    _vaultProcess.Kill(entireProcessTree: true);
                    _vaultProcess.Dispose();
                    _vaultProcess = null;
                }
            }
            catch { /* log if needed */ }
        }

        public bool IsRunning =>
            _vaultProcess != null && !_vaultProcess.HasExited;
    }
}
