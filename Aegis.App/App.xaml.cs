using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using Aegis.App.Core;

namespace Aegis.App;

public partial class App : Application
{
    private Process? _vaultProcess;


    protected override void OnStartup(
        StartupEventArgs e)
    {
        base.OnStartup(e);


        SystemSecurity.SecurityStatus securityStatus;

        try
        {
            securityStatus =
                SystemSecurity.GetStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Unable to determine Windows security status.\n\n" +
                $"{ex.Message}",
                "Aegis Security",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            Shutdown();
            return;
        }


        // =====================================================
        // REBOOT REQUIRED
        // =====================================================

        if (securityStatus.RebootRequired)
        {
            MessageBox.Show(
                "Aegis security protections have been configured, " +
                "but Windows must be restarted before they become active.",
                "Restart Required",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            Shutdown();
            return;
        }


        // =====================================================
        // SECURITY REQUIREMENTS NOT MET
        // =====================================================

        if (!securityStatus.MeetsRecommendations)
        {
            MessageBoxResult result =
                MessageBox.Show(
                    "Recommended Windows security protections are " +
                    "not currently enabled.\n\n" +
                    "Would you like Aegis to enable the required " +
                    "protections now?",
                    "Aegis Security",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);


            if (result != MessageBoxResult.Yes)
            {
                Shutdown();
                return;
            }


            // =================================================
            // ELEVATION REQUIRED
            // =================================================

            if (!securityStatus.IsAdministrator)
            {
                RelaunchElevated();
                return;
            }


            // =================================================
            // ENABLE SECURITY FEATURES
            // =================================================

            try
            {
                SystemSecurity.EnableRecommendedFeatures();
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show(
                    "Aegis was unable to modify the required " +
                    "Windows security settings because administrator " +
                    "privileges were not available.",
                    "Aegis Security",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);

                Shutdown();
                return;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Failed to configure Windows security protections.\n\n" +
                    ex.Message,
                    "Aegis Security",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);

                Shutdown();
                return;
            }


            // =================================================
            // REBOOT WINDOWS
            // =================================================

            MessageBox.Show(
                "The required Windows security protections have been " +
                "configured.\n\n" +
                "Windows must now restart before Aegis can continue.",
                "Restart Required",
                MessageBoxButton.OK,
                MessageBoxImage.Information);


            RestartWindows();
        }


        // =====================================================
        // SECURITY REQUIREMENTS ARE ALREADY SATISFIED
        // =====================================================

        //  StartVaultProcess();
    }


    // =========================================================
    // ELEVATED RELAUNCH
    // =========================================================

    private void RelaunchElevated()
    {
        string executablePath =
            Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Unable to determine application executable path.");


        try
        {
            Process.Start(
                new ProcessStartInfo
                {
                    FileName = executablePath,
                    UseShellExecute = true,
                    Verb = "runas"
                });
        }
        catch (Win32Exception)
        {
            MessageBox.Show(
                "Administrator privileges are required to configure " +
                "Aegis security protections.",
                "Aegis Security",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            Shutdown();
            return;
        }


        Shutdown();
    }


    // =========================================================
    // WINDOWS RESTART
    // =========================================================

    private static void RestartWindows()
    {
        Process.Start(
            new ProcessStartInfo
            {
                FileName = "shutdown.exe",
                Arguments = "/r /t 5 /f",
                UseShellExecute = true,
                CreateNoWindow = true
            });
    }


    // =========================================================
    // START AEGIS CORE
    // =========================================================

    private void StartVaultProcess()
    {
        if (_vaultProcess != null)
        {
            try
            {
                if (!_vaultProcess.HasExited)
                {
                    return;
                }
            }
            catch
            {
            }


            _vaultProcess.Dispose();
            _vaultProcess = null;
        }


        string path =
            Path.Combine(
                AppContext.BaseDirectory,
                "Aegis.Core.exe");


        if (!File.Exists(path))
        {
            MessageBox.Show(
                $"Aegis.Core.exe was not found.\n\n{path}",
                "Aegis",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            return;
        }


        try
        {
            _vaultProcess =
                Process.Start(
                    new ProcessStartInfo
                    {
                        FileName = path,

                        WorkingDirectory =
                            AppContext.BaseDirectory,

                        UseShellExecute = true,

                        CreateNoWindow = true,

                        WindowStyle =
                            ProcessWindowStyle.Hidden
                    });


            if (_vaultProcess == null)
            {
                MessageBox.Show(
                    "Aegis.Core.exe could not be started.",
                    "Aegis",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed to start Aegis.Core.exe.\n\n{ex.Message}",
                "Aegis",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    // =========================================================
    // APPLICATION EXIT
    // =========================================================

    protected override void OnExit(
        ExitEventArgs e)
    {
        try
        {
            if (_vaultProcess != null)
            {
                if (!_vaultProcess.HasExited)
                {
                    _vaultProcess.Kill(
                        entireProcessTree: true);

                    _vaultProcess.WaitForExit(
                        5000);
                }

                _vaultProcess.Dispose();
                _vaultProcess = null;
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Failed to stop Aegis.Core.exe: {ex}");
        }


        base.OnExit(e);
    }
}