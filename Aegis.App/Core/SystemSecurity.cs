using Microsoft.Win32;
using System;
using System.Management;
using System.Windows;

public static class SystemSecurity
{
    /// <summary>
    /// Checks if Virtualization-Based Security (VBS) is enabled.
    /// </summary>
    public static bool IsVbsEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
            if (key != null)
            {
                var vbsValue = key.GetValue("EnableVirtualizationBasedSecurity");
                return vbsValue is int val && val != 0;
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Enables VBS via registry (requires reboot).
    /// </summary>
    public static void EnableVbs()
    {
        using var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
        key.SetValue("EnableVirtualizationBasedSecurity", 1, RegistryValueKind.DWord);

        // Optional: enable hypervisor launch
        using var hkey = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
        hkey.SetValue("Enabled", 1, RegistryValueKind.DWord);

        MessageBox.Show("VBS has been enabled. Please reboot for changes to take effect.", "VBS Enabled", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    /// <summary>
    /// Checks if Kernel DMA Protection is enabled.
    /// </summary>
    public static bool IsKernelDmaProtectionEnabled()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftTpm", "SELECT * FROM Win32_DeviceGuard");
            foreach (var obj in searcher.Get())
            {
                if (obj["KernelDMAProtectionStatus"] is uint val)
                    return val != 0;
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Enables Kernel DMA Protection (requires reboot).
    /// </summary>
    public static void EnableKernelDmaProtection()
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\KernelDMAProtection");
            key.SetValue("Enabled", 1, RegistryValueKind.DWord);

            MessageBox.Show("Kernel DMA Protection has been enabled. Please reboot for changes to take effect.", "DMA Protection Enabled", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to enable Kernel DMA Protection: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// Ensures VBS and DMA protection are enabled.
    /// </summary>
    public static void EnsureSecurityEnabled()
    {
        if (!IsVbsEnabled())
            EnableVbs();

        if (!IsKernelDmaProtectionEnabled())
            EnableKernelDmaProtection();
    }
}

