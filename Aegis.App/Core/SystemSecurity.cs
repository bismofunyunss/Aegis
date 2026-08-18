using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Aegis.App.Core;

public static class SystemSecurity
{
    // =========================================================
    // WMI / CIM
    // =========================================================

    private const string DeviceGuardNamespace =
        @"root\Microsoft\Windows\DeviceGuard";

    private const string DeviceGuardClass =
        "Win32_DeviceGuard";

    private const string TpmNamespace =
        @"root\CIMV2\Security\MicrosoftTpm";

    private const string TpmClass =
        "Win32_Tpm";


    // =========================================================
    // REGISTRY PATHS
    // =========================================================

    private const string DeviceGuardRegistryPath =
        @"SYSTEM\CurrentControlSet\Control\DeviceGuard";

    private const string HvciRegistryPath =
        @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";

    private const string LsaRegistryPath =
        @"SYSTEM\CurrentControlSet\Control\Lsa";

    private const string CurrentVersionRegistryPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";


    // =========================================================
    // DEVICE GUARD SERVICE IDS
    //
    // Microsoft Win32_DeviceGuard:
    //
    // 1 = Credential Guard
    // 2 = Hypervisor-enforced Code Integrity
    //
    // Do not infer other IDs as Credential Guard.
    // =========================================================

    private const int CredentialGuardServiceId = 1;
    private const int HvciServiceId = 2;


    // =========================================================
    // SECURITY PROPERTY IDS
    //
    // Win32_DeviceGuard:
    //
    // 3 = DMA Protection
    // =========================================================

    private const int DmaProtectionPropertyId = 3;

    // =========================================================
    // TPM 2.0 DETECTION
    //
    // Uses TPM Base Services (TBS) instead of Win32_Tpm WMI.
    //
    // This is preferable for security-status detection because
    // Win32_Tpm can return Access Denied for non-elevated users.
    //
    // Tbsi_GetDeviceInfo directly reports the TPM version.
    // =========================================================

    private const uint TBS_SUCCESS =
        0x00000000;

    private const uint TBS_E_TPM_NOT_FOUND =
        0x8028400F;

    private const uint TPM_VERSION_12 =
        0x00000001;

    private const uint TPM_VERSION_20 =
        0x00000002;


    [StructLayout(
        LayoutKind.Sequential)]
    private struct TPM_DEVICE_INFO
    {
        public uint StructVersion;

        public uint TpmVersion;

        public uint TpmInterfaceType;

        public uint TpmImpRevision;
    }


    [DllImport(
        "tbs.dll",
        ExactSpelling = true,
        CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsi_GetDeviceInfo(
        uint size,
        out TPM_DEVICE_INFO info);


    // =========================================================
    // PUBLIC API
    // =========================================================

    public static SecurityStatus GetStatus()
    {
        List<string> detectionErrors = new();

        WindowsEditionInfo edition =
            GetWindowsEdition(detectionErrors);

        DeviceGuardSnapshot deviceGuard =
            GetDeviceGuardSnapshot(detectionErrors);

        SecurityFeatureState secureBoot =
            GetSecureBootState(detectionErrors);

        SecurityFeatureState tpm =
            GetTpm20State(detectionErrors);

        SecurityFeatureState kernelDma =
            GetKernelDmaProtectionState(
                deviceGuard,
                detectionErrors);

        bool isAdministrator =
            IsAdministrator(detectionErrors);

        bool vbsConfigured =
            IsRegistryEnabled(
                RegistryHive.LocalMachine,
                DeviceGuardRegistryPath,
                "EnableVirtualizationBasedSecurity",
                detectionErrors);

        bool hvciConfigured =
            IsRegistryEnabled(
                RegistryHive.LocalMachine,
                HvciRegistryPath,
                "Enabled",
                detectionErrors);

        int? lsaCfgFlags =
            GetDwordValue(
                RegistryHive.LocalMachine,
                LsaRegistryPath,
                "LsaCfgFlags",
                detectionErrors);

        bool credentialGuardConfigured =
            deviceGuard.CredentialGuardConfigured ||
            (lsaCfgFlags.HasValue &&
             lsaCfgFlags.Value != 0);

        bool credentialGuardSupported =
            edition.CredentialGuardSupported;

        bool rebootRequired =
            DetermineRebootRequired(
                vbsConfigured,
                deviceGuard.VbsRunning,
                hvciConfigured,
                deviceGuard.HvciRunning,
                credentialGuardConfigured,
                deviceGuard.CredentialGuardRunning,
                credentialGuardSupported);

        SecurityStatus status =
            new SecurityStatus
            {
                IsAdministrator =
                    isAdministrator,

                Edition =
                    edition,

                SecureBootState =
                    secureBoot,

                Tpm20State =
                    tpm,

                VbsState =
                    deviceGuard.VbsState,

                VbsConfigured =
                    vbsConfigured,

                HvciState =
                    deviceGuard.HvciState,

                HvciConfigured =
                    hvciConfigured,

                CredentialGuardState =
                    credentialGuardSupported
                        ? deviceGuard.CredentialGuardState
                        : SecurityFeatureState.NotSupported,

                CredentialGuardConfigured =
                    credentialGuardConfigured,

                CredentialGuardSupported =
                    credentialGuardSupported,

                KernelDmaState =
                    kernelDma,

                RebootRequired =
                    rebootRequired,

                DeviceGuardAvailable =
                    deviceGuard.Available,

                CodeIntegrityPolicyEnforcementStatus =
                    deviceGuard.CodeIntegrityPolicyEnforcementStatus,

                UsermodeCodeIntegrityPolicyEnforcementStatus =
                    deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus,

                DetectionErrors =
                    detectionErrors
            };


        return status;
    }


    // =========================================================
    // RECOMMENDED SECURITY CONFIGURATION
    // =========================================================

    public static void EnableRecommendedFeatures()
    {
        if (!IsAdministrator())
        {
            throw new UnauthorizedAccessException(
                "Administrator privileges are required to modify Windows security settings.");
        }


        SecurityStatus status =
            GetStatus();


        //
        // VBS
        //
        EnableVbs();


        //
        // HVCI
        //
        EnableHvci();


        //
        // Credential Guard
        //
        //
        // Do NOT attempt to enable Credential Guard on an
        // unsupported Windows edition.
        //
        if (status.CredentialGuardSupported)
        {
            EnableCredentialGuard();
        }
    }


    // =========================================================
    // ENABLE VBS
    // =========================================================

    private static void EnableVbs()
    {
        using RegistryKey key =
            Registry.LocalMachine.CreateSubKey(
                DeviceGuardRegistryPath)
            ?? throw new InvalidOperationException(
                "Unable to open the Device Guard registry key.");


        key.SetValue(
            "EnableVirtualizationBasedSecurity",
            1,
            RegistryValueKind.DWord);


        //
        // 3 =
        // Secure Boot + DMA protection / platform security
        //
        // This is Microsoft's documented platform-security
        // configuration value.
        //
        key.SetValue(
            "RequirePlatformSecurityFeatures",
            3,
            RegistryValueKind.DWord);
    }


    // =========================================================
    // ENABLE HVCI
    // =========================================================

    private static void EnableHvci()
    {
        using RegistryKey key =
            Registry.LocalMachine.CreateSubKey(
                HvciRegistryPath)
            ?? throw new InvalidOperationException(
                "Unable to open the HVCI registry key.");


        key.SetValue(
            "Enabled",
            1,
            RegistryValueKind.DWord);
    }


    // =========================================================
    // ENABLE CREDENTIAL GUARD
    // =========================================================

    public static void EnableCredentialGuard()
    {
        if (!IsAdministrator())
        {
            throw new UnauthorizedAccessException(
                "Administrator privileges are required to enable Credential Guard.");
        }


        WindowsEditionInfo edition =
            GetWindowsEdition(
                new List<string>());


        if (!edition.CredentialGuardSupported)
        {
            throw new PlatformNotSupportedException(
                $"Credential Guard is not supported/licensed on " +
                $"{edition.EditionName}.");
        }


        using RegistryKey key =
            Registry.LocalMachine.CreateSubKey(
                LsaRegistryPath)
            ?? throw new InvalidOperationException(
                "Unable to open the LSA registry key.");


        //
        // 1 = Enable Credential Guard.
        //
        // Note:
        // Setting this value configures Credential Guard.
        // It does NOT prove that Credential Guard is running.
        //
        key.SetValue(
            "LsaCfgFlags",
            1,
            RegistryValueKind.DWord);
    }


    // =========================================================
    // DETERMINE REBOOT REQUIREMENT
    // =========================================================

    private static bool DetermineRebootRequired(
        bool vbsConfigured,
        bool vbsRunning,
        bool hvciConfigured,
        bool hvciRunning,
        bool credentialGuardConfigured,
        bool credentialGuardRunning,
        bool credentialGuardSupported)
    {
        //
        // VBS configured but not running.
        //
        if (vbsConfigured && !vbsRunning)
        {
            return true;
        }


        //
        // HVCI configured but not running.
        //
        if (hvciConfigured && !hvciRunning)
        {
            return true;
        }


        //
        // Credential Guard configured on a supported edition
        // but not yet running.
        //
        if (credentialGuardSupported &&
            credentialGuardConfigured &&
            !credentialGuardRunning)
        {
            return true;
        }


        //
        // IMPORTANT:
        //
        // Credential Guard configured on an unsupported edition
        // is NOT treated as a reboot condition.
        //
        // It is a platform/licensing failure instead.
        //
        return false;
    }


    // =========================================================
    // DEVICE GUARD
    // =========================================================

    private static DeviceGuardSnapshot
        GetDeviceGuardSnapshot(
            List<string> detectionErrors)
    {
        try
        {
            using ManagementObjectSearcher searcher =
                new ManagementObjectSearcher(
                    DeviceGuardNamespace,
                    $"SELECT * FROM {DeviceGuardClass}");


            using ManagementObjectCollection results =
                searcher.Get();


            foreach (ManagementObject obj in results)
            {
                int vbsStatus =
                    GetInt32(
                        obj["VirtualizationBasedSecurityStatus"]);


                int codeIntegrityStatus =
                    GetInt32(
                        obj["CodeIntegrityPolicyEnforcementStatus"]);


                int userModeCodeIntegrityStatus =
                    GetInt32(
                        obj["UsermodeCodeIntegrityPolicyEnforcementStatus"]);


                int[] configuredServices =
                    GetIntArray(
                        obj["SecurityServicesConfigured"]);


                int[] runningServices =
                    GetIntArray(
                        obj["SecurityServicesRunning"]);


                int[] availableSecurityProperties =
                    GetIntArray(
                        obj["AvailableSecurityProperties"]);


                int[] requiredSecurityProperties =
                    GetIntArray(
                        obj["RequiredSecurityProperties"]);


                bool credentialGuardConfigured =
                    configuredServices.Contains(
                        CredentialGuardServiceId);


                bool credentialGuardRunning =
                    runningServices.Contains(
                        CredentialGuardServiceId);


                bool hvciConfigured =
                    configuredServices.Contains(
                        HvciServiceId);


                bool hvciRunning =
                    runningServices.Contains(
                        HvciServiceId);


                return new DeviceGuardSnapshot
                {
                    Available =
                        true,

                    VbsState =
                        ConvertVbsState(
                            vbsStatus),

                    VbsRunning =
                        vbsStatus == 2,

                    HvciState =
                        hvciRunning
                            ? SecurityFeatureState.Running
                            : hvciConfigured
                                ? SecurityFeatureState.Configured
                                : SecurityFeatureState.Disabled,

                    HvciRunning =
                        hvciRunning,

                    CredentialGuardState =
                        credentialGuardRunning
                            ? SecurityFeatureState.Running
                            : credentialGuardConfigured
                                ? SecurityFeatureState.Configured
                                : SecurityFeatureState.Disabled,

                    CredentialGuardConfigured =
                        credentialGuardConfigured,

                    CredentialGuardRunning =
                        credentialGuardRunning,

                    AvailableSecurityProperties =
                        availableSecurityProperties,

                    RequiredSecurityProperties =
                        requiredSecurityProperties,

                    SecurityServicesConfigured =
                        configuredServices,

                    SecurityServicesRunning =
                        runningServices,

                    CodeIntegrityPolicyEnforcementStatus =
                        codeIntegrityStatus,

                    UsermodeCodeIntegrityPolicyEnforcementStatus =
                        userModeCodeIntegrityStatus
                };
            }


            return DeviceGuardSnapshot.Unknown();
        }
        catch (ManagementException ex)
        {
            LogDetectionFailure(
                "Device Guard",
                ex,
                detectionErrors);

            return DeviceGuardSnapshot.Unknown();
        }
        catch (UnauthorizedAccessException ex)
        {
            LogDetectionFailure(
                "Device Guard",
                ex,
                detectionErrors);

            return DeviceGuardSnapshot.Unknown();
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                "Device Guard",
                ex,
                detectionErrors);

            return DeviceGuardSnapshot.Unknown();
        }
    }


    // =========================================================
    // VBS STATE
    // =========================================================

    private static SecurityFeatureState
        ConvertVbsState(
            int status)
    {
        return status switch
        {
            0 =>
                SecurityFeatureState.Disabled,

            1 =>
                SecurityFeatureState.Configured,

            2 =>
                SecurityFeatureState.Running,

            _ =>
                SecurityFeatureState.Unknown
        };
    }


    // =========================================================
    // SECURE BOOT
    // =========================================================

    private static SecurityFeatureState
        GetSecureBootState(
            List<string> detectionErrors)
    {
        try
        {
            using RegistryKey? key =
                Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");


            if (key == null)
            {
                return SecurityFeatureState.Unknown;
            }


            object? value =
                key.GetValue(
                    "UEFISecureBootEnabled");


            if (value == null)
            {
                return SecurityFeatureState.Unknown;
            }


            return Convert.ToInt32(value) == 1
                ? SecurityFeatureState.Running
                : SecurityFeatureState.Disabled;
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                "Secure Boot",
                ex,
                detectionErrors);

            return SecurityFeatureState.Unknown;
        }
    }


    // =========================================================
    // GET TPM 2.0 STATE
    // =========================================================

    private static SecurityFeatureState GetTpm20State(
        List<string> detectionErrors)
    {
        try
        {
            TPM_DEVICE_INFO deviceInfo;


            uint result =
                Tbsi_GetDeviceInfo(
                    (uint)Marshal.SizeOf<TPM_DEVICE_INFO>(),
                    out deviceInfo);


            // =====================================================
            // TPM FOUND
            // =====================================================

            if (result == TBS_SUCCESS)
            {
                Debug.WriteLine(
                    "[SystemSecurity] " +
                    $"TPM detected. " +
                    $"Version=0x{deviceInfo.TpmVersion:X8}, " +
                    $"InterfaceType=0x{deviceInfo.TpmInterfaceType:X8}, " +
                    $"ImplementationRevision=0x{deviceInfo.TpmImpRevision:X8}");


                // =================================================
                // TPM 2.0
                // =================================================

                if (deviceInfo.TpmVersion ==
                    TPM_VERSION_20)
                {
                    return SecurityFeatureState.Running;
                }


                // =================================================
                // TPM 1.2
                // =================================================

                if (deviceInfo.TpmVersion ==
                    TPM_VERSION_12)
                {
                    return SecurityFeatureState.Disabled;
                }


                // =================================================
                // UNKNOWN TPM VERSION
                // =================================================

                return SecurityFeatureState.Unknown;
            }


            // =====================================================
            // TPM NOT FOUND
            // =====================================================

            if (result ==
                TBS_E_TPM_NOT_FOUND)
            {
                Debug.WriteLine(
                    "[SystemSecurity] " +
                    "TPM was not detected.");

                return SecurityFeatureState.NotPresent;
            }


            // =====================================================
            // OTHER TBS ERROR
            // =====================================================

            string error =
                $"Tbsi_GetDeviceInfo failed. " +
                $"TBS result=0x{result:X8}.";


            detectionErrors.Add(
                $"TPM 2.0: {error}");


            Debug.WriteLine(
                "[SystemSecurity] " +
                error);


            return SecurityFeatureState.Unknown;
        }
        catch (DllNotFoundException ex)
        {
            LogDetectionFailure(
                "TPM 2.0 / TBS",
                ex,
                detectionErrors);

            return SecurityFeatureState.Unknown;
        }
        catch (EntryPointNotFoundException ex)
        {
            LogDetectionFailure(
                "TPM 2.0 / TBS",
                ex,
                detectionErrors);

            return SecurityFeatureState.Unknown;
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                "TPM 2.0 / TBS",
                ex,
                detectionErrors);

            return SecurityFeatureState.Unknown;
        }
    }

    // =========================================================
    // KERNEL DMA PROTECTION
    // =========================================================

    private static SecurityFeatureState
        GetKernelDmaProtectionState(
            DeviceGuardSnapshot deviceGuard,
            List<string> detectionErrors)
    {
        try
        {
            if (!deviceGuard.Available)
            {
                return SecurityFeatureState.Unknown;
            }


            bool dmaAvailable =
                deviceGuard.AvailableSecurityProperties
                    .Contains(
                        DmaProtectionPropertyId);


            if (!dmaAvailable)
            {
                return SecurityFeatureState.NotSupported;
            }


            //
            // Kernel DMA Protection is automatically enabled by
            // Windows on supported UEFI platforms.
            //
            // If the platform advertises DMA protection support,
            // do not incorrectly require a custom registry value.
            //
            return SecurityFeatureState.Running;
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                "Kernel DMA Protection",
                ex,
                detectionErrors);

            return SecurityFeatureState.Unknown;
        }
    }


    // =========================================================
    // WINDOWS EDITION
    // =========================================================

    private static WindowsEditionInfo
        GetWindowsEdition(
            List<string> detectionErrors)
    {
        try
        {
            using RegistryKey? key =
                Registry.LocalMachine.OpenSubKey(
                    CurrentVersionRegistryPath);


            if (key == null)
            {
                return WindowsEditionInfo.Unknown();
            }


            string productName =
                key.GetValue(
                        "ProductName")?
                    .ToString()
                ?? string.Empty;


            string editionId =
                key.GetValue(
                        "EditionID")?
                    .ToString()
                ?? string.Empty;


            string installationType =
                key.GetValue(
                        "InstallationType")?
                    .ToString()
                ?? string.Empty;


            string displayVersion =
                key.GetValue(
                        "DisplayVersion")?
                    .ToString()
                ?? string.Empty;


            bool isServer =
                installationType.Contains(
                    "Server",
                    StringComparison.OrdinalIgnoreCase)
                ||
                productName.Contains(
                    "Server",
                    StringComparison.OrdinalIgnoreCase);


            WindowsEdition edition =
                DetermineEdition(
                    productName,
                    editionId,
                    isServer);


            return new WindowsEditionInfo
            {
                Edition =
                    edition,

                EditionName =
                    productName,

                EditionId =
                    editionId,

                DisplayVersion =
                    displayVersion,

                IsServer =
                    isServer,

                CredentialGuardSupported =
                    IsCredentialGuardSupported(
                        edition)
            };
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                "Windows edition detection",
                ex,
                detectionErrors);

            return WindowsEditionInfo.Unknown();
        }
    }


    private static WindowsEdition
        DetermineEdition(
            string productName,
            string editionId,
            bool isServer)
    {
        if (isServer)
        {
            return WindowsEdition.Server;
        }


        string value =
            $"{productName} {editionId}"
                .ToLowerInvariant();


        if (value.Contains("enterprise"))
        {
            return WindowsEdition.Enterprise;
        }


        if (value.Contains("education"))
        {
            return WindowsEdition.Education;
        }


        if (value.Contains("pro"))
        {
            return WindowsEdition.Pro;
        }


        if (value.Contains("home"))
        {
            return WindowsEdition.Home;
        }


        return WindowsEdition.Unknown;
    }


    private static bool IsCredentialGuardSupported(
        WindowsEdition edition)
    {
        //
        // Microsoft currently documents Credential Guard support
        // for Enterprise and Education editions.
        //
        return edition ==
               WindowsEdition.Enterprise
               ||
               edition ==
               WindowsEdition.Education
               ||
               edition ==
               WindowsEdition.Server;
    }


    // =========================================================
    // REGISTRY
    // =========================================================

    private static bool IsRegistryEnabled(
        RegistryHive hive,
        string path,
        string valueName,
        List<string> detectionErrors)
    {
        int? value =
            GetDwordValue(
                hive,
                path,
                valueName,
                detectionErrors);


        return value.HasValue &&
               value.Value != 0;
    }


    private static int? GetDwordValue(
        RegistryHive hive,
        string path,
        string valueName,
        List<string> detectionErrors)
    {
        try
        {
            using RegistryKey baseKey =
                RegistryKey.OpenBaseKey(
                    hive,
                    RegistryView.Registry64);


            using RegistryKey? key =
                baseKey.OpenSubKey(
                    path);


            if (key == null)
            {
                return null;
            }


            object? value =
                key.GetValue(
                    valueName,
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames);


            if (value == null)
            {
                return null;
            }


            return Convert.ToInt32(value);
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                $"Registry: {path}\\{valueName}",
                ex,
                detectionErrors);

            return null;
        }
    }


    // =========================================================
    // ADMINISTRATOR
    // =========================================================

    public static bool IsAdministrator()
    {
        return IsAdministrator(
            new List<string>());
    }


    private static bool IsAdministrator(
        List<string> detectionErrors)
    {
        try
        {
            using WindowsIdentity identity =
                WindowsIdentity.GetCurrent();


            WindowsPrincipal principal =
                new WindowsPrincipal(
                    identity);


            return principal.IsInRole(
                WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex)
        {
            LogDetectionFailure(
                "Administrator detection",
                ex,
                detectionErrors);

            return false;
        }
    }


    // =========================================================
    // TESTING ONLY
    // =========================================================

    public static void DisableSoftwareProtectionsForTesting()
    {
        if (!IsAdministrator())
        {
            throw new UnauthorizedAccessException(
                "Administrator privileges are required.");
        }


        //
        // VBS
        //
        using (RegistryKey key =
               Registry.LocalMachine.CreateSubKey(
                   DeviceGuardRegistryPath)
               ?? throw new InvalidOperationException(
                   "Unable to open the Device Guard registry key."))
        {
            key.SetValue(
                "EnableVirtualizationBasedSecurity",
                0,
                RegistryValueKind.DWord);

            key.SetValue(
                "RequirePlatformSecurityFeatures",
                0,
                RegistryValueKind.DWord);
        }


        //
        // HVCI
        //
        using (RegistryKey key =
               Registry.LocalMachine.CreateSubKey(
                   HvciRegistryPath)
               ?? throw new InvalidOperationException(
                   "Unable to open the HVCI registry key."))
        {
            key.SetValue(
                "Enabled",
                0,
                RegistryValueKind.DWord);
        }


        //
        // Credential Guard
        //
        using (RegistryKey key =
               Registry.LocalMachine.CreateSubKey(
                   LsaRegistryPath)
               ?? throw new InvalidOperationException(
                   "Unable to open the LSA registry key."))
        {
            key.SetValue(
                "LsaCfgFlags",
                0,
                RegistryValueKind.DWord);
        }
    }


    // =========================================================
    // ARRAY HELPERS
    // =========================================================

    private static int[] GetIntArray(
        object? value)
    {
        if (value is not Array array)
        {
            return Array.Empty<int>();
        }


        List<int> values =
            new(array.Length);


        foreach (object? item in array)
        {
            if (item == null)
            {
                continue;
            }


            try
            {
                values.Add(
                    Convert.ToInt32(item));
            }
            catch
            {
                // Ignore malformed individual entries.
            }
        }


        return values.ToArray();
    }


    private static int GetInt32(
        object? value)
    {
        if (value == null)
        {
            return 0;
        }


        try
        {
            return Convert.ToInt32(value);
        }
        catch
        {
            return 0;
        }
    }


    // =========================================================
    // LOGGING
    // =========================================================

    private static void LogDetectionFailure(
        string component,
        Exception exception,
        List<string> detectionErrors)
    {
        string message =
            $"[SystemSecurity] {component} detection failed: " +
            exception.Message;


        detectionErrors.Add(
            message);


        Debug.WriteLine(
            message);


        Debug.WriteLine(
            exception);
    }


    // =========================================================
    // DEVICE GUARD SNAPSHOT
    // =========================================================

    private sealed class DeviceGuardSnapshot
    {
        public bool Available { get; init; }

        public SecurityFeatureState VbsState { get; init; }

        public bool VbsRunning { get; init; }

        public SecurityFeatureState HvciState { get; init; }

        public bool HvciRunning { get; init; }

        public SecurityFeatureState CredentialGuardState
        {
            get;
            init;
        }

        public bool CredentialGuardConfigured
        {
            get;
            init;
        }

        public bool CredentialGuardRunning
        {
            get;
            init;
        }

        public int[] AvailableSecurityProperties
        {
            get;
            init;
        } = Array.Empty<int>();

        public int[] RequiredSecurityProperties
        {
            get;
            init;
        } = Array.Empty<int>();

        public int[] SecurityServicesConfigured
        {
            get;
            init;
        } = Array.Empty<int>();

        public int[] SecurityServicesRunning
        {
            get;
            init;
        } = Array.Empty<int>();

        public int CodeIntegrityPolicyEnforcementStatus
        {
            get;
            init;
        }

        public int UsermodeCodeIntegrityPolicyEnforcementStatus
        {
            get;
            init;
        }


        public static DeviceGuardSnapshot Unknown()
        {
            return new DeviceGuardSnapshot
            {
                Available =
                    false,

                VbsState =
                    SecurityFeatureState.Unknown,

                HvciState =
                    SecurityFeatureState.Unknown,

                CredentialGuardState =
                    SecurityFeatureState.Unknown
            };
        }
    }


    // =========================================================
    // WINDOWS EDITION INFO
    // =========================================================

    public sealed class WindowsEditionInfo
    {
        public WindowsEdition Edition
        {
            get;
            init;
        }

        public string EditionName
        {
            get;
            init;
        } = string.Empty;

        public string EditionId
        {
            get;
            init;
        } = string.Empty;

        public string DisplayVersion
        {
            get;
            init;
        } = string.Empty;

        public bool IsServer
        {
            get;
            init;
        }

        public bool CredentialGuardSupported
        {
            get;
            init;
        }


        public static WindowsEditionInfo Unknown()
        {
            return new WindowsEditionInfo
            {
                Edition =
                    WindowsEdition.Unknown,

                EditionName =
                    "Unknown",

                CredentialGuardSupported =
                    false
            };
        }
    }


    // =========================================================
    // SECURITY STATUS
    // =========================================================

    public sealed class SecurityStatus
    {
        public bool IsAdministrator
        {
            get;
            init;
        }


        public WindowsEditionInfo Edition
        {
            get;
            init;
        } = WindowsEditionInfo.Unknown();


        // -----------------------------------------------------
        // SECURE BOOT
        // -----------------------------------------------------

        public SecurityFeatureState SecureBootState
        {
            get;
            init;
        }

        public bool SecureBootEnabled =>
            SecureBootState ==
            SecurityFeatureState.Running;


        // -----------------------------------------------------
        // TPM
        // -----------------------------------------------------

        public SecurityFeatureState Tpm20State
        {
            get;
            init;
        }

        public bool Tpm20Present =>
            Tpm20State ==
            SecurityFeatureState.Running;


        // -----------------------------------------------------
        // VBS
        // -----------------------------------------------------

        public SecurityFeatureState VbsState
        {
            get;
            init;
        }

        public bool VbsConfigured
        {
            get;
            init;
        }

        public bool VbsRunning =>
            VbsState ==
            SecurityFeatureState.Running;


        // -----------------------------------------------------
        // HVCI
        // -----------------------------------------------------

        public SecurityFeatureState HvciState
        {
            get;
            init;
        }

        public bool HvciConfigured
        {
            get;
            init;
        }

        public bool HvciRunning =>
            HvciState ==
            SecurityFeatureState.Running;


        // -----------------------------------------------------
        // CREDENTIAL GUARD
        // -----------------------------------------------------

        public SecurityFeatureState CredentialGuardState
        {
            get;
            init;
        }

        public bool CredentialGuardSupported
        {
            get;
            init;
        }

        public bool CredentialGuardConfigured
        {
            get;
            init;
        }

        public bool CredentialGuardRunning =>
            CredentialGuardState ==
            SecurityFeatureState.Running;


        // -----------------------------------------------------
        // KERNEL DMA
        // -----------------------------------------------------

        public SecurityFeatureState KernelDmaState
        {
            get;
            init;
        }

        public bool KernelDmaProtectionEnabled =>
            KernelDmaState ==
            SecurityFeatureState.Running;


        // -----------------------------------------------------
        // DEVICE GUARD
        // -----------------------------------------------------

        public bool DeviceGuardAvailable
        {
            get;
            init;
        }

        public int CodeIntegrityPolicyEnforcementStatus
        {
            get;
            init;
        }

        public int UsermodeCodeIntegrityPolicyEnforcementStatus
        {
            get;
            init;
        }


        // -----------------------------------------------------
        // REBOOT
        // -----------------------------------------------------

        public bool RebootRequired
        {
            get;
            init;
        }


        // -----------------------------------------------------
        // DIAGNOSTICS
        // -----------------------------------------------------

        public IReadOnlyList<string> DetectionErrors
        {
            get;
            init;
        } = Array.Empty<string>();


        // -----------------------------------------------------
        // OVERALL RESULT
        // -----------------------------------------------------

        public bool MeetsRecommendations
        {
            get
            {
                //
                // Fundamental platform protections.
                //
                if (!SecureBootEnabled)
                {
                    return false;
                }


                if (!Tpm20Present)
                {
                    return false;
                }


                if (!VbsRunning)
                {
                    return false;
                }


                if (!HvciRunning)
                {
                    return false;
                }


                if (!KernelDmaProtectionEnabled)
                {
                    return false;
                }


                //
                // Credential Guard is a hard requirement only
                // when the platform supports it.
                //
                // On Home/unsupported editions, this property
                // intentionally does NOT pretend that Credential
                // Guard can be enabled.
                //
                if (CredentialGuardSupported &&
                    !CredentialGuardRunning)
                {
                    return false;
                }


                return true;
            }
        }


        // -----------------------------------------------------
        // SECURITY BLOCKERS
        // -----------------------------------------------------

        public IReadOnlyList<string> BlockingReasons
        {
            get
            {
                List<string> reasons =
                    new();


                if (!SecureBootEnabled)
                {
                    reasons.Add(
                        "Secure Boot is not enabled.");
                }


                if (!Tpm20Present)
                {
                    reasons.Add(
                        "TPM 2.0 is not available.");
                }


                if (!VbsRunning)
                {
                    reasons.Add(
                        "Virtualization-based Security (VBS) is not running.");
                }


                if (!HvciRunning)
                {
                    reasons.Add(
                        "Hypervisor-enforced Code Integrity (HVCI) is not running.");
                }


                if (!KernelDmaProtectionEnabled)
                {
                    reasons.Add(
                        "Kernel DMA Protection is not active or is unavailable.");
                }


                if (CredentialGuardSupported &&
                    !CredentialGuardRunning)
                {
                    if (CredentialGuardConfigured)
                    {
                        reasons.Add(
                            "Credential Guard is configured but is not running.");
                    }
                    else
                    {
                        reasons.Add(
                            "Credential Guard is not configured.");
                    }
                }


                if (!CredentialGuardSupported)
                {
                    reasons.Add(
                        $"Credential Guard is not supported/licensed on " +
                        $"{Edition.EditionName}.");
                }


                if (DetectionErrors.Count > 0)
                {
                    reasons.Add(
                        "One or more security components could not be fully assessed.");
                }


                return reasons;
            }
        }
    }


    // =========================================================
    // ENUMS
    // =========================================================

    public enum SecurityFeatureState
    {
        Unknown,

        NotSupported,

        NotPresent,

        Disabled,

        Configured,

        Running
    }


    public enum WindowsEdition
    {
        Unknown,

        Home,

        Pro,

        Enterprise,

        Education,

        Server
    }
}