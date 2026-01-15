using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using Windows.Security.Credentials;

namespace Aegis.WindowsHello
{

    internal static class WindowsHelloService
    {
            private const string HelloKeyName = "AegisHelloKey";

            /// <summary>
            /// Prompts user for Windows Hello every time and returns a deterministic KEK.
            /// </summary>
            public static byte[] PromptHelloAndGetKek()
            {
                var provider = new CngProvider("Microsoft Platform Crypto Provider");
                CngKey key;

                try
                {
                    key = CngKey.Open(
                        HelloKeyName,
                        provider,
                        (CngKeyOpenOptions)CngUIProtectionLevels.ForceHighProtection // forces PIN/biometric prompt
                    );
                }
                catch (CryptographicException)
                {
                    key = CngKey.Create(
                        CngAlgorithm.ECDsaP256,
                        HelloKeyName,
                        new CngKeyCreationParameters
                        {
                            Provider = provider,
                            KeyUsage = CngKeyUsages.Signing,
                            ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                            UIPolicy = new CngUIPolicy(
                                CngUIProtectionLevels.ForceHighProtection,
                                friendlyName: "Aegis Windows Hello Key",
                                description: "Authenticate to derive KEK",
                                useContext: null,
                                creationTitle: "Authenticate"
                            )
                        }
                    );
                }

                using var ecdsa = new ECDsaCng(key);
                byte[] pubKey = ecdsa.ExportSubjectPublicKeyInfo();
                return SHA256.HashData(pubKey);
            }
        }


}
