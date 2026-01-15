using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace Aegis.App.WindowsHello;

public class WindowsHelloManager
{
    private const string KeyName = "Aegis.Hello.Master";

    public byte[] Protect(byte[] data)
    {
        using var key = GetOrCreateKey();

        using var ecdh = new ECDiffieHellmanCng(key)
        {
            KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
            HashAlgorithm = CngAlgorithm.Sha256
        };

        byte[] kek = ecdh.DeriveKeyMaterial(key);
        byte[] enc = AesGcmEncrypt(kek, data);

        CryptographicOperations.ZeroMemory(kek);
        return enc;
    }

    private static CngKey GetOrCreateKey()
    {
        if (CngKey.Exists(KeyName))
            return CngKey.Open(KeyName);

        var creation = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftPlatformCryptoProvider,
            KeyUsage = CngKeyUsages.KeyAgreement,
            ExportPolicy = CngExportPolicies.None,
            UIPolicy = new CngUIPolicy(CngUIProtectionLevels.ForceHighProtection)
        };

        return CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, KeyName, creation);
    }

    private static byte[] AesGcmEncrypt(byte[] key, byte[] data)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] tag = new byte[16];
        byte[] cipher = new byte[data.Length];

        using var gcm = new AesGcm(key);
        gcm.Encrypt(nonce, data, cipher, tag);

        return nonce.Concat(tag).Concat(cipher).ToArray();
    }
}