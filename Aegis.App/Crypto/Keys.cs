using System.IO;
using System.Security.Cryptography;
using System.Text;
using ABI.Windows.Devices.Bluetooth.Advertisement;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.IO;
using Microsoft.Win32;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Aegis.App.Crypto;

internal static class Keys
{
    internal static byte[] GenerateMasterSeed(int len)
    {
        var masterKey = new byte[len];
        RandomNumberGenerator.Fill(masterKey);

        return masterKey;
    }

    public static byte[] GetMachineSecret()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        if (key == null) throw new InvalidOperationException("Cannot read MachineGuid.");
        var machineGuid = key.GetValue("MachineGuid") as string
                          ?? throw new InvalidOperationException("MachineGuid missing.");

        return SHA256.HashData(Encoding.UTF8.GetBytes(machineGuid));
    }


    /// <summary>
    ///     AES Key Wrap (RFC 5649) wrapper.
    /// </summary>
    public static byte[] AesKeyWrap(byte[] kek, byte[] keyToWrap)
    {
        var engine = new AesWrapPadEngine(); // RFC 5649
        engine.Init(true, new KeyParameter(kek)); // true = wrap
        return engine.Wrap(keyToWrap, 0, keyToWrap.Length);
    }

    /// <summary>
    ///     AES Key Unwrap (RFC 5649) unwrapper.
    /// </summary>
    public static byte[] AesKeyUnwrap(byte[] kek, byte[] wrappedKey)
    {
        var engine = new AesWrapPadEngine(); // RFC 5649
        engine.Init(false, new KeyParameter(kek)); // false = unwrap
        return engine.Unwrap(wrappedKey, 0, wrappedKey.Length);
    }

    /// <summary>
    ///     Derives a 32-byte Key Encryption Key (KEK) using HKDF-SHA3-512.
    /// </summary>
    /// <param name="helloEntropy">128-byte Windows Hello entropy</param>
    /// <param name="machineSecret">32-byte SHA256(MachineGuid)</param>
    /// <param name="helloPubKeyHash">48-byte SHA384 hash of Hello public key</param>
    /// <param name="salt">128-byte HKDF salt</param>
    /// <param name="info">Optional context string</param>
    /// <returns>32-byte KEK</returns>
    public static byte[] DeriveKEK(
        byte[] helloEntropy, // 128 bytes
        byte[] machineSecret, // 32 bytes
        byte[] helloPubKeyHash, // 48 bytes SHA384
        byte[] cngPubKeyHash, // 48 bytes SHA384
        byte[] salt, // 128 bytes
        string info)
    {
        if (helloEntropy == null || helloEntropy.Length != 128)
            throw new ArgumentException("Invalid Hello entropy");
        if (machineSecret == null || machineSecret.Length != 32)
            throw new ArgumentException("Invalid machine secret");
        if (helloPubKeyHash == null || helloPubKeyHash.Length != 48)
            throw new ArgumentException("Invalid Hello public key hash");
        if (cngPubKeyHash == null || cngPubKeyHash.Length != 48)
            throw new ArgumentException("Invalid CNG public key hash");
        if (salt == null || salt.Length != 128)
            throw new ArgumentException("Invalid salt");

        // Combine all entropy + hashes
        var ikm = HelperMethods.Combine(helloEntropy, machineSecret, helloPubKeyHash, cngPubKeyHash);

        // Derive KEK using HKDF-SHA384
        var kek = CryptoMethods.HKDF.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes(info), 32);

        // Clear sensitive buffers
        MemoryHandling.Clear(ikm);

        return kek;
    }


    /// <summary>
    ///     Derives a 64-byte master key using multiple high-entropy sources.
    /// </summary>
    /// <param name="masterSeed">64-byte RNG master seed</param>
    /// <param name="helloEntropy">128-byte Hello entropy</param>
    /// <param name="helloPubKeyHash">48-byte SHA384 hash of Hello key</param>
    /// <param name="machineSecret">32-byte machine secret</param>
    /// <param name="salt">128-byte salt for HKDF</param>
    /// <param name="info">Optional context string</param>
    /// <returns>64-byte master key</returns>
    public static byte[] CreateMasterKey(byte[] masterSeed, byte[] helloEntropy, byte[] helloPubKeyHash,
        byte[] machineSecret, byte[] salt, string info = "Aegis Master Key")
    {
        if (masterSeed == null || masterSeed.Length != 64) throw new ArgumentException("Invalid master seed");
        if (helloEntropy == null || helloEntropy.Length != 128)
            throw new ArgumentException("Invalid Hello entropy");
        if (helloPubKeyHash == null || helloPubKeyHash.Length != 48)
            throw new ArgumentException("Invalid Hello public key hash");
        if (machineSecret == null || machineSecret.Length != 32)
            throw new ArgumentException("Invalid machine secret");
        if (salt == null || salt.Length != 128) throw new ArgumentException("Invalid salt");

        var ikm = HelperMethods.Combine(masterSeed, helloEntropy, helloPubKeyHash, machineSecret);
        var masterKey = CryptoMethods.HKDF.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes(info), 64);
        MemoryHandling.Clear(ikm);

        return masterKey;
    }
}