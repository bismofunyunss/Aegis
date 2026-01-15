using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace Aegis.App.Crypto;

internal static class WindowsHelloManager
{
    public static async Task<byte[]> GetHelloPublicKeyHashAsync(KeyCredential key)
    {
        // Retrieve the public key as IBuffer
        var buffer = key.RetrievePublicKey();

        // Convert IBuffer -> byte[]
        var pubKey = new byte[buffer.Length];
        DataReader.FromBuffer(buffer).ReadBytes(pubKey);

        // Hash the public key
        using var sha = SHA256.Create();
        return await Task.Run(() => sha.ComputeHash(pubKey));
    }


    public static byte[] DeriveHelloKEK(byte[] pubKeyHash, byte[] salt)
     => CryptoMethods.HKDF.DeriveKey(
         pubKeyHash,
         salt,
         Encoding.UTF8.GetBytes("Aegis-HELLO-KEK"),
         32
     );

    public static async Task<KeyCredential> CreateHelloKeyAsync(string username)
    {
        if (!await KeyCredentialManager.IsSupportedAsync())
            throw new NotSupportedException("Windows Hello KeyCredential not available.");

        var result = await KeyCredentialManager.RequestCreateAsync(
            username,
            KeyCredentialCreationOption.ReplaceExisting // or ReplaceExisting
        );

        if (result.Status != KeyCredentialStatus.Success)
            throw new Exception($"Windows Hello registration failed: {result.Status}");

        return result.Credential;
    }

}