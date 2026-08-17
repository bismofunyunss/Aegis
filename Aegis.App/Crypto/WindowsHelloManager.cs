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
         "Aegis-HELLO-KEK"u8.ToArray(),
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

    public static async Task<KeyCredential> GetHelloKeyAsync(string username)
    {
        // Check if Windows Hello KeyCredential is available
        if (!await KeyCredentialManager.IsSupportedAsync())
            throw new NotSupportedException("Windows Hello KeyCredential not available.");

        // Attempt to open the existing key
        var result = await KeyCredentialManager.OpenAsync(username);

        if (result.Status == KeyCredentialStatus.Success)
        {
            // Key exists, return it
            return result.Credential;
        }
        else if (result.Status == KeyCredentialStatus.NotFound)
        {
            // No existing key found
            return null;
        }
        else
        {
            // Some other error occurred
            throw new Exception($"Failed to retrieve Windows Hello key: {result.Status}");
        }
    }


}