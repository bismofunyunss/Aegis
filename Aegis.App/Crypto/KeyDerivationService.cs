using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Crypto
{
    public sealed class DerivedKeys : IDisposable
    {
        public byte[] XChaChaKey { get; }
        public byte[] ThreefishKey { get; }
        public byte[] SerpentKey { get; }
        public byte[] AesKey { get; }
        public byte[] ShuffleKey { get; }
        public byte[] ThreefishHmacKey { get; }
        public byte[] SerpentHmacKey { get; }
        public byte[] AesHmacKey { get; }
        public byte[][] Salts { get; }

        public DerivedKeys(
            byte[] xChaCha,
            byte[] threefish,
            byte[] serpent,
            byte[] aes,
            byte[] shuffle,
            byte[] tfHmac,
            byte[] serpentHmac,
            byte[] aesHmac,
            byte[][] salts)
        {
            XChaChaKey = xChaCha;
            ThreefishKey = threefish;
            SerpentKey = serpent;
            AesKey = aes;
            ShuffleKey = shuffle;
            ThreefishHmacKey = tfHmac;
            SerpentHmacKey = serpentHmac;
            AesHmacKey = aesHmac;
            Salts = salts;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(XChaChaKey);
            CryptographicOperations.ZeroMemory(ThreefishKey);
            CryptographicOperations.ZeroMemory(SerpentKey);
            CryptographicOperations.ZeroMemory(AesKey);
            CryptographicOperations.ZeroMemory(ShuffleKey);
            CryptographicOperations.ZeroMemory(ThreefishHmacKey);
            CryptographicOperations.ZeroMemory(SerpentHmacKey);
            CryptographicOperations.ZeroMemory(AesHmacKey);
        }
    }

}
