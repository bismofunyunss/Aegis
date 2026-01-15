using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.CryptoMethods
{
    internal class RfcKeyWrapService
    {
        // AES key wrap placeholder (RFC 5649)
        public static byte[] Wrap(byte[] kek, byte[] keyToWrap)
        {
            if (kek == null || keyToWrap == null)
                throw new ArgumentNullException();

            var engine = new AesWrapPadEngine(); // true = RFC 5649 (padding)
            var parameters = new KeyParameter(kek);

            engine.Init(true, parameters); // true = encrypt (wrap)

            return engine.Wrap(keyToWrap, 0, keyToWrap.Length);
        }

        /// <summary>
        /// Unwraps a key wrapped with AES Key Wrap RFC5649 (padding)
        /// </summary>
        /// <param name="kek">Key encryption key</param>
        /// <param name="wrappedKey">Wrapped key bytes</param>
        /// <returns>Original unwrapped key bytes</returns>
        public static byte[] Unwrap(byte[] kek, byte[] wrappedKey)
        {
            if (kek == null || wrappedKey == null)
                throw new ArgumentNullException();

            var engine = new AesWrapPadEngine(); // RFC5649
            var parameters = new KeyParameter(kek);

            engine.Init(false, parameters); // false = decrypt (unwrap)

            return engine.Unwrap(wrappedKey, 0, wrappedKey.Length);
        }
    }
}
